//! RFC-0006 A2 mode 0: ordered instance batching with virtual leading selectors.
use crate::{
    append, dense::check_tables, interpolate, message_bytes, reserve, round, Dense, Error,
    Instance, Proof, ScRecord, Summand,
};
use alloc::vec::Vec;
use stele_hash::{AbsorbLabel, ChallengeField, ChallengeLabel, Transcript};
/// One evaluation obligation at a verifier-derived suffix point.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Claim<K> {
    /// Input tensor identity from the plan.
    pub tensor: u64,
    /// Unscaled evaluation point, never supplied by the proof.
    pub point: Vec<K>,
    /// Claimed evaluation, still requiring a consumer.
    pub value: K,
}
/// Exact RLC loss numerator over p^field_degree, excluding FS/H.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RlcRecord {
    /// Verifier-owned batch identity.
    pub id: u64,
    /// Number of ordered members, including zero-weight members.
    pub t: u32,
    /// Canonical extension degree.
    pub field_degree: u8,
    /// Conservative numerator t, including singleton batches.
    pub numerator: u64,
}
/// Conditional reduction only: every emitted claim must be discharged.
#[must_use = "discharge every evaluation through a reduction or opening"]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Reduction<K> {
    /// Full shared point, including leading padding coordinates.
    pub point: Vec<K>,
    /// Ordered input obligations; none are removed when multipliers vanish.
    pub claims: Vec<Claim<K>>,
    /// One shared sumcheck record, not one per member.
    pub sc: ScRecord,
    /// One coefficient challenge and its conservative loss.
    pub rlc: RlcRecord,
}
/// Ordered verifier-owned instances; ids must also be unique in the surrounding plan.
pub struct Batch<'a, K> {
    /// Batch identity, distinct from all member ids.
    pub id: u64,
    /// Nonempty ordered members, with their original dimensions and polynomials.
    pub instances: &'a [Instance<K>],
}
impl<K: ChallengeField + Eq> Batch<'_, K> {
    fn shape(&self) -> Result<(u32, usize, usize), Error> {
        if self.instances.is_empty() || u32::try_from(self.instances.len()).is_err() {
            return Err(Error::InvalidBatch);
        }
        let (mut m, mut degree, mut inputs) = (0, 0, 0usize);
        for (b, i) in self.instances.iter().enumerate() {
            degree = degree.max(i.validate().map_err(|_| Error::InvalidBatch)?);
            m = m.max(i.num_vars);
            inputs = inputs.checked_add(i.inputs.len()).ok_or(Error::Capacity)?;
            if i.id == self.id
                || self.instances[..b].iter().any(|j| {
                    j.id == i.id
                        || (j.num_vars != i.num_vars
                            && i.inputs.iter().any(|id| j.inputs.contains(id)))
                })
            {
                return Err(Error::InvalidBatch);
            }
        }
        if self.instances.iter().any(|i| i.num_vars != m) {
            degree = degree.max(1);
        }
        Ok((m, degree, inputs))
    }
    /// Complete canonical descriptor absorbed before the coefficient challenge.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let (m, degree, _) = self.shape()?;
        let mut out = Vec::new();
        append(&mut out, &[1, field_degree::<K>(), 0])?;
        append(&mut out, &self.id.to_le_bytes())?;
        append(&mut out, &(self.instances.len() as u32).to_le_bytes())?;
        append(&mut out, &m.to_le_bytes())?;
        append(&mut out, &[degree as u8])?;
        for i in self.instances {
            let bytes = i.encode()?;
            append(
                &mut out,
                &u64::try_from(bytes.len())
                    .map_err(|_| Error::Capacity)?
                    .to_le_bytes(),
            )?;
            append(&mut out, &bytes)?;
        }
        Ok(out)
    }
    fn tables(&self, tables: &[Vec<Vec<K>>]) -> Result<(), Error> {
        self.shape()?;
        if tables.len() != self.instances.len() {
            return Err(Error::PublicShape);
        }
        for (b, (i, group)) in self.instances.iter().zip(tables).enumerate() {
            check_tables(i, group)?;
            for (n, id) in i.inputs.iter().enumerate() {
                if let Some((prev, at)) =
                    self.instances[..b]
                        .iter()
                        .enumerate()
                        .find_map(|(j, other)| {
                            other.inputs.iter().position(|x| x == id).map(|at| (j, at))
                        })
                {
                    if tables[prev][at] != group[n] {
                        return Err(Error::PublicShape);
                    }
                }
            }
        }
        Ok(())
    }
    fn start(&self, transcript: &mut Transcript<K>) -> Result<(Vec<K>, K), Error> {
        transcript.absorb(AbsorbLabel::Batch, &self.encode()?)?;
        let gamma = transcript.challenge(ChallengeLabel::BatchCoefficient)?;
        let mut weights = Vec::new();
        reserve(&mut weights, self.instances.len())?;
        let (mut w, mut sum) = (K::from_i64(1), K::from_i64(0));
        for i in self.instances {
            weights.push(w);
            sum = sum + w * i.claimed_sum;
            w = w * gamma;
        }
        Ok((weights, sum))
    }
    fn finish(
        &self,
        values: &[K],
        point: &[K],
        weights: &[K],
        running: K,
        transcript: &mut Transcript<K>,
    ) -> Result<(), Error> {
        let mut out = Vec::new();
        append(&mut out, &self.id.to_le_bytes())?;
        append(&mut out, &[0])?;
        append(&mut out, &(self.instances.len() as u32).to_le_bytes())?;
        let (mut at, mut sum) = (0, K::from_i64(0));
        for (i, w) in self.instances.iter().zip(weights) {
            let end = at + i.inputs.len();
            let selector = point[..point.len() - i.num_vars as usize]
                .iter()
                .fold(K::from_i64(1), |s, r| s * (K::from_i64(1) - *r));
            sum = sum + *w * selector * i.evaluate(&values[at..end]);
            append(
                &mut out,
                &message_bytes(i.id, i.inputs.len() as u32, &values[at..end])?,
            )?;
            at = end;
        }
        if sum != running {
            return Err(Error::FinalEvaluationMismatch);
        }
        transcript.absorb(AbsorbLabel::BatchFinal, &out)?;
        Ok(())
    }
    /// Fold original tables only when their suffix coordinates become active.
    pub fn prove(
        &self,
        tables: Vec<Vec<Vec<K>>>,
        transcript: &mut Transcript<K>,
    ) -> Result<Proof<K>, Error> {
        self.tables(&tables)?;
        let (m, degree, inputs) = self.shape()?;
        let mut states = Vec::new();
        reserve(&mut states, tables.len())?;
        for (i, data) in self.instances.iter().zip(tables) {
            let dense = Dense::new(i, data)?;
            let sum = if i.num_vars < m {
                dense.sum(i)?
            } else {
                K::from_i64(0)
            };
            states.push((dense, sum, K::from_i64(1)));
        }
        let (weights, mut running) = self.start(transcript)?;
        let mut rounds = Vec::new();
        reserve(&mut rounds, m as usize)?;
        let mut point = Vec::new();
        reserve(&mut point, m as usize)?;
        for index in 0..m {
            let mut values = Vec::new();
            reserve(&mut values, degree + 1)?;
            values.resize(degree + 1, K::from_i64(0));
            for ((i, (dense, sum, selector)), w) in self.instances.iter().zip(&states).zip(&weights)
            {
                let active = index >= m - i.num_vars;
                let row = if active { dense.round(i)? } else { Vec::new() };
                for (node, out) in values.iter_mut().enumerate() {
                    let x = K::from_i64(node as i64);
                    let value = if active {
                        if node < row.len() {
                            row[node]
                        } else {
                            interpolate(&row, x)?
                        }
                    } else {
                        *sum * (K::from_i64(1) - x)
                    };
                    *out = *out + *w * *selector * value;
                }
            }
            let (r, next) = round(self.id, index, &values, running, transcript)?;
            for (i, (dense, _, selector)) in self.instances.iter().zip(&mut states) {
                if index < m - i.num_vars {
                    *selector = *selector * (K::from_i64(1) - r);
                } else {
                    dense.fold(r)?;
                }
            }
            point.push(r);
            rounds.push(values);
            running = next;
        }
        let mut final_values = Vec::new();
        reserve(&mut final_values, inputs)?;
        for (dense, _, _) in states {
            final_values.extend(dense.final_values()?);
        }
        self.finish(&final_values, &point, &weights, running, transcript)?;
        Ok(Proof {
            rounds,
            final_values,
        })
    }
    /// Verify the reduction and return every suffix-point evaluation obligation.
    pub fn verify(
        &self,
        proof: &Proof<K>,
        transcript: &mut Transcript<K>,
    ) -> Result<Reduction<K>, Error> {
        let (m, degree, inputs) = self.shape()?;
        if proof.rounds.len() != m as usize
            || proof.final_values.len() != inputs
            || proof.rounds.iter().any(|r| r.len() != degree + 1)
        {
            return Err(Error::ProofShape);
        }
        let (weights, mut running) = self.start(transcript)?;
        let mut point = Vec::new();
        reserve(&mut point, m as usize)?;
        for (index, values) in proof.rounds.iter().enumerate() {
            let (r, next) = round(self.id, index as u32, values, running, transcript)?;
            point.push(r);
            running = next;
        }
        self.finish(&proof.final_values, &point, &weights, running, transcript)?;
        let mut claims = Vec::new();
        reserve(&mut claims, inputs)?;
        for i in self.instances {
            for id in &i.inputs {
                let mut suffix = Vec::new();
                reserve(&mut suffix, i.num_vars as usize)?;
                suffix.extend_from_slice(&point[m as usize - i.num_vars as usize..]);
                claims.push(Claim {
                    tensor: *id,
                    point: suffix,
                    value: proof.final_values[claims.len()],
                });
            }
        }
        Ok(Reduction {
            point,
            claims,
            sc: ScRecord {
                id: self.id,
                m,
                degree: degree as u8,
                field_degree: field_degree::<K>(),
                numerator: u64::from(m) * degree as u64,
            },
            rlc: RlcRecord {
                id: self.id,
                t: self.instances.len() as u32,
                field_degree: field_degree::<K>(),
                numerator: self.instances.len() as u64,
            },
        })
    }
    /// Close every obligation against verifier-owned tables, including unused inputs.
    pub fn verify_public(
        &self,
        proof: &Proof<K>,
        tables: &[Vec<Vec<K>>],
        transcript: &mut Transcript<K>,
    ) -> Result<Reduction<K>, Error> {
        self.tables(tables)?;
        let result = self.verify(proof, transcript)?;
        for (claim, table) in result.claims.iter().zip(tables.iter().flatten()) {
            let weights = stele_poly::eq_table(&claim.point).map_err(|_| Error::Capacity)?;
            let actual = table
                .iter()
                .zip(weights)
                .fold(K::from_i64(0), |s, (v, w)| s + *v * w);
            if actual != claim.value {
                return Err(Error::ClaimMismatch);
            }
        }
        Ok(result)
    }
}
pub(crate) fn field_degree<K: ChallengeField>() -> u8 {
    (K::from_i64(0).to_le_bytes().as_ref().len() / 4) as u8
}

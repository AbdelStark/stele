//! Eq-factored zerocheck and bounded skip with original slice claims, RFC-0006 A3.
use crate::{
    append,
    batch::{field_degree, Claim},
    dense::check_tables,
    interpolate, message_bytes, reserve, Error, Instance, ScRecord,
};
use alloc::vec::Vec;
use stele_hash::{AbsorbLabel, ChallengeField, ChallengeLabel, Transcript};
/// Logical A3 proof; all lengths come from the verifier's descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Proof<K> {
    /// Outside-node values Q(s)..Q(D); empty when k=0 or degree=1.
    pub skip_values: Vec<K>,
    /// Tail rows, each with degree+1 evaluations.
    pub rounds: Vec<Vec<K>>,
    /// Input-major, then ascending Boolean prefix; no claimed points.
    pub final_values: Vec<K>,
}
/// Conditional reduction: no statement acceptance until every claim is consumed.
#[must_use = "discharge every original tensor slice claim"]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Reduction<K> {
    /// All original MLE claims, including unused or zero-weight slices.
    pub claims: Vec<Claim<K>>,
    /// SC phases 0 (weights), 1 (skip), 2 (tail), in that fixed order.
    pub sc: [ScRecord; 3],
}
/// Verifier-owned row-zero relation, not merely a zero Boolean sum.
pub struct Zerocheck<'a, K> {
    /// Reuses A1's ordered polynomial/ids; claimed_sum must be zero and is not encoded.
    pub instance: &'a Instance<K>,
    /// Plan-fixed leading coordinates to skip, 0..=min(m,4).
    pub skip: u8,
}
fn zeros<K: ChallengeField>(n: usize) -> Result<Vec<K>, Error> {
    let mut out = Vec::new();
    reserve(&mut out, n)?;
    out.resize(n, K::from_i64(0));
    Ok(out)
}
fn dot<K: ChallengeField>(a: &[K], b: &[K]) -> K {
    a.iter()
        .zip(b)
        .fold(K::from_i64(0), |sum, (a, b)| sum + *a * *b)
}
fn fold<K: ChallengeField>(table: &mut Vec<K>, r: K) {
    let half = table.len() / 2;
    for c in 0..half {
        table[c] = table[c] + r * (table[c + half] - table[c]);
    }
    table.truncate(half);
}
impl<K: ChallengeField + Eq> Zerocheck<'_, K> {
    fn shape(&self) -> Result<(usize, usize, u32, usize), Error> {
        let degree = self
            .instance
            .validate()
            .map_err(|_| Error::InvalidZerocheck)?;
        if self.skip > 4
            || u32::from(self.skip) > self.instance.num_vars
            || (degree == 0 && self.skip != 0)
            || self.instance.claimed_sum != K::from_i64(0)
        {
            return Err(Error::InvalidZerocheck);
        }
        let s = 1usize << self.skip;
        Ok((
            degree,
            s,
            self.instance.num_vars - u32::from(self.skip),
            degree.saturating_sub(1) * (s - 1),
        ))
    }
    /// Canonical A3 descriptor; no A1 claimed-sum suffix.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        self.shape()?;
        let mut out = self.instance.encode()?;
        out.truncate(out.len() - usize::from(field_degree::<K>()) * 4);
        reserve(&mut out, 1)?;
        // A3 inserts k after version, field, id and m: 1+1+8+4 bytes.
        out.insert(14, self.skip);
        Ok(out)
    }
    fn start(&self, t: &mut Transcript<K>, j: u32) -> Result<Vec<K>, Error> {
        let mut alpha = zeros(j as usize)?;
        t.absorb(AbsorbLabel::Zero, &self.encode()?)?;
        for value in &mut alpha {
            *value = t.challenge(ChallengeLabel::ZeroWeight)?;
        }
        Ok(alpha)
    }
    fn skip_round(
        &self,
        t: &mut Transcript<K>,
        values: &[K],
        s: usize,
    ) -> Result<(Vec<K>, K), Error> {
        if self.skip == 0 {
            let mut weights = zeros(1)?;
            weights[0] = K::from_i64(1);
            return Ok((weights, K::from_i64(0)));
        }
        t.absorb(
            AbsorbLabel::ZeroSkip,
            &message_bytes(self.instance.id, values.len() as u32, values)?,
        )?;
        let u = t.challenge(ChallengeLabel::Sumcheck)?;
        let mut polynomial = zeros(s)?;
        reserve(&mut polynomial, values.len())?;
        polynomial.extend_from_slice(values);
        Ok((
            crate::interpolation_weights(s, u)?,
            interpolate(&polynomial, u)?,
        ))
    }
    fn round(
        &self,
        t: &mut Transcript<K>,
        h: usize,
        row: &[K],
        alpha: K,
        running: K,
    ) -> Result<(K, K), Error> {
        let at_one = row[usize::from(row.len() > 1)];
        if (K::from_i64(1) - alpha) * row[0] + alpha * at_one != running {
            return Err(Error::RoundSumMismatch);
        }
        t.absorb(
            AbsorbLabel::Round,
            &message_bytes(self.instance.id, h as u32, row)?,
        )?;
        let r = t.challenge(ChallengeLabel::Sumcheck)?;
        Ok((r, interpolate(row, r)?))
    }
    fn finish(
        &self,
        t: &mut Transcript<K>,
        final_values: &[K],
        weights: &[K],
        running: K,
    ) -> Result<(), Error> {
        let mut values = zeros(self.instance.inputs.len())?;
        for (out, slice) in values
            .iter_mut()
            .zip(final_values.chunks_exact(weights.len()))
        {
            *out = dot(weights, slice);
        }
        if self.instance.evaluate(&values) != running {
            return Err(Error::FinalEvaluationMismatch);
        }
        let mut bytes = message_bytes::<K>(self.instance.id, values.len() as u32, &[])?;
        append(&mut bytes, &(weights.len() as u32).to_le_bytes())?;
        for v in final_values {
            append(&mut bytes, v.to_le_bytes().as_ref())?;
        }
        t.absorb(AbsorbLabel::ZeroFinal, &bytes)?;
        Ok(())
    }
    /// Verify the reduction and emit all original tensor evaluations and phased SC records.
    pub fn verify(&self, proof: &Proof<K>, t: &mut Transcript<K>) -> Result<Reduction<K>, Error> {
        let (degree, s, j, count) = self.shape()?;
        let finals = self
            .instance
            .inputs
            .len()
            .checked_mul(s)
            .ok_or(Error::Capacity)?;
        if proof.skip_values.len() != count
            || proof.rounds.len() != j as usize
            || proof.final_values.len() != finals
            || proof.rounds.iter().any(|row| row.len() != degree + 1)
        {
            return Err(Error::ProofShape);
        }
        let mut point = zeros(j as usize)?;
        let mut claims = Vec::new();
        reserve(&mut claims, finals)?;
        let alpha = self.start(t, j)?;
        let (weights, mut running) = self.skip_round(t, &proof.skip_values, s)?;
        for (h, row) in proof.rounds.iter().enumerate() {
            (point[h], running) = self.round(t, h, row, alpha[h], running)?;
        }
        self.finish(t, &proof.final_values, &weights, running)?;
        for (input, values) in self
            .instance
            .inputs
            .iter()
            .zip(proof.final_values.chunks_exact(s))
        {
            for (b, value) in values.iter().enumerate() {
                let mut full = zeros(self.instance.num_vars as usize)?;
                for (bit, out) in full[..self.skip as usize].iter_mut().enumerate() {
                    *out = K::from_i64(((b >> (self.skip as usize - bit - 1)) & 1) as i64);
                }
                full[self.skip as usize..].copy_from_slice(&point);
                claims.push(Claim {
                    tensor: *input,
                    point: full,
                    value: *value,
                });
            }
        }
        let sc = [
            (j, 1),
            (u32::from(self.skip > 0), degree * (s - 1)),
            (j, degree),
        ]
        .map(|(m, degree)| ScRecord {
            id: self.instance.id,
            m,
            degree: degree as u8,
            field_degree: field_degree::<K>(),
            numerator: u64::from(m) * degree as u64,
        });
        Ok(Reduction { claims, sc })
    }
    /// Close all returned MLE claims against verifier-owned original tables.
    pub fn verify_public(
        &self,
        proof: &Proof<K>,
        tables: &[Vec<K>],
        t: &mut Transcript<K>,
    ) -> Result<Reduction<K>, Error> {
        let (_, s, _, _) = self.shape()?;
        check_tables(self.instance, tables)?;
        let result = self.verify(proof, t)?;
        for (table, claims) in tables.iter().zip(result.claims.chunks_exact(s)) {
            for claim in claims {
                let weights = stele_poly::eq_table(&claim.point).map_err(|_| Error::Capacity)?;
                if dot(table, &weights) != claim.value {
                    return Err(Error::ClaimMismatch);
                }
            }
        }
        Ok(result)
    }
    fn hybrid(&self, tables: &[Vec<K>], width: usize, weights: &[K]) -> Result<Vec<Vec<K>>, Error> {
        let mut out = Vec::new();
        reserve(&mut out, tables.len())?;
        for table in tables {
            let mut values = zeros(width)?;
            for (slice, weight) in table.chunks_exact(width).zip(weights) {
                for (out, value) in values.iter_mut().zip(slice) {
                    *out = *out + *weight * *value;
                }
            }
            out.push(values);
        }
        Ok(out)
    }
    fn sum(&self, tables: &[Vec<K>], weights: &[K], node: Option<K>) -> Result<K, Error> {
        let mut values = zeros(tables.len())?;
        let mut sum = K::from_i64(0);
        for (column, weight) in weights.iter().enumerate() {
            for (value, table) in values.iter_mut().zip(tables) {
                *value = table[column];
                if let Some(x) = node {
                    *value = *value + x * (table[column + weights.len()] - *value);
                }
            }
            sum = sum + *weight * self.instance.evaluate(&values);
        }
        Ok(sum)
    }
    /// Dense CPU prover: interpolate prefixes, fold tail coordinates, retain original slices.
    pub fn prove(&self, tables: &[Vec<K>], t: &mut Transcript<K>) -> Result<Proof<K>, Error> {
        let (degree, s, j, count) = self.shape()?;
        check_tables(self.instance, tables)?;
        let width = 1usize.checked_shl(j).ok_or(Error::Capacity)?;
        let alpha = self.start(t, j)?;
        let eq = stele_poly::eq_table(&alpha).map_err(|_| Error::Capacity)?;
        let mut skip_values = zeros(count)?;
        for (offset, value) in skip_values.iter_mut().enumerate() {
            let weights = crate::interpolation_weights(s, K::from_i64((s + offset) as i64))?;
            *value = self.sum(&self.hybrid(tables, width, &weights)?, &eq, None)?;
        }
        let (weights, mut running) = self.skip_round(t, &skip_values, s)?;
        let mut state = self.hybrid(tables, width, &weights)?;
        let mut rounds = Vec::new();
        reserve(&mut rounds, j as usize)?;
        let mut point = zeros(j as usize)?;
        for h in 0..j as usize {
            let eq = stele_poly::eq_table(&alpha[h + 1..]).map_err(|_| Error::Capacity)?;
            let mut row = zeros(degree + 1)?;
            for (node, value) in row.iter_mut().enumerate() {
                *value = self.sum(&state, &eq, Some(K::from_i64(node as i64)))?;
            }
            (point[h], running) = self.round(t, h, &row, alpha[h], running)?;
            for table in &mut state {
                fold(table, point[h]);
            }
            rounds.push(row);
        }
        let mut final_values = Vec::new();
        reserve(
            &mut final_values,
            tables.len().checked_mul(s).ok_or(Error::Capacity)?,
        )?;
        for table in tables {
            for slice in table.chunks_exact(width) {
                let mut scratch = zeros(width)?;
                scratch.copy_from_slice(slice);
                for r in &point {
                    fold(&mut scratch, *r);
                }
                final_values.push(scratch[0]);
            }
        }
        self.finish(t, &final_values, &weights, running)?;
        Ok(Proof {
            skip_values,
            rounds,
            final_values,
        })
    }
}

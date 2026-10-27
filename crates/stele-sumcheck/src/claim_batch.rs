//! RFC-0006 A2 mode 1: claims on one virtual tensor, with verifier-computed A(r).
use crate::{
    append,
    batch::{field_degree, Claim, Reduction, RlcRecord},
    reserve, round, Dense, Error, Instance, Proof, ScRecord, Summand, Term,
};
use alloc::vec::Vec;
use stele_hash::{AbsorbLabel, ChallengeField, ChallengeLabel, Transcript};
/// Verifier-owned claims. The caller must derive the virtual role from its verified plan;
/// committed tensors use PCS functional openings, never a proof-supplied routing flag.
pub struct Batch<'a, K> {
    /// Plan batch identity, unique among invocations.
    pub id: u64,
    /// The virtual tensor identity.
    pub tensor: u64,
    /// Its hypercube dimension.
    pub num_vars: u32,
    /// Nonempty ordered (point, value) claims; overlaps and duplicates are allowed.
    pub claims: &'a [(Vec<K>, K)],
}
impl<K: ChallengeField + Eq> Batch<'_, K> {
    fn validate(&self) -> Result<(), Error> {
        if self.claims.is_empty()
            || u32::try_from(self.claims.len()).is_err()
            || self
                .claims
                .iter()
                .any(|(z, _)| z.len() != self.num_vars as usize)
        {
            return Err(Error::InvalidBatch);
        }
        Ok(())
    }
    fn table(&self, table: &[K]) -> Result<(), Error> {
        self.validate()?;
        if !table.len().is_power_of_two() || table.len().trailing_zeros() != self.num_vars {
            return Err(Error::PublicShape);
        }
        Ok(())
    }
    /// Canonical mode-1 descriptor, binding every point/value before gamma.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut out = Vec::new();
        append(&mut out, &[1, field_degree::<K>(), 1])?;
        append(&mut out, &self.id.to_le_bytes())?;
        append(&mut out, &self.tensor.to_le_bytes())?;
        append(&mut out, &self.num_vars.to_le_bytes())?;
        append(&mut out, &(self.claims.len() as u32).to_le_bytes())?;
        for (z, value) in self.claims {
            for x in z.iter().chain(core::iter::once(value)) {
                append(&mut out, x.to_le_bytes().as_ref())?;
            }
        }
        Ok(out)
    }
    /// Pure coefficient construction, not a way to supply a protocol challenge.
    /// Maximal leading Boolean prefixes select contiguous blocks; overlaps accumulate.
    pub fn coefficient_table(&self, gamma: K) -> Result<Vec<K>, Error> {
        self.validate()?;
        let n = 1usize.checked_shl(self.num_vars).ok_or(Error::Capacity)?;
        let (zero, one) = (K::from_i64(0), K::from_i64(1));
        let mut out = Vec::new();
        reserve(&mut out, n)?;
        out.resize(n, zero);
        let mut weight = one;
        for (z, _) in self.claims {
            let (mut prefix, mut start) = (0, 0);
            for x in z {
                if *x != zero && *x != one {
                    break;
                }
                start = 2 * start + usize::from(*x == one);
                prefix += 1;
            }
            let suffix = stele_poly::eq_table(&z[prefix..]).map_err(|_| Error::Capacity)?;
            // A2: start < 2^prefix and suffix.len() = 2^(m-prefix), so the block fits.
            let begin = start * suffix.len();
            for (target, value) in out[begin..begin + suffix.len()].iter_mut().zip(suffix) {
                *target = *target + weight * value;
            }
            weight = weight * gamma;
        }
        Ok(out)
    }
    /// Direct verifier evaluation in O(t*(m+1)); no coefficient table or final A value.
    pub fn coefficient(&self, point: &[K], gamma: K) -> Result<K, Error> {
        self.validate()?;
        if point.len() != self.num_vars as usize {
            return Err(Error::PublicShape);
        }
        let (mut weight, mut sum) = (K::from_i64(1), K::from_i64(0));
        for (z, _) in self.claims {
            sum =
                sum + weight * stele_poly::eq_evaluate(z, point).map_err(|_| Error::PublicShape)?;
            weight = weight * gamma;
        }
        Ok(sum)
    }
    fn start(&self, transcript: &mut Transcript<K>) -> Result<(K, K), Error> {
        transcript.absorb(AbsorbLabel::Batch, &self.encode()?)?;
        let gamma = transcript.challenge(ChallengeLabel::BatchCoefficient)?;
        let (mut weight, mut sum) = (K::from_i64(1), K::from_i64(0));
        for (_, value) in self.claims {
            sum = sum + weight * *value;
            weight = weight * gamma;
        }
        Ok((gamma, sum))
    }
    fn finish(
        &self,
        value: K,
        point: &[K],
        gamma: K,
        running: K,
        transcript: &mut Transcript<K>,
    ) -> Result<(), Error> {
        if value * self.coefficient(point, gamma)? != running {
            return Err(Error::FinalEvaluationMismatch);
        }
        let mut out = Vec::new();
        append(&mut out, &self.id.to_le_bytes())?;
        append(&mut out, &[1])?;
        append(&mut out, &self.tensor.to_le_bytes())?;
        append(&mut out, value.to_le_bytes().as_ref())?;
        transcript.absorb(AbsorbLabel::BatchFinal, &out)?;
        Ok(())
    }
    // Local polynomial description for Dense only; never a transcript instance.
    fn product(&self, sum: K) -> Result<Instance<K>, Error> {
        let mut inputs = Vec::new();
        reserve(&mut inputs, 2)?;
        inputs.extend([0, 1]);
        let mut factors = Vec::new();
        reserve(&mut factors, 2)?;
        factors.extend([0, 1]);
        let mut terms = Vec::new();
        reserve(&mut terms, 1)?;
        terms.push(Term {
            coefficient: K::from_i64(1),
            factors,
        });
        Ok(Instance {
            id: self.id,
            num_vars: self.num_vars,
            inputs,
            terms,
            claimed_sum: sum,
        })
    }
    /// Prove with gamma drawn only by the engine after the complete descriptor.
    pub fn prove(&self, table: Vec<K>, transcript: &mut Transcript<K>) -> Result<Proof<K>, Error> {
        self.table(&table)?;
        let (gamma, mut running) = self.start(transcript)?;
        let mut tables = Vec::new();
        reserve(&mut tables, 2)?;
        tables.push(table);
        tables.push(self.coefficient_table(gamma)?);
        let product = self.product(running)?;
        let mut dense = Dense::new(&product, tables)?;
        let mut rounds = Vec::new();
        reserve(&mut rounds, self.num_vars as usize)?;
        let mut point = Vec::new();
        reserve(&mut point, self.num_vars as usize)?;
        for index in 0..self.num_vars {
            let values = dense.round(&product)?;
            let (r, next) = round(self.id, index, &values, running, transcript)?;
            dense.fold(r)?;
            rounds.push(values);
            point.push(r);
            running = next;
        }
        let mut final_values = Vec::new();
        reserve(&mut final_values, 1)?;
        final_values.push(dense.final_values()?[0]);
        self.finish(final_values[0], &point, gamma, running, transcript)?;
        Ok(Proof {
            rounds,
            final_values,
        })
    }
    /// Reduce to one y(r) obligation, even when A(r)=0; this is not statement acceptance.
    pub fn verify(
        &self,
        proof: &Proof<K>,
        transcript: &mut Transcript<K>,
    ) -> Result<Reduction<K>, Error> {
        self.validate()?;
        if proof.rounds.len() != self.num_vars as usize
            || proof.rounds.iter().any(|r| r.len() != 3)
            || proof.final_values.len() != 1
        {
            return Err(Error::ProofShape);
        }
        let (gamma, mut running) = self.start(transcript)?;
        let mut point = Vec::new();
        reserve(&mut point, self.num_vars as usize)?;
        for (index, values) in proof.rounds.iter().enumerate() {
            let (r, next) = round(self.id, index as u32, values, running, transcript)?;
            point.push(r);
            running = next;
        }
        self.finish(proof.final_values[0], &point, gamma, running, transcript)?;
        let mut copy = Vec::new();
        reserve(&mut copy, point.len())?;
        copy.extend_from_slice(&point);
        let mut claims = Vec::new();
        reserve(&mut claims, 1)?;
        claims.push(Claim {
            tensor: self.tensor,
            point: copy,
            value: proof.final_values[0],
        });
        Ok(Reduction {
            point,
            claims,
            sc: ScRecord {
                id: self.id,
                m: self.num_vars,
                degree: 2,
                field_degree: field_degree::<K>(),
                numerator: 2 * u64::from(self.num_vars),
            },
            rlc: RlcRecord {
                id: self.id,
                t: self.claims.len() as u32,
                field_degree: field_degree::<K>(),
                numerator: self.claims.len() as u64,
            },
        })
    }
    /// Discharge the sole tensor evaluation against verifier-owned public data.
    pub fn verify_public(
        &self,
        proof: &Proof<K>,
        table: &[K],
        transcript: &mut Transcript<K>,
    ) -> Result<Reduction<K>, Error> {
        self.table(table)?;
        let result = self.verify(proof, transcript)?;
        let weights = stele_poly::eq_table(&result.point).map_err(|_| Error::Capacity)?;
        let actual = table
            .iter()
            .zip(weights)
            .fold(K::from_i64(0), |s, (v, w)| s + *v * w);
        if actual != result.claims[0].value {
            return Err(Error::ClaimMismatch);
        }
        Ok(result)
    }
}

//! The A2 batch verifiers: an ordered batch of A1 instances (mode 0) and a batch of
//! claims on one virtual tensor (mode 1), each one sumcheck under a random linear
//! combination (RFC-0006 A2, task E8-02b).
//!
//! Provenance (#373 review): this module was derived from `stele-sumcheck`'s
//! verifiers. Mode 0's `shape` transcribes production condition for condition. It was
//! then checked against the RFC-0006 A2 text by a non-author review, and it is held to
//! `research/batching/corpus.jsonl` and the production decisions recorded beside it.
//! It shares no code with `stele-sumcheck`, but it is not an independent derivation.
//! ADR-128 records that, and writes later pieces from the RFC alone.

use crate::sumcheck::{
    bytes_of, degree, evaluate, instance_bytes, message, mle_at, step, Bytes, Error, Instance,
    Proof, ScRecord,
};
use crate::zerocheck::Claim;
use alloc::vec::Vec;
use stele_hash::{AbsorbLabel, ChallengeField, ChallengeLabel, Transcript};

/// The RLC record: `t` members under one coefficient challenge, charged `t/p^d`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RlcRecord {
    pub id: u64,
    pub t: u32,
    pub field_degree: u8,
    pub numerator: u64,
}

/// A verified batch: the shared point, one claim per member input, and the SC and RLC
/// records.
#[derive(Clone, Debug, Eq, PartialEq)]
#[must_use = "every claim needs a consumer"]
pub struct Reduction<K> {
    pub point: Vec<K>,
    pub claims: Vec<Claim<K>>,
    pub sc: ScRecord,
    pub rlc: RlcRecord,
}

fn field_degree<K: ChallengeField>() -> u8 {
    (bytes_of(&K::from_i64(0)) / 4) as u8
}

/// `γ^0, γ^1, …` for the members, and `Σ γ^k·x_k`.
fn powers<K: ChallengeField>(
    gamma: K,
    xs: impl ExactSizeIterator<Item = K>,
) -> Result<(Vec<K>, K), Error> {
    let mut out = Vec::new();
    out.try_reserve_exact(xs.len())
        .map_err(|_| Error::Capacity)?;
    let (mut w, mut sum) = (K::from_i64(1), K::from_i64(0));
    for x in xs {
        out.push(w);
        sum = sum + w * x;
        w = w * gamma;
    }
    Ok((out, sum))
}

/// Mode 0: ordered instances, sized to the largest; a smaller instance is a suffix of
/// the point, with `Π(1 − r)` over the leading coordinates it does not read.
pub struct Batch<'a, K> {
    pub id: u64,
    pub instances: &'a [Instance<K>],
}

impl<K: ChallengeField + Eq> Batch<'_, K> {
    /// `(m, degree, total inputs)`; a mixed-size batch has degree at least 1.
    fn shape(&self) -> Result<(u32, usize, usize), Error> {
        if self.instances.is_empty() || u32::try_from(self.instances.len()).is_err() {
            return Err(Error::InvalidBatch);
        }
        let (mut m, mut d, mut inputs) = (0u32, 0usize, 0usize);
        // RFC-0006 A2: ids distinct from each other and from the batch; an input shared
        // by two instances only between instances of one size.
        for (b, i) in self.instances.iter().enumerate() {
            d = d.max(degree(i).map_err(|_| Error::InvalidBatch)?);
            m = m.max(i.num_vars);
            inputs = inputs.checked_add(i.inputs.len()).ok_or(Error::Capacity)?;
            let clash = self.instances[..b].iter().any(|o| {
                o.id == i.id
                    || (o.num_vars != i.num_vars && i.inputs.iter().any(|x| o.inputs.contains(x)))
            });
            if i.id == self.id || clash {
                return Err(Error::InvalidBatch);
            }
        }
        if self.instances.iter().any(|i| i.num_vars != m) {
            d = d.max(1);
        }
        Ok((m, d, inputs))
    }

    /// `u8 1, u8 field, u8 mode 0, u64 id, u32 count, u32 m, u8 degree`, then each
    /// instance's length-prefixed A1 bytes.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let (m, d, _) = self.shape()?;
        let mut parts = Vec::new();
        parts
            .try_reserve_exact(self.instances.len())
            .map_err(|_| Error::Capacity)?;
        let mut size = 23usize;
        for i in self.instances {
            let bytes = instance_bytes(i, degree(i)?)?;
            size = size.checked_add(8 + bytes.len()).ok_or(Error::Capacity)?;
            parts.push(bytes);
        }
        let mut out = Bytes::with(size)?;
        out.put(&[1, field_degree::<K>(), 0])
            .put(&self.id.to_le_bytes())
            .put(&(self.instances.len() as u32).to_le_bytes())
            .put(&m.to_le_bytes())
            .put(&[d as u8]);
        for bytes in &parts {
            out.put(&(bytes.len() as u64).to_le_bytes()).put(bytes);
        }
        Ok(out.0)
    }

    pub fn verify(&self, proof: &Proof<K>, t: &mut Transcript<K>) -> Result<Reduction<K>, Error> {
        let (m, d, inputs) = self.shape()?;
        // RFC-0006 A2: exactly m rounds of degree + 1 values and one final value per
        // member input; never more or fewer.
        if proof.rounds.len() != m as usize
            || proof.final_values.len() != inputs
            || proof.rounds.iter().any(|r| r.len() != d + 1)
        {
            return Err(Error::ProofShape);
        }
        t.absorb(AbsorbLabel::Batch, &self.encode()?)?;
        let gamma = t.challenge(ChallengeLabel::BatchCoefficient)?;
        let (weights, mut claim) = powers(gamma, self.instances.iter().map(|i| i.claimed_sum))?;
        let mut point = Vec::new();
        point
            .try_reserve_exact(m as usize)
            .map_err(|_| Error::Capacity)?;
        for (index, g) in (0u32..).zip(&proof.rounds) {
            let r;
            (r, claim) = step(self.id, index, g, claim, t)?;
            point.push(r);
        }
        let mut tail = Vec::new();
        tail.try_reserve_exact(13).map_err(|_| Error::Capacity)?;
        tail.extend_from_slice(&self.id.to_le_bytes());
        tail.push(0);
        tail.extend_from_slice(&(self.instances.len() as u32).to_le_bytes());
        let (mut at, mut sum) = (0usize, K::from_i64(0));
        for (i, w) in self.instances.iter().zip(&weights) {
            let values = &proof.final_values[at..at + i.inputs.len()];
            let lead = (m - i.num_vars) as usize;
            let mut selector = K::from_i64(1);
            for r in &point[..lead] {
                selector = selector * (K::from_i64(1) - *r);
            }
            sum = sum + *w * selector * evaluate(i, values);
            let part = message(i.id, i.inputs.len() as u32, values)?;
            tail.try_reserve_exact(part.len())
                .map_err(|_| Error::Capacity)?;
            tail.extend_from_slice(&part);
            at += i.inputs.len();
        }
        // RFC-0006 A2: Σ γ^k·selector_k·P_k(finals) is the last claim.
        if sum != claim {
            return Err(Error::FinalEvaluationMismatch);
        }
        t.absorb(AbsorbLabel::BatchFinal, &tail)?;
        let mut claims = Vec::new();
        claims
            .try_reserve_exact(inputs)
            .map_err(|_| Error::Capacity)?;
        for i in self.instances {
            let lead = (m - i.num_vars) as usize;
            for tensor in &i.inputs {
                let mut suffix = Vec::new();
                suffix
                    .try_reserve_exact(point.len() - lead)
                    .map_err(|_| Error::Capacity)?;
                suffix.extend_from_slice(&point[lead..]);
                claims.push(Claim {
                    tensor: *tensor,
                    point: suffix,
                    value: proof.final_values[claims.len()],
                });
            }
        }
        let fd = field_degree::<K>();
        let count = self.instances.len() as u32;
        Ok(Reduction {
            point,
            claims,
            sc: ScRecord {
                id: self.id,
                m,
                degree: d as u8,
                field_degree: fd,
                numerator: u64::from(m) * d as u64,
            },
            rlc: RlcRecord {
                id: self.id,
                t: count,
                field_degree: fd,
                numerator: u64::from(count),
            },
        })
    }

    /// [`Self::verify`], then every claim against the verifier's own tables, grouped
    /// per instance. An input shared by two instances must have one table.
    pub fn verify_public(
        &self,
        proof: &Proof<K>,
        tables: &[Vec<Vec<K>>],
        t: &mut Transcript<K>,
    ) -> Result<Reduction<K>, Error> {
        self.shape()?;
        // RFC-0006 A2: one table group per instance, one table per input, and a shared
        // input's tables equal.
        if tables.len() != self.instances.len() {
            return Err(Error::PublicShape);
        }
        for (b, (i, group)) in self.instances.iter().zip(tables).enumerate() {
            degree(i)?;
            let sized = |n: usize| n.is_power_of_two() && n.trailing_zeros() == i.num_vars;
            if group.len() != i.inputs.len() || group.iter().any(|x| !sized(x.len())) {
                return Err(Error::PublicShape);
            }
            for (n, id) in i.inputs.iter().enumerate() {
                let earlier = self.instances[..b]
                    .iter()
                    .enumerate()
                    .find_map(|(j, o)| o.inputs.iter().position(|x| x == id).map(|at| (j, at)));
                if earlier.is_some_and(|(j, at)| tables[j][at] != group[n]) {
                    return Err(Error::PublicShape);
                }
            }
        }
        let result = self.verify(proof, t)?;
        for (claim, table) in result.claims.iter().zip(tables.iter().flatten()) {
            // RFC-0006 A2: each claim is its table's MLE at the claim's point suffix.
            if mle_at(table, &claim.point) != claim.value {
                return Err(Error::ClaimMismatch);
            }
        }
        Ok(result)
    }
}

/// Mode 1: claims `(z_k, v_k)` on one tensor over `num_vars` variables, proved as
/// `Σ_x T(x)·Σ_k γ^k eq(z_k, x)` by a degree-2 sumcheck.
pub struct ClaimBatch<'a, K> {
    pub id: u64,
    pub tensor: u64,
    pub num_vars: u32,
    pub claims: &'a [(Vec<K>, K)],
}

/// `eq(z, r) = Π (z_i·r_i + (1 − z_i)(1 − r_i))`; lengths must agree.
fn eq<K: ChallengeField>(z: &[K], r: &[K]) -> Result<K, Error> {
    if z.len() != r.len() {
        return Err(Error::PublicShape);
    }
    let one = K::from_i64(1);
    Ok(z.iter()
        .zip(r)
        .fold(one, |acc, (a, b)| acc * (*a * *b + (one - *a) * (one - *b))))
}

impl<K: ChallengeField + Eq> ClaimBatch<'_, K> {
    fn validate(&self) -> Result<(), Error> {
        // RFC-0006 A2 mode 1: a non-empty batch, every point of num_vars coordinates.
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

    /// `u8 1, u8 field, u8 mode 1, u64 id, u64 tensor, u32 num_vars, u32 count`, then
    /// each claim's point and value.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let width = bytes_of(&K::from_i64(0));
        let size = self
            .claims
            .len()
            .checked_mul(
                (self.num_vars as usize)
                    .checked_add(1)
                    .and_then(|n| n.checked_mul(width))
                    .ok_or(Error::Capacity)?,
            )
            .and_then(|n| n.checked_add(27))
            .ok_or(Error::Capacity)?;
        let mut out = Bytes::with(size)?;
        out.put(&[1, field_degree::<K>(), 1])
            .put(&self.id.to_le_bytes())
            .put(&self.tensor.to_le_bytes())
            .put(&self.num_vars.to_le_bytes())
            .put(&(self.claims.len() as u32).to_le_bytes());
        for (z, v) in self.claims {
            for x in z.iter().chain(core::iter::once(v)) {
                out.put(x.to_le_bytes().as_ref());
            }
        }
        Ok(out.0)
    }

    pub fn verify(&self, proof: &Proof<K>, t: &mut Transcript<K>) -> Result<Reduction<K>, Error> {
        self.validate()?;
        // RFC-0006 A2 mode 1: num_vars degree-2 rounds (3 values) and one final value.
        if proof.rounds.len() != self.num_vars as usize
            || proof.rounds.iter().any(|r| r.len() != 3)
            || proof.final_values.len() != 1
        {
            return Err(Error::ProofShape);
        }
        t.absorb(AbsorbLabel::Batch, &self.encode()?)?;
        let gamma = t.challenge(ChallengeLabel::BatchCoefficient)?;
        let (_, mut claim) = powers(gamma, self.claims.iter().map(|(_, v)| *v))?;
        let mut point = Vec::new();
        point
            .try_reserve_exact(self.num_vars as usize)
            .map_err(|_| Error::Capacity)?;
        for (index, g) in (0u32..).zip(&proof.rounds) {
            let r;
            (r, claim) = step(self.id, index, g, claim, t)?;
            point.push(r);
        }
        let value = proof.final_values[0];
        let mut coefficient = K::from_i64(0);
        let mut w = K::from_i64(1);
        for (z, _) in self.claims {
            coefficient = coefficient + w * eq(z, &point)?;
            w = w * gamma;
        }
        // RFC-0006 A2 mode 1: T(r)·Σ γ^k eq(z_k, r) is the last claim.
        if value * coefficient != claim {
            return Err(Error::FinalEvaluationMismatch);
        }
        let mut tail = Bytes::with(17 + bytes_of(&value))?;
        tail.put(&self.id.to_le_bytes())
            .put(&[1])
            .put(&self.tensor.to_le_bytes())
            .put(value.to_le_bytes().as_ref());
        t.absorb(AbsorbLabel::BatchFinal, &tail.0)?;
        let fd = field_degree::<K>();
        let count = self.claims.len() as u32;
        Ok(Reduction {
            point: point.clone(),
            claims: alloc::vec![Claim {
                tensor: self.tensor,
                point,
                value,
            }],
            sc: ScRecord {
                id: self.id,
                m: self.num_vars,
                degree: 2,
                field_degree: fd,
                numerator: 2 * u64::from(self.num_vars),
            },
            rlc: RlcRecord {
                id: self.id,
                t: count,
                field_degree: fd,
                numerator: u64::from(count),
            },
        })
    }

    /// [`Self::verify`], then the claim against the verifier's own table.
    pub fn verify_public(
        &self,
        proof: &Proof<K>,
        table: &[K],
        t: &mut Transcript<K>,
    ) -> Result<Reduction<K>, Error> {
        self.validate()?;
        // RFC-0006 A2 mode 1: the tensor's table has 2^num_vars entries.
        if !table.len().is_power_of_two() || table.len().trailing_zeros() != self.num_vars {
            return Err(Error::PublicShape);
        }
        let result = self.verify(proof, t)?;
        // RFC-0006 A2 mode 1: the final value is the table's MLE at the point.
        if mle_at(table, &result.point) != result.claims[0].value {
            return Err(Error::ClaimMismatch);
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sumcheck::Term;
    use stele_field::{Field, QM31};

    fn shape_of(r: Result<Reduction<QM31>, Error>) -> Result<(), Error> {
        r.map(|_| ())
    }

    /// Mode 0's upper bounds: a round row one value too long, an extra round and an
    /// extra final value are each `ProofShape`.
    #[test]
    fn rejects_overlong_instance_batch_proofs() {
        let one = QM31::from_i64(1);
        let instances = [Instance {
            id: 5,
            num_vars: 1,
            inputs: alloc::vec![11],
            terms: alloc::vec![Term {
                coefficient: one,
                factors: alloc::vec![0],
            }],
            claimed_sum: one,
        }];
        let batch = Batch {
            id: 9,
            instances: &instances,
        };
        let honest = || Proof {
            rounds: alloc::vec![alloc::vec![one; 2]],
            final_values: alloc::vec![one],
        };
        let mut long = [honest(), honest(), honest()];
        long[0].rounds[0].push(one);
        long[1].rounds.push(alloc::vec![one; 2]);
        long[2].final_values.push(one);
        for proof in long {
            let mut t = Transcript::new(b"stele/test/a2-shape").expect("transcript");
            assert_eq!(
                shape_of(batch.verify(&proof, &mut t)),
                Err(Error::ProofShape)
            );
        }
    }

    /// Mode 1's upper bounds: a round row of 4 values, an extra round and a second final
    /// value are each `ProofShape`.
    #[test]
    fn rejects_overlong_claim_batch_proofs() {
        let one = QM31::from_i64(1);
        let claims = [(alloc::vec![one], one)];
        let batch = ClaimBatch {
            id: 9,
            tensor: 11,
            num_vars: 1,
            claims: &claims,
        };
        let honest = || Proof {
            rounds: alloc::vec![alloc::vec![one; 3]],
            final_values: alloc::vec![one],
        };
        let mut long = [honest(), honest(), honest()];
        long[0].rounds[0].push(one);
        long[1].rounds.push(alloc::vec![one; 3]);
        long[2].final_values.push(one);
        for proof in long {
            let mut t = Transcript::new(b"stele/test/a2-shape").expect("transcript");
            assert_eq!(
                shape_of(batch.verify(&proof, &mut t)),
                Err(Error::ProofShape)
            );
        }
    }
}

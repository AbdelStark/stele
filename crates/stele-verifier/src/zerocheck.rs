//! The A3 zerocheck verifier: eq-weighted rows that must vanish, with a bounded
//! skip over the leading coordinates (RFC-0006 A3, task E8-02b).
//!
//! An independent re-implementation, held to `research/zerocheck/corpus.jsonl` and
//! the production decisions recorded beside it. No code is shared with
//! `stele-sumcheck`.

use crate::sumcheck::{
    bytes_of, degree, evaluate, instance_bytes, lagrange, message, mle_at, Bytes, Error, Instance,
    ScRecord,
};
use alloc::vec::Vec;
use stele_hash::{AbsorbLabel, ChallengeField, ChallengeLabel, Transcript};

/// A zerocheck over `instance` (whose claimed sum must be zero) that skips its first
/// `skip ≤ 4` coordinates by interpolation over `2^skip` nodes.
pub struct Zerocheck<'a, K> {
    pub instance: &'a Instance<K>,
    pub skip: u8,
}

/// A3 proof: the skip polynomial's values past the zero nodes, one row per tail
/// round, and for each input its `2^skip` slice values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Proof<K> {
    pub skip_values: Vec<K>,
    pub rounds: Vec<Vec<K>>,
    pub final_values: Vec<K>,
}

/// One original-tensor claim: `tensor` at `point` (Boolean skip bits, then the tail
/// challenges) is `value`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Claim<K> {
    pub tensor: u64,
    pub point: Vec<K>,
    pub value: K,
}

/// A verified zerocheck: every slice claim, and the SC records of its weight, skip and
/// tail phases.
#[derive(Clone, Debug, Eq, PartialEq)]
#[must_use = "every claim needs a consumer"]
pub struct Reduction<K> {
    pub claims: Vec<Claim<K>>,
    pub sc: [ScRecord; 3],
}

/// `(degree, s = 2^skip, tail rounds j, skip values count)`.
struct Shape {
    degree: usize,
    s: usize,
    j: u32,
    count: usize,
}

fn zeros<K: ChallengeField>(n: usize) -> Result<Vec<K>, Error> {
    let mut v = Vec::new();
    v.try_reserve_exact(n).map_err(|_| Error::Capacity)?;
    v.resize(n, K::from_i64(0));
    Ok(v)
}

/// The Lagrange basis on the nodes `0..n` at `x`.
fn basis<K: ChallengeField>(n: usize, x: K) -> Result<Vec<K>, Error> {
    let mut out = zeros(n)?;
    for (k, w) in out.iter_mut().enumerate() {
        let mut unit = zeros(n)?;
        unit[k] = K::from_i64(1);
        *w = lagrange(&unit, x)?;
    }
    Ok(out)
}

impl<K: ChallengeField + Eq> Zerocheck<'_, K> {
    fn shape(&self) -> Result<Shape, Error> {
        let degree = degree(self.instance).map_err(|_| Error::InvalidZerocheck)?;
        if self.skip > 4
            || u32::from(self.skip) > self.instance.num_vars
            || (degree == 0 && self.skip != 0)
            || self.instance.claimed_sum != K::from_i64(0)
        {
            return Err(Error::InvalidZerocheck);
        }
        let s = 1usize << self.skip;
        Ok(Shape {
            degree,
            s,
            j: self.instance.num_vars - u32::from(self.skip),
            count: degree.saturating_sub(1) * (s - 1),
        })
    }

    /// The A3 descriptor: the A1 instance bytes without the claimed sum, with the skip
    /// byte after version, field, id and `num_vars` (offset 14).
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let shape = self.shape()?;
        let mut bytes = instance_bytes(self.instance, shape.degree)?;
        bytes.truncate(bytes.len() - bytes_of(&self.instance.claimed_sum));
        let mut out = Bytes::with(bytes.len() + 1)?;
        out.put(&bytes[..14]).put(&[self.skip]).put(&bytes[14..]);
        Ok(out.0)
    }

    /// Verify the reduction; the returned claims remain obligations.
    pub fn verify(&self, proof: &Proof<K>, t: &mut Transcript<K>) -> Result<Reduction<K>, Error> {
        let Shape {
            degree,
            s,
            j,
            count,
        } = self.shape()?;
        let i = self.instance;
        let finals = i.inputs.len().checked_mul(s).ok_or(Error::Capacity)?;
        if proof.skip_values.len() != count
            || proof.rounds.len() != j as usize
            || proof.final_values.len() != finals
            || proof.rounds.iter().any(|row| row.len() != degree + 1)
        {
            return Err(Error::ProofShape);
        }
        // The eq weights of the tail coordinates, one run after the descriptor.
        t.absorb(AbsorbLabel::Zero, &self.encode()?)?;
        let mut alpha = zeros::<K>(j as usize)?;
        for a in &mut alpha {
            *a = t.challenge(ChallengeLabel::ZeroWeight)?;
        }
        // The skip polynomial vanishes on its 2^skip Boolean nodes; the proof gives it
        // past them. Without a skip the weight is the single node 1 and the claim 0.
        let (weights, mut claim) = if self.skip == 0 {
            (alloc::vec![K::from_i64(1)], K::from_i64(0))
        } else {
            let values = &proof.skip_values;
            t.absorb(
                AbsorbLabel::ZeroSkip,
                &message(i.id, values.len() as u32, values)?,
            )?;
            let u = t.challenge(ChallengeLabel::Sumcheck)?;
            let mut nodes = zeros(s)?;
            nodes
                .try_reserve_exact(values.len())
                .map_err(|_| Error::Capacity)?;
            nodes.extend_from_slice(values);
            (basis(s, u)?, lagrange(&nodes, u)?)
        };
        let mut point = Vec::new();
        point
            .try_reserve_exact(j as usize)
            .map_err(|_| Error::Capacity)?;
        for ((h, row), a) in (0u32..).zip(&proof.rounds).zip(&alpha) {
            // The eq-weighted round: (1 − α)·g(0) + α·g(1).
            let at_one = if row.len() > 1 { row[1] } else { row[0] };
            if (K::from_i64(1) - *a) * row[0] + *a * at_one != claim {
                return Err(Error::RoundSumMismatch);
            }
            t.absorb(AbsorbLabel::Round, &message(i.id, h, row)?)?;
            let r = t.challenge(ChallengeLabel::Sumcheck)?;
            claim = lagrange(row, r)?;
            point.push(r);
        }
        // Each input's value at the skip challenge, from its slice values.
        let mut values = zeros(i.inputs.len())?;
        for (v, slice) in values.iter_mut().zip(proof.final_values.chunks_exact(s)) {
            for (w, x) in weights.iter().zip(slice) {
                *v = *v + *w * *x;
            }
        }
        if evaluate(i, &values) != claim {
            return Err(Error::FinalEvaluationMismatch);
        }
        let head = message::<K>(i.id, i.inputs.len() as u32, &[])?;
        let width = proof.final_values.first().map_or(0, bytes_of);
        let mut tail = Bytes::with(head.len() + 4 + width * proof.final_values.len())?;
        tail.put(&head).put(&(weights.len() as u32).to_le_bytes());
        for v in &proof.final_values {
            tail.put(v.to_le_bytes().as_ref());
        }
        t.absorb(AbsorbLabel::ZeroFinal, &tail.0)?;
        let skip = usize::from(self.skip);
        let mut claims = Vec::new();
        claims
            .try_reserve_exact(finals)
            .map_err(|_| Error::Capacity)?;
        for (tensor, slice) in i.inputs.iter().zip(proof.final_values.chunks_exact(s)) {
            for (b, value) in slice.iter().enumerate() {
                let mut full = Vec::new();
                full.try_reserve_exact(skip + point.len())
                    .map_err(|_| Error::Capacity)?;
                // The slice index's bits, most significant first, then the tail.
                for bit in (0..skip).rev() {
                    full.push(K::from_i64(((b >> bit) & 1) as i64));
                }
                full.extend_from_slice(&point);
                claims.push(Claim {
                    tensor: *tensor,
                    point: full,
                    value: *value,
                });
            }
        }
        let fd = (bytes_of(&i.claimed_sum) / 4) as u8;
        let record = |m: u32, d: usize| ScRecord {
            id: i.id,
            m,
            degree: d as u8,
            field_degree: fd,
            numerator: u64::from(m) * d as u64,
        };
        Ok(Reduction {
            claims,
            sc: [
                record(j, 1),
                record(u32::from(self.skip > 0), degree * (s - 1)),
                record(j, degree),
            ],
        })
    }

    /// [`Self::verify`], then each slice claim against the verifier's own table of its
    /// input (`2^num_vars` entries).
    pub fn verify_public(
        &self,
        proof: &Proof<K>,
        tables: &[Vec<K>],
        t: &mut Transcript<K>,
    ) -> Result<Reduction<K>, Error> {
        let s = self.shape()?.s;
        let m = self.instance.num_vars;
        let sized = |n: usize| n.is_power_of_two() && n.trailing_zeros() == m;
        if tables.len() != self.instance.inputs.len() || tables.iter().any(|x| !sized(x.len())) {
            return Err(Error::PublicShape);
        }
        let result = self.verify(proof, t)?;
        for (table, claims) in tables.iter().zip(result.claims.chunks_exact(s)) {
            for claim in claims {
                if mle_at(table, &claim.point) != claim.value {
                    return Err(Error::ClaimMismatch);
                }
            }
        }
        Ok(result)
    }
}

//! Canonical sumcheck reduction and public-table consumer, RFC-0006 §§1–2, A1.
#![forbid(unsafe_code)]
#![no_std]
#![cfg_attr(not(test), deny(clippy::float_arithmetic))]
extern crate alloc;
use alloc::vec::Vec;
use stele_hash::{AbsorbLabel, ChallengeField, ChallengeLabel, Transcript};
/// Ordered instance batching, RFC-0006 A2.
pub mod batch;
mod buffers;
/// Virtual-tensor claim batching, RFC-0006 A2.
pub mod claim_batch;
mod dense;
mod instance;
mod small;
/// Eq-factored zerocheck and bounded skip, RFC-0006 A3.
pub mod zerocheck;
pub use buffers::prove_into;
pub use dense::Dense;
pub use instance::{Instance, Term};
pub use small::{Small, SmallTable};

/// Invalid input or failed reduction; abort the entire transcript attempt on error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Invalid degree, factor ordinal, repeated input id or width.
    InvalidInstance,
    /// Empty or inconsistent ordered batch descriptor.
    InvalidBatch,
    /// Invalid row-zero descriptor or plan-selected skip count.
    InvalidZerocheck,
    /// Unsupported small-value prefix or a different cached instance.
    InvalidSmallValue,
    /// Subproof dimensions differ from the verifier-owned instance.
    ProofShape,
    /// Input tables or strategy dimensions differ from the instance.
    PublicShape,
    /// Round values do not sum to the current claim.
    RoundSumMismatch,
    /// P of the final values differs from the last running claim.
    FinalEvaluationMismatch,
    /// A public input evaluation does not discharge its final obligation.
    ClaimMismatch,
    /// Allocation or addressable table size exceeded.
    Capacity,
    /// The production transcript aborted.
    Transcript(stele_hash::Error),
}
impl From<stele_hash::Error> for Error {
    fn from(value: stele_hash::Error) -> Self {
        Self::Transcript(value)
    }
}
fn reserve<T>(v: &mut Vec<T>, additional: usize) -> Result<(), Error> {
    v.try_reserve(additional).map_err(|_| Error::Capacity)
}
fn append(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), Error> {
    reserve(out, bytes.len())?;
    out.extend_from_slice(bytes);
    Ok(())
}
fn put(out: &mut [u8], cursor: &mut usize, bytes: &[u8]) -> Result<(), Error> {
    let end = cursor.checked_add(bytes.len()).ok_or(Error::Capacity)?;
    out.get_mut(*cursor..end)
        .ok_or(Error::Capacity)?
        .copy_from_slice(bytes);
    *cursor = end;
    Ok(())
}
/// Checked size of an A1 round/final payload, RFC-0006 A1/A6.
pub fn message_size<K: ChallengeField>(value_count: usize) -> Result<usize, Error> {
    value_count
        .checked_mul(4 * K::DEGREE)
        .and_then(|n| n.checked_add(12))
        .ok_or(Error::Capacity)
}
/// Write an A1 payload prefix without allocation; short buffers are untouched.
pub fn message_bytes_into<K: ChallengeField>(
    id: u64,
    index: u32,
    values: &[K],
    out: &mut [u8],
) -> Result<usize, Error> {
    let size = message_size::<K>(values.len())?;
    if out.len() < size {
        return Err(Error::Capacity);
    }
    let mut cursor = 0;
    put(out, &mut cursor, &id.to_le_bytes())?;
    put(out, &mut cursor, &index.to_le_bytes())?;
    for value in values {
        put(out, &mut cursor, value.to_le_bytes().as_ref())?;
    }
    Ok(cursor)
}
/// Canonical round/final payload: instance id, round index or input count, values.
pub fn message_bytes<K: ChallengeField>(
    id: u64,
    index: u32,
    values: &[K],
) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    let size = message_size::<K>(values.len())?;
    reserve(&mut out, size)?;
    out.resize(size, 0);
    message_bytes_into(id, index, values, &mut out)?;
    Ok(out)
}
/// Logical subproof; the inference-proof container belongs to RFC-0016.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Proof<K> {
    /// Exactly m rows of degree+1 evaluations at 0..degree.
    pub rounds: Vec<Vec<K>>,
    /// One value for each ordered input tensor; no prover-supplied point.
    pub final_values: Vec<K>,
}
/// Exact SC numerator over symbolic p^field_degree; not a complete profile budget.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScRecord {
    /// Verifier-owned instance identity.
    pub id: u64,
    /// Number of rounds/challenges.
    pub m: u32,
    /// Individual-variable degree derived from the relation.
    pub degree: u8,
    /// Canonical extension degree, 4 or 8.
    pub field_degree: u8,
    /// Exact m*degree.
    pub numerator: u64,
}
/// Conditional reduction result: all claims still require a real consumer.
#[must_use = "every final claim must be discharged by a reduction or opening"]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Reduction<K> {
    /// The single derived point shared by every claim below.
    pub point: Vec<K>,
    /// Ordered (tensor id, value) obligations at point.
    pub claims: Vec<(u64, K)>,
    /// This instance's algebraic loss; excludes FS, PCS and composition.
    pub sc: ScRecord,
}
/// Prover-side strategy only; P, dimensions and challenges remain engine-owned.
pub trait Summand<K: ChallengeField> {
    /// Remaining variables and input count.
    fn shape(&self) -> (u32, usize);
    /// Evaluate the next round polynomial at the engine's nodes 0..degree.
    fn round(&self, instance: &Instance<K>) -> Result<Vec<K>, Error>;
    /// Fix the leading coordinate to the engine's challenge.
    fn fold(&mut self, challenge: K) -> Result<(), Error>;
    /// Evaluations after every coordinate has been fixed.
    fn final_values(&self) -> Result<Vec<K>, Error>;
    /// Fill existing endpoint storage. The default allocates; bounded strategies override it.
    fn round_into(&self, instance: &Instance<K>, out: &mut [K]) -> Result<(), Error> {
        let values = self.round(instance)?;
        if values.len() != out.len() {
            return Err(Error::ProofShape);
        }
        out.copy_from_slice(&values);
        Ok(())
    }
    /// Fill existing final storage. The default allocates; bounded strategies override it.
    fn final_values_into(&self, out: &mut [K]) -> Result<(), Error> {
        let values = self.final_values()?;
        if values.len() != out.len() {
            return Err(Error::ProofShape);
        }
        out.copy_from_slice(&values);
        Ok(())
    }
}
fn interpolation_weight<K: ChallengeField>(count: usize, i: usize, point: K) -> Result<K, Error> {
    let mut basis = K::from_i64(1);
    let mut denominator = K::from_i64(1);
    for j in 0..count {
        if i != j {
            basis = basis * (point - K::from_i64(j as i64));
            denominator = denominator * K::from_i64(i as i64 - j as i64);
        }
    }
    Ok(basis * denominator.inverse().ok_or(Error::InvalidInstance)?)
}
// RFC-0006 A3: up to 61 nodes; factorial denominators must never use machine integers.
fn interpolation_weights<K: ChallengeField>(count: usize, point: K) -> Result<Vec<K>, Error> {
    if !(1..=61).contains(&count) {
        return Err(Error::InvalidInstance);
    }
    let mut weights = Vec::new();
    reserve(&mut weights, count)?;
    for i in 0..count {
        weights.push(interpolation_weight(count, i, point)?);
    }
    Ok(weights)
}
fn interpolate<K: ChallengeField>(values: &[K], point: K) -> Result<K, Error> {
    if !(1..=61).contains(&values.len()) {
        return Err(Error::InvalidInstance);
    }
    values
        .iter()
        .enumerate()
        .try_fold(K::from_i64(0), |sum, (i, value)| {
            Ok(sum + *value * interpolation_weight(values.len(), i, point)?)
        })
}

fn round<K: ChallengeField + Eq>(
    id: u64,
    index: u32,
    values: &[K],
    running: K,
    transcript: &mut Transcript<K>,
) -> Result<(K, K), Error> {
    round_payload(
        values,
        running,
        &message_bytes(id, index, values)?,
        transcript,
    )
}
fn round_payload<K: ChallengeField + Eq>(
    values: &[K],
    running: K,
    payload: &[u8],
    transcript: &mut Transcript<K>,
) -> Result<(K, K), Error> {
    if values[0] + values[if values.len() == 1 { 0 } else { 1 }] != running {
        return Err(Error::RoundSumMismatch);
    }
    transcript.absorb(AbsorbLabel::Round, payload)?;
    let challenge = transcript.challenge(ChallengeLabel::Sumcheck)?;
    Ok((challenge, interpolate(values, challenge)?))
}
fn finish<K: ChallengeField + Eq>(
    i: &Instance<K>,
    final_values: &[K],
    running: K,
    transcript: &mut Transcript<K>,
) -> Result<(), Error> {
    finish_payload(
        i,
        final_values,
        running,
        &message_bytes(i.id, i.inputs.len() as u32, final_values)?,
        transcript,
    )
}
fn finish_payload<K: ChallengeField + Eq>(
    i: &Instance<K>,
    final_values: &[K],
    running: K,
    payload: &[u8],
    transcript: &mut Transcript<K>,
) -> Result<(), Error> {
    if i.evaluate(final_values) != running {
        return Err(Error::FinalEvaluationMismatch);
    }
    transcript.absorb(AbsorbLabel::Final, payload)?;
    Ok(())
}
/// Prove the verifier-owned instance with an arbitrary checked strategy.
pub fn prove<K: ChallengeField + Eq>(
    i: &Instance<K>,
    mut summand: impl Summand<K>,
    transcript: &mut Transcript<K>,
) -> Result<Proof<K>, Error> {
    let degree = i.validate()?;
    if summand.shape() != (i.num_vars, i.inputs.len()) {
        return Err(Error::PublicShape);
    }
    let mut rounds = Vec::new();
    reserve(&mut rounds, i.num_vars as usize)?;
    transcript.absorb(AbsorbLabel::Instance, &i.encode()?)?;
    let mut running = i.claimed_sum;
    for index in 0..i.num_vars {
        let values = summand.round(i)?;
        if values.len() != degree + 1 {
            return Err(Error::ProofShape);
        }
        let (challenge, next) = round(i.id, index, &values, running, transcript)?;
        summand.fold(challenge)?;
        if summand.shape() != (i.num_vars - index - 1, i.inputs.len()) {
            return Err(Error::PublicShape);
        }
        running = next;
        rounds.push(values);
    }
    let final_values = summand.final_values()?;
    if final_values.len() != i.inputs.len() {
        return Err(Error::ProofShape);
    }
    finish(i, &final_values, running, transcript)?;
    Ok(Proof {
        rounds,
        final_values,
    })
}
/// Verify a reduction only; its returned input evaluations remain obligations.
pub fn verify<K: ChallengeField + Eq>(
    i: &Instance<K>,
    proof: &Proof<K>,
    transcript: &mut Transcript<K>,
) -> Result<Reduction<K>, Error> {
    let degree = i.validate()?;
    if proof.rounds.len() != i.num_vars as usize
        || proof.final_values.len() != i.inputs.len()
        || proof.rounds.iter().any(|r| r.len() != degree + 1)
    {
        return Err(Error::ProofShape);
    }
    let mut point = Vec::new();
    reserve(&mut point, i.num_vars as usize)?;
    let mut claims = Vec::new();
    reserve(&mut claims, i.inputs.len())?;
    transcript.absorb(AbsorbLabel::Instance, &i.encode()?)?;
    let mut running = i.claimed_sum;
    for (index, values) in proof.rounds.iter().enumerate() {
        let (challenge, next) = round(i.id, index as u32, values, running, transcript)?;
        point.push(challenge);
        running = next;
    }
    finish(i, &proof.final_values, running, transcript)?;
    claims.extend(
        i.inputs
            .iter()
            .copied()
            .zip(proof.final_values.iter().copied()),
    );
    Ok(Reduction {
        point,
        claims,
        sc: ScRecord {
            id: i.id,
            m: i.num_vars,
            degree: degree as u8,
            field_degree: (K::from_i64(0).to_le_bytes().as_ref().len() / 4) as u8,
            numerator: u64::from(i.num_vars) * degree as u64,
        },
    })
}
/// Close every final obligation using verifier-owned public tables in input order.
/// Private tensors instead need their real reduction/PCS consumers.
pub fn verify_public<K: ChallengeField + Eq>(
    i: &Instance<K>,
    proof: &Proof<K>,
    tables: &[Vec<K>],
    transcript: &mut Transcript<K>,
) -> Result<Reduction<K>, Error> {
    dense::check_tables(i, tables)?;
    let result = verify(i, proof, transcript)?;
    if !tables.is_empty() {
        let weights = stele_poly::eq_table(&result.point).map_err(|_| Error::Capacity)?;
        for (table, (_, expected)) in tables.iter().zip(&result.claims) {
            let actual = table
                .iter()
                .zip(&weights)
                .fold(K::from_i64(0), |s, (x, w)| s + *x * *w);
            if actual != *expected {
                return Err(Error::ClaimMismatch);
            }
        }
    }
    Ok(result)
}

#[cfg(test)]
mod interpolation_tests;

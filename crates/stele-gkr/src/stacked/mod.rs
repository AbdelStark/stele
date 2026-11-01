//! RFC-0006 A4 / formal/stacked-runtime.md: conditional public-source field proofs.
//! Dense preparation, round work, partial storage and public consumption are charged
//! separately by §6; this implementation makes no streaming or inference claim.
mod statement;
mod strategy;
use alloc::vec::Vec;
pub use statement::{Claim, Limits, Order, Prepared, Statement};
use stele_hash::{AbsorbLabel, ChallengeField, HashUsage, Transcript};
use stele_sumcheck::{Proof, Reduction, ScRecord};
pub use strategy::Dense;

/// A checked statement, resource or actual consuming-protocol failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Invalid expected layout, identity, coefficient or polynomial.
    InvalidStacked,
    /// Wrong public original count, dimensions or nonzero padding.
    PublicShape,
    /// Checked size, caller budget or allocation failure.
    Capacity,
    /// Independent A7 evaluation differs from the coefficient final.
    CoefficientMismatch,
    /// An original public table does not consume its final claim.
    ClaimMismatch,
    /// Actual A1 failure, without replacing its rejecting cause.
    Sumcheck(stele_sumcheck::Error),
    /// Actual production-transcript failure.
    Transcript(stele_hash::Error),
}
/// Failed attempt: discard the transcript; this observation authorizes no retry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Failure {
    /// Actual rejecting consumer.
    pub cause: Error,
    /// One cumulative snapshot, including preflight and later failures.
    pub usage: HashUsage,
}
/// Complete public field relation after every original and coefficient is consumed.
/// Construction is private; no profile, integer or privacy admission follows.
/// ```compile_fail,E0423
/// use stele_gkr::stacked::Record;
/// use stele_field::QM31;
/// fn forge(r: stele_sumcheck::Reduction<QM31>) -> Record<QM31> { Record(r) }
/// ```
#[must_use = "retain the conditional SC obligation"]
pub struct Record<K>(Reduction<K>);
impl<K> Record<K> {
    /// Original tensor coordinate order, restored from the actual A1 challenges.
    pub fn point(&self) -> &[K] {
        &self.0.point
    }
    /// All consumed original claims in expected order, including unused originals.
    pub fn claims(&self) -> &[(u64, K)] {
        &self.0.claims
    }
    /// Actual A1 accounting, including zero-degree and zero-round records.
    pub fn sc(&self) -> &ScRecord {
        &self.0.sc
    }
}
fn reserve<T>(values: &mut Vec<T>, count: usize) -> Result<(), Error> {
    values.try_reserve_exact(count).map_err(|_| Error::Capacity)
}
fn zeros<K: ChallengeField>(count: usize) -> Result<Vec<K>, Error> {
    let mut result = Vec::new();
    reserve(&mut result, count)?;
    result.resize(count, K::from_i64(0));
    Ok(result)
}
fn add(a: usize, b: usize) -> Result<usize, Error> {
    a.checked_add(b).ok_or(Error::Capacity)
}
fn mul(a: usize, b: usize) -> Result<usize, Error> {
    a.checked_mul(b).ok_or(Error::Capacity)
}
fn observed<T, K: ChallengeField>(
    result: Result<T, Error>,
    t: &Transcript<K>,
) -> Result<(T, HashUsage), Failure> {
    let usage = t.usage();
    result
        .map(|value| (value, usage))
        .map_err(|cause| Failure { cause, usage })
}
/// Prove with immutable expected public originals, fixing every byte before A1.
pub fn prove_public<K: ChallengeField + Eq>(
    t: &mut Transcript<K>,
    s: &Statement<'_, K>,
    tables: &[&[K]],
    limits: Limits,
) -> Result<Proof<K>, Failure> {
    let result = (|| {
        let prepared = Prepared::new(s, limits)?;
        let sources = prepared.source_bytes(tables)?;
        let mut dense = prepared.strategy(tables)?;
        t.absorb(AbsorbLabel::StackSources, &sources)
            .map_err(Error::Transcript)?;
        t.absorb(AbsorbLabel::Stack, prepared.bytes())
            .map_err(Error::Transcript)?;
        stele_sumcheck::prove(prepared.instance(), &mut dense, t).map_err(Error::Sumcheck)
    })();
    observed(result, t).map(|(proof, _)| proof)
}
/// Verify and consume all public originals; statements and limits are caller-owned.
pub fn verify_public<K: ChallengeField + Eq>(
    t: &mut Transcript<K>,
    s: &Statement<'_, K>,
    proof: &Proof<K>,
    tables: &[&[K]],
    limits: Limits,
) -> Result<(Record<K>, HashUsage), Failure> {
    let result = (|| {
        let prepared = Prepared::new(s, limits)?;
        stele_sumcheck::preflight(prepared.instance(), proof).map_err(Error::Sumcheck)?;
        let sources = prepared.source_bytes(tables)?;
        t.absorb(AbsorbLabel::StackSources, &sources)
            .map_err(Error::Transcript)?;
        t.absorb(AbsorbLabel::Stack, prepared.bytes())
            .map_err(Error::Transcript)?;
        let mut reduction =
            stele_sumcheck::verify(prepared.instance(), proof, t).map_err(Error::Sumcheck)?;
        if s.order == Order::LayerLast {
            reduction.point.rotate_right(usize::from(s.axes[0].bits));
        }
        if prepared
            .coefficient
            .evaluate(&reduction.point)
            .map_err(|_| Error::Capacity)?
            != proof.final_values[tables.len()]
        {
            return Err(Error::CoefficientMismatch);
        }
        reduction.claims.pop();
        if !tables.is_empty() {
            let weights = stele_poly::eq_table(&reduction.point).map_err(|_| Error::Capacity)?;
            for (table, (_, expected)) in tables.iter().zip(&reduction.claims) {
                let actual = table
                    .iter()
                    .zip(&weights)
                    .fold(K::from_i64(0), |sum, (x, w)| sum + *x * *w);
                if actual != *expected {
                    return Err(Error::ClaimMismatch);
                }
            }
        }
        Ok(Record(reduction))
    })();
    observed(result, t)
}

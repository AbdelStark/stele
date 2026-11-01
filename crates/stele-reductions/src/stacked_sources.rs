//! RFC-0006 A4 §§3–6: close restored originals with actual RFC-0010 A9 openings.
//! Adds every source's existing preparation/registration/opening cost to the GKR
//! dense c_sc/T_misc work; source setup and complete peak memory are separate costs.
use alloc::vec::Vec;
use stele_gkr::stacked::{self, Limits, Prepared, Statement};
use stele_hash::{AbsorbLabel, ChallengeField, HashUsage, Transcript};
use stele_pcs::{CodeField, OpeningRecord, PreparedSource, ProofKind, Usage, VerifiedCertificate};
use stele_sumcheck::{Proof, ScRecord};

/// A failed complete stacked attempt, preserving its actual rejecting consumer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Expected sources/openings or the full unpadded layout do not match.
    SourceRoster,
    /// A checked size, caller budget or allocation cannot be satisfied.
    Capacity,
    /// The production source-frame transcript operation failed.
    Transcript(stele_hash::Error),
    /// The actual stacked statement, A1 or independent A7 consumer rejected.
    Stacked(stacked::Error),
    /// The actual source context, wire parser or PCS consumer rejected.
    Pcs(stele_pcs::Error),
}
/// Failed-attempt observations, never permission to continue or retry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Failure {
    /// Actual rejecting cause.
    pub cause: Error,
    /// One cumulative transcript snapshot and all disjoint opening-local work.
    pub usage: Usage,
}
/// Untrusted proof data only; the expected statement and source roster are external.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StackedProof<K> {
    /// Actual A1 rounds/finals, including the uncommitted coefficient final.
    pub sumcheck: Proof<K>,
    /// One complete A9 opening for every original, in expected order.
    pub openings: Vec<Vec<u8>>,
}
/// Complete conditional result; every original has an actual opening record.
/// No profile, integer or privacy admission follows. Construction is private:
/// ```compile_fail
/// use stele_field::QM31;
/// let fake = stele_reductions::StackedSourceRecord::<QM31>::from_digest([0; 32]);
/// ```
/// Only verified certificates own its lifetime, never temporary proof data:
/// ```compile_fail,E0515
/// use stele_field::QM31;
/// use stele_hash::Transcript;
/// use stele_gkr::stacked::{Statement, Limits};
/// use stele_pcs::VerifiedCertificate;
/// use stele_sumcheck::Proof;
/// use stele_reductions::{verify_stacked_sources, StackedSourceRecord};
/// fn escape(c: VerifiedCertificate<QM31>, t: &mut Transcript<QM31>,
///     s: &Statement<'_, QM31>, p: &Proof<QM31>, bytes: &[u8], limits: Limits)
///     -> StackedSourceRecord<'static, QM31> {
///     verify_stacked_sources(t, s, &[&c], p, &[bytes], limits).unwrap().0
/// }
/// ```
#[must_use = "retain actual SC and every original certificate/opening obligation"]
pub struct StackedSourceRecord<'cert, K: ChallengeField> {
    sc: ScRecord,
    openings: Vec<OpeningRecord<'cert, K>>,
}
impl<K: ChallengeField> StackedSourceRecord<'_, K> {
    /// Actual A1 loss, including zero-round and zero-degree records.
    pub fn sc(&self) -> &ScRecord {
        &self.sc
    }
    /// Every original opening, borrowing its actual verified certificate loss.
    pub fn openings(&self) -> &[OpeningRecord<'_, K>] {
        &self.openings
    }
}
fn stacked_error(error: stacked::Error) -> Error {
    if error == stacked::Error::Capacity {
        Error::Capacity
    } else {
        Error::Stacked(error)
    }
}
fn pcs_error(error: stele_pcs::Error) -> Error {
    if error == stele_pcs::Error::Capacity {
        Error::Capacity
    } else {
        Error::Pcs(error)
    }
}
fn reserve<T>(values: &mut Vec<T>, count: usize) -> Result<(), Error> {
    values.try_reserve_exact(count).map_err(|_| Error::Capacity)
}
fn observed<K: ChallengeField, T>(
    result: Result<T, Error>,
    t: &Transcript<K>,
    hashes: u64,
) -> Result<(T, Usage), Failure> {
    let usage = Usage {
        transcript: t.usage(),
        non_transcript: HashUsage {
            hash_evaluations: hashes,
            ..HashUsage::default()
        },
    };
    result
        .map(|value| (value, usage))
        .map_err(|cause| Failure { cause, usage })
}
fn prepare<'a, K: ChallengeField + Eq>(
    s: &'a Statement<'a, K>,
    certificates: &[&VerifiedCertificate<K>],
    mut limits: Limits,
) -> Result<(Prepared<'a, K>, Vec<u8>), Error> {
    if certificates.len() != s.inputs.len() {
        return Err(Error::SourceRoster);
    }
    let count = u32::try_from(certificates.len()).map_err(|_| Error::Capacity)?;
    let source_bytes = certificates
        .len()
        .checked_mul(137)
        .and_then(|n| n.checked_add(14))
        .ok_or(Error::Capacity)?;
    let mut maximum_hashes = 0u64;
    for c in certificates {
        let source = c.record().source();
        // Complete A9 frames and proofs share the caller's descriptor/proof caps.
        // Mode-1 GKR preparation accounts for the remaining StackSources/Stack/A1.
        limits.descriptor_bytes = limits
            .descriptor_bytes
            .checked_sub(source.opening_frame_size().map_err(pcs_error)?)
            .ok_or(Error::Capacity)?;
        limits.proof_bytes = limits
            .proof_bytes
            .checked_sub(source.proof_size(ProofKind::Opening).map_err(pcs_error)?)
            .ok_or(Error::Capacity)?;
        let work = u64::from(source.queries(ProofKind::Opening))
            .checked_mul(1 + source.path_height() as u64)
            .ok_or(Error::Capacity)?;
        maximum_hashes = maximum_hashes.checked_add(work).ok_or(Error::Capacity)?;
    }
    let prepared = Prepared::for_certified_sources(s, limits).map_err(stacked_error)?;
    if s.axes.iter().any(|a| a.real != 1u64 << a.bits) {
        return Err(Error::SourceRoster);
    }
    for (c, id) in certificates.iter().zip(s.inputs) {
        let source = c.record().source();
        if source.descriptor().id != *id
            || source.rows().trailing_zeros() + source.columns().trailing_zeros()
                != prepared.instance().num_vars
        {
            return Err(Error::SourceRoster);
        }
    }
    let mut bundle = Vec::new();
    reserve(&mut bundle, source_bytes)?;
    bundle.extend_from_slice(&[1, 1]);
    bundle.extend_from_slice(&s.id.to_le_bytes());
    bundle.extend_from_slice(&count.to_le_bytes());
    for c in certificates {
        bundle.extend_from_slice(&c.record().source().bytes());
        bundle.extend_from_slice(&c.record().id());
    }
    Ok((prepared, bundle))
}
/// Bind expected verified sources, run Stack/A1/A7, then consume every restored
/// original through A9. No original tables or replacement points are accepted.
/// Descriptor/proof limits include all opening frames/wires; prepared/partial/axis
/// limits retain their GKR meanings. A9 keeps its own checked allocation paths.
pub fn verify_stacked_sources<'cert, K: ChallengeField + CodeField + Eq>(
    t: &mut Transcript<K>,
    s: &Statement<'_, K>,
    certificates: &[&'cert VerifiedCertificate<K>],
    proof: &Proof<K>,
    opening_proofs: &[&[u8]],
    limits: Limits,
) -> Result<(StackedSourceRecord<'cert, K>, Usage), Failure>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let mut hashes = 0u64;
    let result = (|| {
        if opening_proofs.len() != certificates.len() {
            return Err(Error::SourceRoster);
        }
        let (prepared, bundle) = prepare(s, certificates, limits)?;
        stele_sumcheck::preflight(prepared.instance(), proof)
            .map_err(|e| Error::Stacked(stacked::Error::Sumcheck(e)))?;
        for (c, bytes) in certificates.iter().zip(opening_proofs) {
            c.record()
                .source()
                .parse(ProofKind::Opening, bytes)
                .map_err(pcs_error)?;
        }
        let mut openings = Vec::new();
        reserve(&mut openings, certificates.len())?;
        t.absorb(AbsorbLabel::StackSources, &bundle)
            .map_err(Error::Transcript)?;
        drop(bundle);
        let (reduction, _) = prepared
            .verify_reduction(t, proof)
            .map_err(|f| stacked_error(f.cause))?;
        for (((id, value), c), bytes) in reduction
            .claims
            .iter()
            .zip(certificates)
            .zip(opening_proofs)
        {
            let result = stele_pcs::verify_point(t, c, *id, &reduction.point, *value, bytes);
            let usage = match &result {
                Ok((_, usage)) => usage,
                Err(f) => &f.usage,
            };
            // prepare checked the maximum sum, including every failing prefix.
            hashes += usage.non_transcript.hash_evaluations;
            openings.push(result.map_err(|f| pcs_error(f.cause))?.0);
        }
        Ok(StackedSourceRecord {
            sc: reduction.sc,
            openings,
        })
    })();
    observed(result, t, hashes)
}
/// Produce Stack/A1 and every real A9 opening from matching immutable source
/// material and the challenges captured during the actual A1 folds. No verifier
/// replay, replacement point or second full lifted witness is used.
pub fn prove_stacked_sources<K: ChallengeField + CodeField + Eq>(
    t: &mut Transcript<K>,
    s: &Statement<'_, K>,
    sources: &[&PreparedSource<'_, K>],
    certificates: &[&VerifiedCertificate<K>],
    limits: Limits,
) -> Result<(StackedProof<K>, Usage), Failure> {
    let mut hashes = 0u64;
    let result = (|| {
        if sources.len() != certificates.len() {
            return Err(Error::SourceRoster);
        }
        for (source, c) in sources.iter().zip(certificates) {
            if source.source().bytes() != c.record().source().bytes() {
                return Err(Error::Pcs(stele_pcs::Error::CertificateContext));
            }
        }
        let (prepared, bundle) = prepare(s, certificates, limits)?;
        let mut tables = Vec::new();
        reserve(&mut tables, sources.len())?;
        tables.extend(sources.iter().map(|source| source.message()));
        let mut dense = prepared.strategy_m31(&tables).map_err(stacked_error)?;
        let mut openings = Vec::new();
        reserve(&mut openings, sources.len())?;
        t.absorb(AbsorbLabel::StackSources, &bundle)
            .map_err(Error::Transcript)?;
        drop(bundle);
        let sumcheck = dense.prove(t).map_err(|f| stacked_error(f.cause))?;
        let point = dense.into_point().map_err(stacked_error)?;
        drop(tables);
        drop(prepared);
        for (((source, c), id), value) in sources
            .iter()
            .zip(certificates)
            .zip(s.inputs)
            .zip(&sumcheck.final_values)
        {
            let result = source.opening_point(t, c, *id, &point, *value);
            let usage = match &result {
                Ok((_, usage)) => usage,
                Err(f) => &f.usage,
            };
            hashes += usage.non_transcript.hash_evaluations;
            openings.push(result.map_err(|f| pcs_error(f.cause))?.0);
        }
        Ok(StackedProof { sumcheck, openings })
    })();
    observed(result, t, hashes)
}

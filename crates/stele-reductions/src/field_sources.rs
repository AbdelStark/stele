//! RFC-0010 A9 §§5,9: close every actual A1 original and retain its conditional loss.
use alloc::vec::Vec;
use stele_hash::{AbsorbLabel, ChallengeField, HashUsage, Transcript};
use stele_pcs::{CodeField, OpeningRecord, ProofKind, Usage, VerifiedCertificate};
use stele_sumcheck::{Instance, Proof, ScRecord};

/// Failed closure; abort the entire attempt without a conditional proof record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Expected sources/openings differ from the exact ordered original roster.
    SourceRoster,
    /// Size, allocation or local hash-work capacity cannot be represented.
    Capacity,
    /// Binding the bundle failed in the production transcript.
    Transcript(stele_hash::Error),
    /// The actual A1 preflight or verifier rejected.
    Sumcheck(stele_sumcheck::Error),
    /// The actual PCS preflight or terminal opening rejected.
    Pcs(stele_pcs::Error),
}
/// Failed-attempt observations only; these authorize no continuation or retry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Failure {
    /// Original rejecting consumer, with its cause preserved.
    pub cause: Error,
    /// One cumulative transcript snapshot and this adapter's actual Merkle work.
    pub usage: Usage,
}
/// Complete conditional A1 result, borrowing the original certificate losses.
/// It grants no profile admission and cannot outlive those certificates:
/// ```compile_fail,E0515
/// use stele_field::QM31;
/// use stele_hash::Transcript;
/// use stele_pcs::VerifiedCertificate;
/// use stele_sumcheck::{Instance, Proof};
/// use stele_reductions::{verify_field_sources, FieldSourceRecord};
/// fn escape(c: VerifiedCertificate<QM31>, t: &mut Transcript<QM31>,
///           i: &Instance<QM31>, p: &Proof<QM31>, bytes: &[u8]) -> FieldSourceRecord<'static, QM31> {
///     verify_field_sources(t, i, &[&c], p, &[bytes]).unwrap().0
/// }
/// ```
#[must_use = "retain A1 and all original certificate/opening obligations"]
pub struct FieldSourceRecord<'cert, K: ChallengeField> {
    sc: ScRecord,
    openings: Vec<OpeningRecord<'cert, K>>,
}
impl<'cert, K: ChallengeField> FieldSourceRecord<'cert, K> {
    /// Actual A1 SC numerator, not a complete profile sum.
    pub fn sc(&self) -> &ScRecord {
        &self.sc
    }
    /// Actual openings in original input order, including unused originals.
    pub fn openings(&self) -> &[OpeningRecord<'cert, K>] {
        &self.openings
    }
}
/// Bind the exact expected roster, run A1, and consume all of its returned claims.
/// No original tables, replacement points or authentication callbacks are accepted.
/// Every failure aborts the enclosing attempt; discard the transcript after error.
pub fn verify_field_sources<'cert, K: ChallengeField + CodeField + Eq>(
    t: &mut Transcript<K>,
    instance: &Instance<K>,
    certificates: &[&'cert VerifiedCertificate<K>],
    proof: &Proof<K>,
    opening_proofs: &[&[u8]],
) -> Result<(FieldSourceRecord<'cert, K>, Usage), Failure>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let mut hashes = 0u64;
    let result = (|| {
        stele_sumcheck::preflight(instance, proof).map_err(Error::Sumcheck)?;
        if certificates.len() != instance.inputs.len() || opening_proofs.len() != certificates.len()
        {
            return Err(Error::SourceRoster);
        }
        let count = u32::try_from(certificates.len()).map_err(|_| Error::Capacity)?;
        let size = certificates
            .len()
            .checked_mul(105 + 32)
            .and_then(|n| n.checked_add(8 + 4))
            .ok_or(Error::Capacity)?;
        let mut maximum_hashes = 0u64;
        for ((certificate, id), bytes) in certificates
            .iter()
            .zip(&instance.inputs)
            .zip(opening_proofs)
        {
            let source = certificate.record().source();
            if source.descriptor().id != *id
                || source.rows().trailing_zeros() + source.columns().trailing_zeros()
                    != instance.num_vars
            {
                return Err(Error::SourceRoster);
            }
            source.opening_frame_size().map_err(Error::Pcs)?;
            source
                .parse(ProofKind::Opening, bytes)
                .map_err(Error::Pcs)?;
            let work = u64::from(source.queries(ProofKind::Opening))
                .checked_mul(1 + source.path_height() as u64)
                .ok_or(Error::Capacity)?;
            maximum_hashes = maximum_hashes.checked_add(work).ok_or(Error::Capacity)?;
        }
        let mut bundle = Vec::new();
        bundle
            .try_reserve_exact(size)
            .map_err(|_| Error::Capacity)?;
        let mut openings = Vec::new();
        openings
            .try_reserve_exact(certificates.len())
            .map_err(|_| Error::Capacity)?;
        bundle.extend_from_slice(&instance.id.to_le_bytes());
        bundle.extend_from_slice(&count.to_le_bytes());
        for certificate in certificates {
            bundle.extend_from_slice(&certificate.record().source().bytes());
            bundle.extend_from_slice(&certificate.record().id());
        }
        t.absorb(AbsorbLabel::FieldSources, &bundle)
            .map_err(Error::Transcript)?;
        drop(bundle);
        let reduction = stele_sumcheck::verify(instance, proof, t).map_err(Error::Sumcheck)?;
        for (((id, value), certificate), bytes) in reduction
            .claims
            .iter()
            .zip(certificates)
            .zip(opening_proofs)
        {
            let result =
                stele_pcs::verify_point(t, certificate, *id, &reduction.point, *value, bytes);
            let usage = match &result {
                Ok((_, usage)) => usage,
                Err(failure) => &failure.usage,
            };
            // A9 §9: openings perform only ordinary Merkle H outside the transcript.
            // The complete roster's checked maximum above bounds every prefix, even on failure.
            hashes += usage.non_transcript.hash_evaluations;
            openings.push(result.map_err(|failure| Error::Pcs(failure.cause))?.0);
        }
        Ok(FieldSourceRecord {
            sc: reduction.sc,
            openings,
        })
    })();
    let usage = Usage {
        transcript: t.usage(),
        non_transcript: HashUsage {
            hash_evaluations: hashes,
            ..HashUsage::default()
        },
    };
    result
        .map(|record| (record, usage))
        .map_err(|cause| Failure { cause, usage })
}

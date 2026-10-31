//! RFC-0010 A9 §3/§9: complete registration verification and conditional records.
use crate::{Error, Parameters, ProofKind, Source, Wire};
use alloc::vec::Vec;
use stele_code::{CodeField, Encoder};
use stele_field::{Serialize, M31};
use stele_hash::{
    certificate_id, merkle, AbsorbLabel, ChallengeField, ChallengeLabel, HashUsage, Transcript,
};

/// Separate local observations; not adversarial caps or evaluated soundness losses.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Usage {
    /// Cumulative transcript work, including rejected attempts; never sum shared snapshots.
    pub transcript: HashUsage,
    /// Only this call's Merkle and completed-proof ID hashing.
    pub non_transcript: HashUsage,
}
/// Abort with observations only; no result record or handle is returned.
/// Discard the enclosing attempt, including any caller-owned transcript.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Failure {
    /// Original failure cause.
    pub cause: Error,
    /// Work completed before rejection; permits no retry or continuation.
    pub usage: Usage,
}
/// Immutable conditional certificate obligation, retaining source and digest identity.
pub struct CertificateRecord<K: ChallengeField> {
    source: Source<K>,
    id: merkle::Digest,
}
impl<K: ChallengeField> CertificateRecord<K> {
    /// Full expected source, including fixed policy and selected field.
    pub fn source(&self) -> &Source<K> {
        &self.source
    }
    /// Exact completed-proof identity; never a constructor or standalone receipt.
    pub fn id(&self) -> merkle::Digest {
        self.id
    }
    /// Verifier-derived Circle geometry and finite query counts.
    pub fn parameters(&self) -> Parameters {
        self.source.parameters()
    }
    /// Number of independent row-weight coordinates.
    pub fn ell(&self) -> u8 {
        self.source.rows().trailing_zeros() as u8
    }
    /// Selected extension degree.
    pub fn degree(&self) -> u8 {
        K::DEGREE as u8
    }
    /// Certificate kind; reusing this record retains its original obligation.
    pub fn kind(&self) -> ProofKind {
        ProofKind::Certificate
    }
}
/// Created only after full verification, including final absorption and ID hashing.
/// ```compile_fail
/// use stele_field::QM31;
/// let fake = stele_pcs::VerifiedCertificate::<QM31>::from_digest([0; 32]);
/// ```
pub struct VerifiedCertificate<K: ChallengeField> {
    record: CertificateRecord<K>,
}
impl<K: ChallengeField> VerifiedCertificate<K> {
    /// Original certificate obligation; this alone accepts no functional claim.
    pub fn record(&self) -> &CertificateRecord<K> {
        &self.record
    }
}

const PUBLIC: &[u8] = b"stele/v0.1/pcs-certificate/public";
fn transcript<K: ChallengeField>(source: &Source<K>) -> Result<Transcript<K>, Error> {
    let mut public = [0; PUBLIC.len() + 105];
    public[..PUBLIC.len()].copy_from_slice(PUBLIC);
    public[PUBLIC.len()..].copy_from_slice(&source.bytes());
    Transcript::new(&public).map_err(Error::Transcript)
}
/// Reparse and fully verify imported bytes against the caller's expected source.
/// Every error aborts this attempt; observations never authorize continuation.
pub fn verify_certificate<K: ChallengeField + CodeField>(
    source: Source<K>,
    proof: &[u8],
) -> Result<(VerifiedCertificate<K>, Usage), Failure>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let mut usage = Usage::default();
    let result = (|| {
        let wire = source.parse(ProofKind::Certificate, proof)?;
        let mut t = transcript(&source)?;
        let result = verify_inner(&source, proof, &wire, &mut t, &mut usage.non_transcript);
        // A9 §9: no post-construction `?` may bypass this failure observation.
        usage.transcript = t.usage();
        result.map(|id| VerifiedCertificate {
            record: CertificateRecord { source, id },
        })
    })();
    result
        .map(|handle| (handle, usage))
        .map_err(|cause| Failure { cause, usage })
}
fn verify_inner<K: ChallengeField + CodeField>(
    source: &Source<K>,
    proof: &[u8],
    wire: &Wire<'_>,
    t: &mut Transcript<K>,
    usage: &mut HashUsage,
) -> Result<merkle::Digest, Error>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let ell = source.rows().trailing_zeros() as usize;
    let mut point = [K::from_i64(0); 30];
    for coordinate in &mut point[..ell] {
        *coordinate = t
            .challenge(ChallengeLabel::CertificateWeight)
            .map_err(Error::Transcript)?;
    }
    let weights = stele_poly::eq_table(&point[..ell]).map_err(|_| Error::Capacity)?;
    let mut row = Vec::new();
    row.try_reserve_exact(source.columns())
        .map_err(|_| Error::Capacity)?;
    for bytes in wire
        .row_bytes()
        .chunks_exact(4 * usize::from(<K as CodeField>::DEGREE))
    {
        let encoded = K::Bytes::try_from(bytes).map_err(|_| Error::NoncanonicalField)?;
        row.push(K::from_le_bytes(encoded).ok_or(Error::NoncanonicalField)?);
    }
    t.absorb(AbsorbLabel::CertificateRow, wire.row_bytes())
        .map_err(Error::Transcript)?;
    let encoded = Encoder::from_code_id(&source.code().code_id())
        .map_err(Error::Encoder)?
        .encode_measured(&row)
        .map_err(Error::Encoder)?;
    for response in wire.responses() {
        let index = t
            .certificate_column(source.descriptor().count)
            .map_err(Error::Transcript)?;
        let mut siblings = [[0; 32]; 30];
        for (out, bytes) in siblings.iter_mut().zip(response.siblings.chunks_exact(32)) {
            out.copy_from_slice(bytes);
        }
        merkle::verify_with_usage(
            source.descriptor(),
            &source.root(),
            index,
            merkle::Opening {
                payload: response.payload,
                siblings: &siblings[..source.path_height()],
            },
            usage,
        )
        .map_err(Error::Merkle)?;
        let mut value = K::from_i64(0);
        for (weight, bytes) in weights.iter().zip(response.payload.chunks_exact(4)) {
            let limb = M31::from_le_bytes(bytes.try_into().map_err(|_| Error::NoncanonicalField)?)
                .ok_or(Error::NoncanonicalField)?;
            value = value + *weight * K::from_i64(i64::from(limb.as_u32()));
        }
        if value.to_le_bytes().as_ref() != encoded.values[index as usize].to_le_bytes().as_ref() {
            return Err(Error::ColumnMismatch);
        }
    }
    t.absorb(AbsorbLabel::CertificateColumns, wire.response_bytes())
        .map_err(Error::Transcript)?;
    certificate_id(&source.bytes(), proof, usage).map_err(Error::Transcript)
}

#[cfg(test)]
#[path = "certificate_tests.rs"]
mod tests;

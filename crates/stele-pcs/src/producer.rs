//! RFC-0010 A9 §3: native certificate bytes; production grants no verification credit.
use crate::{Error, PreparedSource, ProofKind, Source};
use alloc::vec::Vec;
use stele_hash::{AbsorbLabel, ChallengeField, ChallengeLabel, HashUsage, Transcript};

/// Aborted production and its observed transcript work; no proof or continuation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CertificateFailure {
    /// Original cause of the failed attempt.
    pub cause: Error,
    /// Local hash work, including discarded draws; not an adversarial query cap.
    pub usage: HashUsage,
}
impl<K: ChallengeField> PreparedSource<'_, K> {
    /// Produce the complete canonical certificate, including every repeated response.
    /// This returns unverified bytes and local transcript work, with no ID or handle.
    pub fn certificate(&self) -> Result<(Vec<u8>, HashUsage), CertificateFailure> {
        let mut usage = HashUsage::default();
        let result = (|| {
            self.source().proof_size(ProofKind::Certificate)?;
            let mut t = transcript(self.source())?;
            let result = produce_inner(self, &mut t);
            usage = t.usage(); // Snapshot on every post-construction exit, including failure.
            result
        })();
        result
            .map(|proof| (proof, usage))
            .map_err(|cause| CertificateFailure { cause, usage })
    }
}
const PUBLIC: &[u8] = b"stele/v0.1/pcs-certificate/public";
fn transcript<K: ChallengeField>(source: &Source<K>) -> Result<Transcript<K>, Error> {
    let mut public = [0; PUBLIC.len() + 105];
    public[..PUBLIC.len()].copy_from_slice(PUBLIC);
    public[PUBLIC.len()..].copy_from_slice(&source.bytes());
    Transcript::new(&public).map_err(Error::Transcript)
}
fn produce_inner<K: ChallengeField>(
    prepared: &PreparedSource<'_, K>,
    t: &mut Transcript<K>,
) -> Result<Vec<u8>, Error> {
    let source = prepared.source();
    let mut proof = Vec::new();
    proof
        .try_reserve_exact(source.proof_size(ProofKind::Certificate)?)
        .map_err(|_| Error::Capacity)?;
    let ell = source.rows().trailing_zeros() as usize;
    let mut point = [K::from_i64(0); 30];
    for coordinate in &mut point[..ell] {
        *coordinate = t
            .challenge(ChallengeLabel::CertificateWeight)
            .map_err(Error::Transcript)?;
    }
    let weights = stele_poly::eq_table(&point[..ell]).map_err(|_| Error::Capacity)?;
    proof.push(1);
    for column in 0..source.columns() {
        let mut value = K::from_i64(0);
        for (row, weight) in weights.iter().enumerate() {
            // PreparedSource checked R*C and immutably borrows exactly that message.
            let limb = prepared.message()[row * source.columns() + column];
            value = value + *weight * K::from_i64(i64::from(limb.as_u32()));
        }
        proof.extend_from_slice(value.to_le_bytes().as_ref());
    }
    drop(weights);
    t.absorb(AbsorbLabel::CertificateRow, &proof[1..])
        .map_err(Error::Transcript)?;
    let start = proof.len();
    for _ in 0..source.queries(ProofKind::Certificate) {
        let index = t
            .certificate_column(source.descriptor().count)
            .map_err(Error::Transcript)?;
        let response = prepared.response(index)?;
        proof.extend_from_slice(response.payload);
        for sibling in response.siblings {
            proof.extend_from_slice(&sibling);
        }
    }
    t.absorb(AbsorbLabel::CertificateColumns, &proof[start..])
        .map_err(Error::Transcript)?;
    Ok(proof)
}
#[cfg(test)]
#[path = "producer_tests.rs"]
mod tests;

//! RFC-0010 A9 §§4,9: general functionals against a verified conditional certificate.
use crate::{
    CertificateRecord, Error, Failure, PreparedSource, ProofKind, Source, Usage,
    VerifiedCertificate,
};
use alloc::vec::Vec;
use stele_code::{CodeField, Encoder};
use stele_field::{Serialize, M31};
use stele_hash::{merkle, AbsorbLabel, ChallengeField, HashUsage, Transcript};

/// Caller-owned expected coefficients and value; this descriptor carries no authority.
#[derive(Clone, Copy)]
pub struct Functional<'a, K: ChallengeField> {
    /// Opening identity within the caller's transcript segment.
    pub id: u64,
    /// Complete row weights in canonical order.
    pub a: &'a [K],
    /// Complete message-column weights in canonical order.
    pub b: &'a [K],
    /// Expected scalar functional.
    pub value: K,
}
impl<K: ChallengeField> Functional<'_, K> {
    fn frame_len(&self, source: &Source<K>) -> Result<usize, Error> {
        if self.a.len() != source.rows() || self.b.len() != source.columns() {
            return Err(Error::FunctionalShape);
        }
        self.a
            .len()
            .checked_add(self.b.len())
            .and_then(|n| n.checked_add(1))
            .and_then(|n| n.checked_mul(4 * K::DEGREE))
            .and_then(|n| n.checked_add(8 + 105 + 32))
            .ok_or(Error::Capacity)
    }
    fn frame(&self, certificate: &CertificateRecord<K>, size: usize) -> Result<Vec<u8>, Error> {
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(size).map_err(|_| Error::Capacity)?;
        bytes.extend_from_slice(&self.id.to_le_bytes());
        bytes.extend_from_slice(&certificate.source().bytes());
        bytes.extend_from_slice(&certificate.id());
        for value in self
            .a
            .iter()
            .chain(self.b)
            .chain(core::iter::once(&self.value))
        {
            bytes.extend_from_slice(value.to_le_bytes().as_ref());
        }
        Ok(bytes)
    }
}
/// One conditional opening obligation, borrowing the original certificate loss.
/// It cannot outlive that certificate or be imported from a digest:
/// ```compile_fail
/// use stele_field::QM31;
/// let fake = stele_pcs::OpeningRecord::<QM31>::from_digest([0; 32]);
/// ```
/// ```compile_fail,E0515
/// use stele_field::QM31;
/// use stele_hash::Transcript;
/// use stele_pcs::{verify_opening, Functional, OpeningRecord, VerifiedCertificate};
/// fn escape(certificate: VerifiedCertificate<QM31>, t: &mut Transcript<QM31>,
///           functional: Functional<'_, QM31>, proof: &[u8]) -> OpeningRecord<'static, QM31> {
///     verify_opening(t, &certificate, functional, proof).unwrap().0
/// }
/// ```
pub struct OpeningRecord<'cert, K: ChallengeField> {
    certificate: &'cert CertificateRecord<K>,
    id: u64,
    queries: u16,
}
impl<K: ChallengeField> OpeningRecord<'_, K> {
    /// Original certificate obligation; reuse never replaces it with zero loss.
    pub fn certificate(&self) -> &CertificateRecord<K> {
        self.certificate
    }
    /// Verifier-owned opening identity.
    pub fn id(&self) -> u64 {
        self.id
    }
    /// Fixed q_o derived from the expected source.
    pub fn queries(&self) -> u16 {
        self.queries
    }
    /// Opening operation, distinct from certificate registration.
    pub fn kind(&self) -> ProofKind {
        ProofKind::Opening
    }
}
impl<K: ChallengeField> PreparedSource<'_, K> {
    /// Produce full ordered opening bytes. Any error aborts the caller's entire attempt.
    /// Transcript usage is cumulative; do not add snapshots from shared transcripts.
    pub fn opening(
        &self,
        t: &mut Transcript<K>,
        certificate: &VerifiedCertificate<K>,
        functional: Functional<'_, K>,
    ) -> Result<(Vec<u8>, Usage), Failure> {
        let result = (|| {
            let record = certificate.record();
            let source = record.source();
            if self.source().bytes() != source.bytes() {
                return Err(Error::CertificateContext);
            }
            let size = functional.frame_len(source)?;
            let proof_size = source.proof_size(ProofKind::Opening)?;
            let frame = functional.frame(record, size)?;
            let mut proof = Vec::new();
            proof
                .try_reserve_exact(proof_size)
                .map_err(|_| Error::Capacity)?;
            t.absorb(AbsorbLabel::Opening, &frame)
                .map_err(Error::Transcript)?;
            drop(frame);
            proof.push(1);
            let mut scalar = K::from_i64(0);
            for (column, b) in functional.b.iter().enumerate() {
                let mut value = K::from_i64(0);
                for (row, a) in functional.a.iter().enumerate() {
                    let limb = self.message()[row * source.columns() + column];
                    value = value + *a * K::from_i64(i64::from(limb.as_u32()));
                }
                scalar = scalar + value * *b;
                proof.extend_from_slice(value.to_le_bytes().as_ref());
            }
            t.absorb(AbsorbLabel::OpeningRow, &proof[1..])
                .map_err(Error::Transcript)?;
            if scalar.to_le_bytes().as_ref() != functional.value.to_le_bytes().as_ref() {
                return Err(Error::ValueMismatch);
            }
            let start = proof.len();
            for _ in 0..source.queries(ProofKind::Opening) {
                let index = t
                    .opening_column(source.descriptor().count)
                    .map_err(Error::Transcript)?;
                let response = self.response(index)?;
                proof.extend_from_slice(response.payload);
                for sibling in response.siblings {
                    proof.extend_from_slice(&sibling);
                }
            }
            t.absorb(AbsorbLabel::OpeningColumns, &proof[start..])
                .map_err(Error::Transcript)?;
            Ok(proof)
        })();
        let usage = Usage {
            transcript: t.usage(),
            non_transcript: HashUsage::default(),
        };
        result
            .map(|proof| (proof, usage))
            .map_err(|cause| Failure { cause, usage })
    }
}
/// Verify complete bytes against the caller-selected certificate and functional.
/// Every error aborts the enclosing attempt; the borrowed transcript must be discarded.
/// Usage contains a cumulative transcript snapshot and only this call's Merkle work.
pub fn verify_opening<'cert, K: ChallengeField + CodeField>(
    t: &mut Transcript<K>,
    certificate: &'cert VerifiedCertificate<K>,
    functional: Functional<'_, K>,
    proof: &[u8],
) -> Result<(OpeningRecord<'cert, K>, Usage), Failure>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let mut hashes = HashUsage::default();
    let result = (|| {
        let record = certificate.record();
        let source = record.source();
        let size = functional.frame_len(source)?;
        let wire = source.parse(ProofKind::Opening, proof)?;
        let frame = functional.frame(record, size)?;
        t.absorb(AbsorbLabel::Opening, &frame)
            .map_err(Error::Transcript)?;
        drop(frame);
        t.absorb(AbsorbLabel::OpeningRow, wire.row_bytes())
            .map_err(Error::Transcript)?;
        let mut row = Vec::new();
        row.try_reserve_exact(source.columns())
            .map_err(|_| Error::Capacity)?;
        let mut scalar = K::from_i64(0);
        for (bytes, b) in wire
            .row_bytes()
            .chunks_exact(4 * usize::from(<K as CodeField>::DEGREE))
            .zip(functional.b)
        {
            let value =
                K::from_le_bytes(K::Bytes::try_from(bytes).map_err(|_| Error::NoncanonicalField)?)
                    .ok_or(Error::NoncanonicalField)?;
            scalar = scalar + value * *b;
            row.push(value);
        }
        if scalar.to_le_bytes().as_ref() != functional.value.to_le_bytes().as_ref() {
            return Err(Error::ValueMismatch);
        }
        let encoded = Encoder::from_code_id(&source.code().code_id())
            .map_err(Error::Encoder)?
            .encode_measured(&row)
            .map_err(Error::Encoder)?;
        drop(row);
        for response in wire.responses() {
            let index = t
                .opening_column(source.descriptor().count)
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
                &mut hashes,
            )
            .map_err(Error::Merkle)?;
            let mut value = K::from_i64(0);
            for (a, bytes) in functional.a.iter().zip(response.payload.chunks_exact(4)) {
                let limb =
                    M31::from_le_bytes(bytes.try_into().map_err(|_| Error::NoncanonicalField)?)
                        .ok_or(Error::NoncanonicalField)?;
                value = value + *a * K::from_i64(i64::from(limb.as_u32()));
            }
            if value.to_le_bytes().as_ref() != encoded.values[index as usize].to_le_bytes().as_ref()
            {
                return Err(Error::ColumnMismatch);
            }
        }
        t.absorb(AbsorbLabel::OpeningColumns, wire.response_bytes())
            .map_err(Error::Transcript)?;
        Ok(OpeningRecord {
            certificate: record,
            id: functional.id,
            queries: source.queries(ProofKind::Opening),
        })
    })();
    let usage = Usage {
        transcript: t.usage(),
        non_transcript: hashes,
    };
    result
        .map(|record| (record, usage))
        .map_err(|cause| Failure { cause, usage })
}

//! RFC-0010 A9 §§4,9 and A10: functional openings and immutable retained rows.
use crate::{
    CertificateRecord, Error, Failure, PreparedSource, ProofKind, Source, Usage,
    VerifiedCertificate,
};
use alloc::vec::Vec;
use stele_code::{CodeField, Encoder};
use stele_field::{Serialize, M31};
use stele_hash::{merkle, AbsorbLabel, ChallengeField, HashUsage, Transcript};

fn point_weights<K: ChallengeField>(
    point: &[K],
    row_bits: usize,
) -> Result<(Vec<K>, Vec<K>), Error> {
    let a = stele_poly::eq_table(&point[..row_bits]).map_err(|_| Error::Capacity)?;
    let b = stele_poly::eq_table(&point[row_bits..]).map_err(|_| Error::Capacity)?;
    Ok((a, b))
}

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
        source.opening_frame_size()
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
/// Derive MSB-first point weights and invoke the actual functional verifier (A9 §4).
/// Any error aborts the enclosing attempt; no caller-supplied coefficients intervene.
pub fn verify_point<'cert, K: ChallengeField + CodeField>(
    t: &mut Transcript<K>,
    certificate: &'cert VerifiedCertificate<K>,
    id: u64,
    point: &[K],
    value: K,
    proof: &[u8],
) -> Result<(OpeningRecord<'cert, K>, Usage), Failure>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let weights = (|| {
        let source = certificate.record().source();
        let ell = source.rows().trailing_zeros() as usize;
        let m = source.columns().trailing_zeros() as usize;
        if point.len() != ell + m {
            return Err(Error::FunctionalShape);
        }
        source.opening_frame_size()?;
        source.parse(ProofKind::Opening, proof)?;
        point_weights(point, ell)
    })();
    let (a, b) = weights.map_err(|cause| Failure {
        cause,
        usage: Usage {
            transcript: t.usage(),
            non_transcript: HashUsage::default(),
        },
    })?;
    verify_opening(
        t,
        certificate,
        Functional {
            id,
            a: &a,
            b: &b,
            value,
        },
        proof,
    )
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

/// Observed row construction only; excludes borrowed source/weights and opening storage.
/// Capacity is the actual retained Vec capacity, not allocator metadata or process RSS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetainedRowWork {
    /// Complete row-major traversals of the original message.
    pub source_visits: usize,
    /// Original M31 elements read, including zero-weight rows.
    pub source_elements: usize,
    /// Owned K-valued row capacity in bytes.
    pub retained_bytes: usize,
}

/// RFC-0010 A10: u = a^T M, borrowing the exact prepared source and row weights.
/// Construction is the only original-message visit; openings borrow this immutable u.
/// There is no constructor for caller-supplied row values:
/// ```compile_fail,E0599
/// use stele_field::QM31;
/// let fake = stele_pcs::RetainedRow::<QM31>::from_values(vec![]);
/// ```
/// The weights and prepared source remain borrowed while the row is used:
/// ```compile_fail,E0502
/// use stele_field::{QM31, Field};
/// use stele_pcs::{PreparedSource, RetainedRow};
/// fn mutate(source: &PreparedSource<'_, QM31>, mut weights: Vec<QM31>) {
///     let row = RetainedRow::new(source, &weights).unwrap();
///     weights[0] = QM31::from_i64(0);
///     let _ = row.values();
/// }
/// ```
/// ```compile_fail,E0505
/// use stele_field::QM31;
/// use stele_pcs::{PreparedSource, RetainedRow};
/// fn release(source: PreparedSource<'_, QM31>, weights: &[QM31]) {
///     let row = RetainedRow::new(&source, weights).unwrap();
///     drop(source);
///     let _ = row.values();
/// }
/// ```
/// Retained values cannot be edited:
/// ```compile_fail,E0594
/// use stele_field::{QM31, Field};
/// use stele_pcs::RetainedRow;
/// fn mutate(row: &RetainedRow<'_, '_, QM31>) {
///     row.values()[0] = QM31::from_i64(0);
/// }
/// ```
pub struct RetainedRow<'prepared, 'message, K: ChallengeField> {
    prepared: &'prepared PreparedSource<'message, K>,
    weights: &'prepared [K],
    values: Vec<K>,
    work: RetainedRowWork,
}

fn row_bytes<K>(columns: usize) -> Result<usize, Error> {
    columns
        .checked_mul(core::mem::size_of::<K>())
        .filter(|bytes| *bytes <= isize::MAX as usize)
        .ok_or(Error::Capacity)
}

impl<'prepared, 'message, K: ChallengeField> RetainedRow<'prepared, 'message, K> {
    /// Accumulate every source element once in row-major order, with checked storage.
    pub fn new(
        prepared: &'prepared PreparedSource<'message, K>,
        weights: &'prepared [K],
    ) -> Result<Self, Error> {
        let source = prepared.source();
        if weights.len() != source.rows() {
            return Err(Error::FunctionalShape);
        }
        row_bytes::<K>(source.columns())?;
        let mut values = Vec::new();
        values
            .try_reserve_exact(source.columns())
            .map_err(|_| Error::Capacity)?;
        values.resize(source.columns(), K::from_i64(0));
        let mut work = RetainedRowWork {
            source_visits: 0,
            source_elements: 0,
            retained_bytes: row_bytes::<K>(values.capacity())?,
        };
        // PreparedSource guarantees the exact R*C shape; even zero weights read each limb.
        work.source_visits += 1;
        for (row, a) in prepared
            .message()
            .chunks_exact(source.columns())
            .zip(weights)
        {
            for (value, limb) in values.iter_mut().zip(row) {
                *value = *value + *a * K::from_i64(i64::from(limb.as_u32()));
                work.source_elements += 1;
            }
        }
        Ok(Self {
            prepared,
            weights,
            values,
            work,
        })
    }

    /// Borrow the retained row for folding or opening; no mutable access is exposed.
    pub fn values(&self) -> &[K] {
        &self.values
    }

    /// Construction observations, not a proof record or a full inference resource ledger.
    pub fn work(&self) -> RetainedRowWork {
        self.work
    }

    /// Emit the ordinary A9 opening from retained values without rereading the message.
    /// A source or row-weight mismatch fails before any transcript mutation.
    pub fn opening(
        &self,
        t: &mut Transcript<K>,
        certificate: &VerifiedCertificate<K>,
        functional: Functional<'_, K>,
    ) -> Result<(Vec<u8>, Usage), Failure> {
        if self.prepared.source().bytes() != certificate.record().source().bytes()
            || self.weights.len() != functional.a.len()
            || self
                .weights
                .iter()
                .zip(functional.a)
                .any(|(a, expected)| a.to_le_bytes().as_ref() != expected.to_le_bytes().as_ref())
        {
            return Err(Failure {
                cause: Error::RowContext,
                usage: Usage {
                    transcript: t.usage(),
                    non_transcript: HashUsage::default(),
                },
            });
        }
        self.prepared
            .opening_row(t, certificate, functional, self.values.iter().copied())
    }
}

#[cfg(test)]
#[test]
fn rejects_retained_row_allocation_sizes() {
    assert_eq!(
        row_bytes::<stele_field::QM31>(usize::MAX),
        Err(Error::Capacity)
    );
    assert_eq!(
        row_bytes::<stele_field::OM31>(
            isize::MAX as usize / core::mem::size_of::<stele_field::OM31>() + 1
        ),
        Err(Error::Capacity)
    );
    let limit = isize::MAX as usize / core::mem::size_of::<stele_field::OM31>();
    assert_eq!(
        row_bytes::<stele_field::OM31>(limit),
        Ok(limit * core::mem::size_of::<stele_field::OM31>())
    );
    assert_eq!(
        row_bytes::<stele_field::QM31>(2),
        Ok(2 * core::mem::size_of::<stele_field::QM31>())
    );
}

impl<K: ChallengeField> PreparedSource<'_, K> {
    /// Produce an A9 opening at the canonical tensor point. The expected source's
    /// own row split determines weights; no stacked layer width is substituted.
    pub fn opening_point(
        &self,
        t: &mut Transcript<K>,
        certificate: &VerifiedCertificate<K>,
        id: u64,
        point: &[K],
        value: K,
    ) -> Result<(Vec<u8>, Usage), Failure> {
        let weights = (|| {
            let source = certificate.record().source();
            if self.source().bytes() != source.bytes() {
                return Err(Error::CertificateContext);
            }
            let row_bits = source.rows().trailing_zeros() as usize;
            let column_bits = source.columns().trailing_zeros() as usize;
            if point.len() != row_bits + column_bits {
                return Err(Error::FunctionalShape);
            }
            source.opening_frame_size()?;
            source.proof_size(ProofKind::Opening)?;
            point_weights(point, row_bits)
        })();
        let (a, b) = weights.map_err(|cause| Failure {
            cause,
            usage: Usage {
                transcript: t.usage(),
                non_transcript: HashUsage::default(),
            },
        })?;
        self.opening(
            t,
            certificate,
            Functional {
                id,
                a: &a,
                b: &b,
                value,
            },
        )
    }
    /// Produce full ordered opening bytes. Any error aborts the caller's entire attempt.
    /// Transcript usage is cumulative; do not add snapshots from shared transcripts.
    pub fn opening(
        &self,
        t: &mut Transcript<K>,
        certificate: &VerifiedCertificate<K>,
        functional: Functional<'_, K>,
    ) -> Result<(Vec<u8>, Usage), Failure> {
        // Lazy iteration preserves A9's preflight and original read/absorption order.
        let row = (0..functional.b.len()).map(|column| {
            let mut value = K::from_i64(0);
            for (row, a) in functional.a.iter().enumerate() {
                let limb = self.message()[row * self.source().columns() + column];
                value = value + *a * K::from_i64(i64::from(limb.as_u32()));
            }
            value
        });
        self.opening_row(t, certificate, functional, row)
    }

    // A9 framing, scalar check and prepared-column responses are shared with A10.
    fn opening_row<I: ExactSizeIterator<Item = K>>(
        &self,
        t: &mut Transcript<K>,
        certificate: &VerifiedCertificate<K>,
        functional: Functional<'_, K>,
        row: I,
    ) -> Result<(Vec<u8>, Usage), Failure> {
        let result = (|| {
            let record = certificate.record();
            let source = record.source();
            if self.source().bytes() != source.bytes() {
                return Err(Error::CertificateContext);
            }
            let size = functional.frame_len(source)?;
            if row.len() != source.columns() {
                return Err(Error::FunctionalShape);
            }
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
            for (value, b) in row.zip(functional.b) {
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

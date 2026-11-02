//! RFC-0024 §2.2: private signed matmul within the complete integer-linear operation.
use super::{add, bytes, mul, pcs_error, Error, Failure, Mode, Record, Statement, VerifierWork};
use alloc::vec::Vec;
use stele_gkr::stacked;
use stele_hash::{ChallengeField, Transcript};
use stele_pcs::{CodeField, Functional, OpeningRecord, PreparedSource, Usage, VerifiedCertificate};

// Geometry has no point/value field: it cannot turn a provisional join into authority.
pub(crate) struct Geometry {
    pub(crate) wire_bytes: usize,
    pub(crate) public_bytes: usize,
    pub(crate) local_hashes: u64,
    pub(crate) retained_entries: usize,
    rounds: usize,
    openings: [usize; 2],
}
impl Geometry {
    pub(crate) fn new<K: ChallengeField>(
        bits: [u8; 4],
        certificates: [&VerifiedCertificate<K>; 2],
        limits: stacked::Limits,
    ) -> Result<Self, Error> {
        let [h, a, b, c] = bits.map(usize::from);
        let m = h + a + c;
        let t = h + b;
        if a > 30 || c > 30 || t > 29 || m > 63 {
            return Err(Error::InvalidMatmul);
        }
        let w = 4 * K::DEGREE;
        let size = 1usize << t;
        let prepared = add(mul(4, size)?, add(t, 4)?)?;
        let partials = mul(4, 1usize << h)?;
        let retained_entries = add(mul(5, size)?, add(1usize << a, 1usize << c)?)?;
        // Includes both restored physical points and the enclosing retained join.
        for count in [prepared, partials, retained_entries, add(m, 1)?] {
            if mul(count, core::mem::size_of::<K>())? > isize::MAX as usize {
                return Err(Error::Capacity);
            }
        }
        let mut frames = 0;
        let mut openings = [0; 2];
        let mut local_hashes = 0u64;
        for (index, (certificate, row_bits)) in certificates.iter().zip([a, c]).enumerate() {
            let source = certificate.record().source();
            if source.rows() != 1usize << row_bits || source.columns() != size {
                return Err(Error::SourceRoster);
            }
            frames = add(frames, source.opening_frame_size().map_err(pcs_error)?)?;
            openings[index] = source
                .proof_size(stele_pcs::ProofKind::Opening)
                .map_err(pcs_error)?;
            let hashes = u64::from(source.queries(stele_pcs::ProofKind::Opening))
                .checked_mul(1 + source.path_height() as u64)
                .ok_or(Error::Capacity)?;
            local_hashes = local_hashes.checked_add(hashes).ok_or(Error::Capacity)?;
        }
        let opening_bytes = add(openings[0], openings[1])?;
        // Exact A4 conservative caps, including its unused 288-byte closed roster.
        let descriptors = add(add(762, mul(w, 2 * m + h + 5)?)?, frames)?;
        let proof_cap = add(add(13, opening_bytes)?, add(12 * t, mul(w, 4 * t + 3)?)?)?;
        if descriptors > limits.descriptor_bytes
            || proof_cap > limits.proof_bytes
            || prepared > limits.prepared_entries
            || partials > limits.partial_entries
        {
            return Err(Error::Capacity);
        }
        let wire_bytes = add(add(1, opening_bytes)?, mul(w, 4 * t + 3)?)?;
        let public_bytes = add(
            add(486 + 12 * t, mul(w, 2 * m + h + 4 * t + 8)?)?,
            add(frames, opening_bytes.checked_sub(2).ok_or(Error::Capacity)?)?,
        )?;
        for size in [descriptors, proof_cap, wire_bytes, public_bytes] {
            if size > isize::MAX as usize {
                return Err(Error::Capacity);
            }
        }
        Ok(Self {
            wire_bytes,
            public_bytes,
            local_hashes,
            retained_entries,
            rounds: t,
            openings,
        })
    }

    pub(crate) fn preflight<K: ChallengeField>(
        &self,
        certificates: [&VerifiedCertificate<K>; 2],
        wire: &[u8],
    ) -> Result<(), Error> {
        use stele_field::{Serialize, M31};
        if wire.len() != self.wire_bytes || wire.first() != Some(&1) {
            return Err(Error::ProofShape);
        }
        let first = 1 + 4 * K::DEGREE * (4 * self.rounds + 3);
        for word in wire[1..first].chunks_exact(4) {
            M31::from_le_bytes(word.try_into().map_err(|_| Error::NoncanonicalField)?)
                .ok_or(Error::NoncanonicalField)?;
        }
        let second = first + self.openings[0];
        for (certificate, bytes) in certificates
            .iter()
            .zip([&wire[first..second], &wire[second..]])
        {
            certificate
                .record()
                .source()
                .parse(stele_pcs::ProofKind::Opening, bytes)
                .map_err(pcs_error)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Work {
    pub(crate) inner: super::Work,
    pub(crate) signed_input_bytes: [usize; 2],
    pub(crate) preparation_peak_bytes: usize,
}

pub(crate) fn prove_measured<K: ChallengeField + Eq>(
    t: &mut Transcript<K>,
    expected: &Statement<'_, K>,
    sources: [&PreparedSource<'_, K>; 2],
    certificates: [&VerifiedCertificate<K>; 2],
    limits: stacked::Limits,
    retained_row_entries: usize,
) -> Result<(Vec<u8>, Usage, Work), Failure> {
    super::producer::prove_mode(
        t,
        expected,
        sources,
        certificates,
        limits,
        retained_row_entries,
        Mode::Centered,
    )
}

pub(crate) fn verify_measured<'cert, K: ChallengeField + CodeField + Eq>(
    t: &mut Transcript<K>,
    expected: &Statement<'_, K>,
    certificates: [&'cert VerifiedCertificate<K>; 2],
    wire: &[u8],
    limits: stacked::Limits,
) -> Result<(Record<'cert, K>, Usage, VerifierWork), Failure>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    super::verify_mode(t, expected, certificates, wire, limits, Mode::Centered)
}

pub(super) fn sum<K: ChallengeField>(values: &[K]) -> K {
    values.iter().fold(K::from_i64(0), |s, v| s + *v)
}

type OpeningResult<'cert, K> =
    Result<(OpeningRecord<'cert, K>, Usage, stele_pcs::VerifierWork), stele_pcs::Failure>;

// The caller observes the actual child failure Usage before wrapping its cause.
pub(super) fn opening<'cert, K: ChallengeField + CodeField>(
    t: &mut Transcript<K>,
    certificate: &'cert VerifiedCertificate<K>,
    id: u64,
    point: &[K],
    value: &mut K,
    wire: &[u8],
) -> Result<OpeningResult<'cert, K>, Error>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let ell = certificate.record().source().rows().trailing_zeros() as usize;
    let a = stele_poly::eq_table(&point[..ell]).map_err(|_| Error::Capacity)?;
    let b = stele_poly::eq_table(&point[ell..]).map_err(|_| Error::Capacity)?;
    let owned = add(bytes(&a)?, bytes(&b)?)?;
    *value = *value + K::from_i64(128) * sum(&a) * sum(&b);
    let result = stele_pcs::verify_opening_measured(
        t,
        certificate,
        Functional {
            id,
            a: &a,
            b: &b,
            value: *value,
        },
        wire,
    );
    Ok(result.and_then(|(record, usage, mut work)| {
        work.weights_bytes = owned;
        work.peak_owned_bytes =
            owned
                .checked_add(work.peak_owned_bytes)
                .ok_or(stele_pcs::Failure {
                    cause: stele_pcs::Error::Capacity,
                    usage,
                })?;
        Ok((record, usage, work))
    }))
}

#[cfg(test)]
#[path = "matmul_centered_tests.rs"]
mod tests;

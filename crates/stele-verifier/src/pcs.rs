//! Certified Circle field sources: certificates and functional openings (RFC-0010 A9,
//! formal/native-field-pcs.md, with A14's Policy 2 grinding), task E8-02d.
//!
//! Written from the RFC text and the Python oracle
//! (`research/merkle-oracle/field_wire.py`, `check_policy2_wire.py`), without
//! `stele-pcs` open (ADR-128). It uses the shared transcript, Merkle path verifier and
//! certificate-ID hash of `stele-hash`, which RFC-0016 §3 allows. Scope: version-1
//! sources, layout 0 (no row shards), Circle codes, and Policies 1 and 2.

use crate::circle::{self, Circle};
use crate::sumcheck::{bytes_of, eq_at};
use alloc::vec::Vec;
use core::marker::PhantomData;
use stele_field::{Field, M31};
use stele_hash::merkle::{self, Descriptor, Digest, Kind, Opening};
use stele_hash::{AbsorbLabel, ChallengeField, ChallengeLabel, HashUsage, Transcript};

/// Why a source, certificate or opening was refused (formal/native-field-pcs.md §8).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// A context, code, layout or policy value outside version 1.
    UnsupportedSource,
    /// A wire length or version error, or a missing or extra nonce.
    ProofShape,
    /// A field limb at or above p.
    NoncanonicalField,
    /// Coefficient vectors of the wrong length.
    FunctionalShape,
    /// The opening's `dot(u, b)` differs from the expected value.
    ValueMismatch,
    /// An authenticated column fails `Enc(u)[c] = Σ_i a_i·column[i]`.
    ColumnMismatch,
    /// The certificate handle does not match the transcript's field.
    CertificateContext,
    /// 64 column draws all fell in the rejected tail.
    ColumnSamplingExhausted,
    /// A size does not fit in memory.
    Capacity,
    /// A Merkle path failed (its own cause).
    Merkle(merkle::Error),
    /// The transcript refused an operation, including `GrindMismatch`.
    Transcript(stele_hash::Error),
}

impl From<stele_hash::Error> for Error {
    fn from(e: stele_hash::Error) -> Self {
        Error::Transcript(e)
    }
}

impl From<circle::Error> for Error {
    fn from(e: circle::Error) -> Self {
        match e {
            circle::Error::Capacity => Error::Capacity,
            _ => Error::UnsupportedSource,
        }
    }
}

/// RFC-0012 A17 item 5 / RFC-0010 A14 item 3: column rounds grind 16 bits.
const COLUMN_GRIND_BITS: u8 = 16;

/// The expected context of one version-1 Circle field source (A9 §1).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Source {
    /// The challenge field's degree, 4 (QM31) or 8 (OM31).
    pub degree: u8,
    pub id: u64,
    /// `R = 2^ell` rows.
    pub ell: u8,
    /// `C = 2^m` columns.
    pub m: u8,
    /// Circle log blowup `b`.
    pub blowup: u8,
    /// Policy 1 (A3) or Policy 2 (A14).
    pub policy: u8,
    pub root: Digest,
}

/// Verifier-derived parameters of a source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Parameters {
    /// Codeword length `N = 2^(m+b)`.
    pub n: u64,
    /// Distance bound `D = N` (C = 1) or `N − C`.
    pub d: u64,
    /// Radius `e = ⌊(D − 1)/3⌋`.
    pub e: u64,
    pub certificate_queries: u16,
    pub opening_queries: u16,
    /// Tensor grinding bits `k_t` (Policy 2), else 0.
    pub tensor_bits: u8,
    /// Column grinding bits `k_q`: 16 under Policy 2, else 0.
    pub column_bits: u8,
}

// A9 §1 Policy 1 tables (q_c, q_o), indexed by m; RFC-0010 A9 text.
fn policy1(m: u8, b: u8) -> (u16, u16) {
    match (b, m) {
        (1, 0) => (130, 1),
        (1, m) => (
            match m {
                1..=2 => 314,
                3..=4 => 434,
                5..=6 => 478,
                7..=8 => 491,
                9..=12 => 494,
                _ => 495,
            },
            match m {
                1 => 130,
                2..=3 => 192,
                4..=5 => 214,
                6..=7 => 221,
                8..=9 => 222,
                _ => 223,
            },
        ),
        (_, 0) => (130, 65),
        (_, m) => (
            314,
            [65, 92, 110, 119, 125, 128, 129]
                .get(m as usize)
                .copied()
                .unwrap_or(130),
        ),
    }
}

// A14 item 2 Policy 2 tables (q_c, q_o), indexed by m; RFC-0010 A14 text.
fn policy2(m: u8, b: u8) -> (u16, u16) {
    const HALF: [(u16, u16); 10] = [
        (92, 1),
        (222, 92),
        (222, 136),
        (308, 136),
        (308, 152),
        (339, 152),
        (339, 156),
        (347, 156),
        (347, 157),
        (350, 157),
    ];
    const QUARTER: [(u16, u16); 7] = [
        (92, 46),
        (222, 66),
        (222, 78),
        (222, 85),
        (222, 88),
        (222, 90),
        (222, 91),
    ];
    if b == 1 {
        HALF.get(m as usize).copied().unwrap_or((350, 158))
    } else {
        QUARTER.get(m as usize).copied().unwrap_or((222, 92))
    }
}

/// A14 item 4: the least `k ≥ 0` with `2·ell·(e+1)·2^108 ≤ p^d·2^k` (0 for OM31).
fn tensor_bits(ell: u8, e: u64, degree: u8) -> Result<u8, Error> {
    if degree == 8 {
        return Ok(0);
    }
    let p = u128::from(M31::MODULUS);
    let field = p * p * p * p;
    let x = 2 * u128::from(ell) * u128::from(e + 1);
    for k in 0..=32u32 {
        let shift = 108 - k;
        // x·2^shift past u128 is already above p^4 < 2^124.
        if x == 0 || (x.leading_zeros() > shift && (x << shift) <= field) {
            return Ok(k as u8);
        }
    }
    Err(Error::UnsupportedSource)
}

impl Source {
    fn code(&self) -> Result<Circle, Error> {
        Ok(Circle::new(u32::from(self.m), u32::from(self.blowup))?)
    }

    /// The verifier's parameters; any value outside version 1 is UnsupportedSource.
    pub fn parameters(&self) -> Result<Parameters, Error> {
        // RFC-0010 A9 §1: K of degree 4 or 8, ell ≤ 30, a valid Circle code, policy 1
        // or 2 (A14 item 1).
        if !matches!(self.degree, 4 | 8) || self.ell > 30 || !matches!(self.policy, 1 | 2) {
            return Err(Error::UnsupportedSource);
        }
        self.code()?;
        let n = 1u64 << (self.m + self.blowup);
        let d = if self.m == 0 { n } else { n - (1u64 << self.m) };
        let e = (d - 1) / 3;
        let (q_c, q_o) = if self.policy == 1 {
            policy1(self.m, self.blowup)
        } else {
            policy2(self.m, self.blowup)
        };
        Ok(Parameters {
            n,
            d,
            e,
            certificate_queries: q_c,
            opening_queries: q_o,
            tensor_bits: if self.policy == 2 {
                tensor_bits(self.ell, e, self.degree)?
            } else {
                0
            },
            column_bits: if self.policy == 2 {
                COLUMN_GRIND_BITS
            } else {
                0
            },
        })
    }

    /// The canonical source bytes (A9 §1, A14 item 1).
    pub fn bytes(&self) -> Result<Vec<u8>, Error> {
        self.parameters()?;
        let mut out = Vec::new();
        out.try_reserve_exact(105).map_err(|_| Error::Capacity)?;
        out.extend_from_slice(b"stele/v0.1/field-source");
        out.extend_from_slice(&[1, self.degree]);
        out.extend_from_slice(&self.id.to_le_bytes());
        out.push(self.ell);
        out.extend_from_slice(&self.code()?.code_id());
        out.extend_from_slice(&(1u64 << self.ell).to_le_bytes());
        out.extend_from_slice(&(1u64 << self.m).to_le_bytes());
        out.extend_from_slice(&[0, self.policy]);
        out.extend_from_slice(&self.root);
        Ok(out)
    }

    fn tree(&self) -> Descriptor {
        Descriptor {
            kind: Kind::Columns,
            id: self.id,
            count: 1u64 << (self.m + self.blowup),
            width: 4u64 << self.ell,
        }
    }

    fn response_size(&self) -> usize {
        (4usize << self.ell) + 32 * (self.m + self.blowup) as usize
    }
}

/// A certificate that passed full verification (A9 §3). It can only be built by
/// [`verify_certificate`]; its identity binds the source, policy, field and the
/// certificate's canonical digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedCertificate<K> {
    source: Source,
    id: Digest,
    field: PhantomData<K>,
}

impl<K> VerifiedCertificate<K> {
    pub fn source(&self) -> &Source {
        &self.source
    }
    pub fn id(&self) -> &Digest {
        &self.id
    }
}

/// A row vector of `count` canonical K values from `raw`.
fn decode<K: ChallengeField>(raw: &[u8], count: usize) -> Result<Vec<K>, Error>
where
    K::Bytes: for<'a> TryFrom<&'a [u8]>,
{
    let width = bytes_of(&K::from_i64(0));
    if raw.len() != count.checked_mul(width).ok_or(Error::Capacity)? {
        return Err(Error::ProofShape);
    }
    let mut out = Vec::new();
    out.try_reserve_exact(count).map_err(|_| Error::Capacity)?;
    for chunk in raw.chunks_exact(width) {
        let bytes = K::Bytes::try_from(chunk).map_err(|_| Error::ProofShape)?;
        out.push(K::from_le_bytes(bytes).ok_or(Error::NoncanonicalField)?);
    }
    Ok(out)
}

/// Append the canonical bytes of `values` to `out`, reserving fallibly.
fn put_fields<K: ChallengeField>(out: &mut Vec<u8>, values: &[K]) -> Result<(), Error> {
    let width = values.first().map_or(0, bytes_of);
    let size = values.len().checked_mul(width).ok_or(Error::Capacity)?;
    out.try_reserve(size).map_err(|_| Error::Capacity)?;
    for v in values {
        out.extend_from_slice(v.to_le_bytes().as_ref());
    }
    Ok(())
}

/// The MSB-first eq table of `point`: entry `x` is `eq(point, x)`.
fn eq_table<K: ChallengeField>(point: &[K]) -> Result<Vec<K>, Error> {
    let n = 1usize << point.len();
    let mut out = Vec::new();
    out.try_reserve_exact(n).map_err(|_| Error::Capacity)?;
    out.extend((0..n).map(|x| eq_at(point, x)));
    Ok(out)
}

/// A9 §2: one column index in `[0, N)`, from at most 64 draws under `label`. A draw's
/// first M31 limb `x` is accepted as `x mod N` only when `x < ⌊p/N⌋·N`.
fn column<K: ChallengeField>(
    t: &mut Transcript<K>,
    label: ChallengeLabel,
    n: u64,
) -> Result<u64, Error> {
    for _ in 0..64 {
        let v = t.challenge(label)?;
        let b = v.to_le_bytes();
        let x = u64::from(u32::from_le_bytes([
            b.as_ref()[0],
            b.as_ref()[1],
            b.as_ref()[2],
            b.as_ref()[3],
        ]));
        if let Some(index) = decode_index(x, n) {
            return Ok(index);
        }
    }
    Err(Error::ColumnSamplingExhausted)
}

/// A9 §2's pure candidate decoder: `x mod N` when `x < ⌊p/N⌋·N`, else `None` (the
/// rejected tail). `N` is a power of two in `[2, 2^30]`.
fn decode_index(x: u64, n: u64) -> Option<u64> {
    let threshold = u64::from(M31::MODULUS) / n * n;
    (x < threshold).then_some(x % n)
}

/// A9 §§3–4: each response, in draw order and with repeats: authenticate the column
/// at its derived index, decode its `R` M31 limbs, and check
/// `Enc(u)[c] = Σ_i a_i·column[i]`.
fn responses<K: ChallengeField + Eq>(
    t: &mut Transcript<K>,
    source: &Source,
    a: &[K],
    u: &[K],
    block: &[u8],
    label: ChallengeLabel,
    count: usize,
) -> Result<(), Error> {
    let tree = source.tree();
    let encoded = source.code()?.encode(u)?;
    let stride = source.response_size();
    let rows = 1usize << source.ell;
    for q in 0..count {
        let index = column(t, label, tree.count)?;
        let response = &block[q * stride..(q + 1) * stride];
        let (payload, path) = response.split_at(4 * rows);
        let mut siblings: Vec<Digest> = Vec::new();
        siblings
            .try_reserve_exact(path.len() / 32)
            .map_err(|_| Error::Capacity)?;
        for c in path.chunks_exact(32) {
            siblings.push(<[u8; 32]>::try_from(c).map_err(|_| Error::ProofShape)?);
        }
        // RFC-0010 A9 §8: authenticate before decoding and checking the column.
        merkle::verify(
            tree,
            &source.root,
            index,
            Opening {
                payload,
                siblings: &siblings,
            },
        )
        .map_err(Error::Merkle)?;
        let mut combined = K::from_i64(0);
        for (w, limb) in a.iter().zip(payload.chunks_exact(4)) {
            let x = u32::from_le_bytes([limb[0], limb[1], limb[2], limb[3]]);
            // RFC-0010 A9 §1: every limb is canonical M31.
            if x >= M31::MODULUS {
                return Err(Error::NoncanonicalField);
            }
            combined = combined + w.mul_m31(M31::from_i64(i64::from(x)));
        }
        // RFC-0010 A9 §3: the encoded row agrees with the column's combination.
        if encoded[index as usize] != combined {
            return Err(Error::ColumnMismatch);
        }
    }
    Ok(())
}

/// Read a u64le nonce at `at`.
fn nonce(proof: &[u8], at: usize) -> Result<u64, Error> {
    proof
        .get(at..at + 8)
        .and_then(|b| <[u8; 8]>::try_from(b).ok())
        .map(u64::from_le_bytes)
        .ok_or(Error::ProofShape)
}

/// A9 §3 with A14 items 3–4: verify a standalone registration certificate for
/// `source`. Only full verification yields a [`VerifiedCertificate`].
pub fn verify_certificate<K: ChallengeField + Eq>(
    source: &Source,
    proof: &[u8],
) -> Result<VerifiedCertificate<K>, Error>
where
    K::Bytes: for<'a> TryFrom<&'a [u8]>,
{
    let p = source.parameters()?;
    let width = bytes_of(&K::from_i64(0));
    if width != 4 * usize::from(source.degree) {
        return Err(Error::CertificateContext);
    }
    let public_source = source.bytes()?;
    let columns = 1usize << source.m;
    let tensor = usize::from(p.tensor_bits > 0) * 8;
    let column_nonce = usize::from(p.column_bits > 0) * 8;
    let row_end = 1 + tensor + columns * width;
    let count = usize::from(p.certificate_queries);
    // RFC-0010 A9 §3 / A14 items 3–4: `u8(1) || [n_t] || t || [n_q] || responses`,
    // every length derived from the expected context.
    let expected = count
        .checked_mul(source.response_size())
        .and_then(|n| n.checked_add(row_end + column_nonce))
        .ok_or(Error::Capacity)?;
    if proof.len() != expected || proof[0] != 1 {
        return Err(Error::ProofShape);
    }
    let row = decode::<K>(&proof[1 + tensor..row_end], columns)?;
    let mut public = Vec::new();
    public
        .try_reserve_exact(33 + public_source.len())
        .map_err(|_| Error::Capacity)?;
    public.extend_from_slice(b"stele/v0.1/pcs-certificate/public");
    public.extend_from_slice(&public_source);
    let mut t = Transcript::<K>::new(&public)?;
    // RFC-0010 A14 item 4: the tensor nonce precedes the CertificateWeight draws.
    if p.tensor_bits > 0 {
        t.verify_grind(p.tensor_bits, nonce(proof, 1)?)?;
    }
    let mut point = Vec::new();
    point
        .try_reserve_exact(usize::from(source.ell))
        .map_err(|_| Error::Capacity)?;
    for _ in 0..source.ell {
        point.push(t.challenge(ChallengeLabel::CertificateWeight)?);
    }
    let a = eq_table(&point)?;
    // RFC-0010 A9 §3: t binds before any column draw.
    t.absorb(AbsorbLabel::CertificateRow, &proof[1 + tensor..row_end])?;
    // RFC-0010 A14 item 3: the column nonce follows CertificateRow.
    if p.column_bits > 0 {
        t.verify_grind(p.column_bits, nonce(proof, row_end)?)?;
    }
    let block = &proof[row_end + column_nonce..];
    responses(
        &mut t,
        source,
        &a,
        &row,
        block,
        ChallengeLabel::CertificateColumn,
        count,
    )?;
    t.absorb(AbsorbLabel::CertificateColumns, block)?;
    let id = stele_hash::certificate_id(&public_source, proof, &mut HashUsage::default())?;
    Ok(VerifiedCertificate {
        source: *source,
        id,
        field: PhantomData,
    })
}

/// A9 §4 with A14 item 3: verify a functional opening `Σ_{i,j} a_i·M[i][j]·b_j = v` of
/// a verified certificate on `t`, under the verifier's own `opening_id`, `a`, `b`, `v`.
pub fn verify_opening<K: ChallengeField + Eq>(
    t: &mut Transcript<K>,
    opening_id: u64,
    certificate: &VerifiedCertificate<K>,
    a: &[K],
    b: &[K],
    v: K,
    proof: &[u8],
) -> Result<(), Error>
where
    K::Bytes: for<'a> TryFrom<&'a [u8]>,
{
    let source = &certificate.source;
    let p = source.parameters()?;
    let width = bytes_of(&v);
    let columns = 1usize << source.m;
    let column_nonce = usize::from(p.column_bits > 0) * 8;
    let row_end = 1 + columns * width;
    let count = usize::from(p.opening_queries);
    // RFC-0010 A9 §4 / A14 item 3: `u8(1) || u || [n_q] || responses`.
    let expected = count
        .checked_mul(source.response_size())
        .and_then(|n| n.checked_add(row_end + column_nonce))
        .ok_or(Error::Capacity)?;
    if proof.len() != expected || proof[0] != 1 {
        return Err(Error::ProofShape);
    }
    let u = decode::<K>(&proof[1..row_end], columns)?;
    // RFC-0010 A9 §4: the coefficient vectors have R and C entries.
    if a.len() != 1usize << source.ell || b.len() != columns {
        return Err(Error::FunctionalShape);
    }
    // RFC-0010 A9 §4: u64le(opening id) || source || certificate ID || a || b || v.
    let source_bytes = source.bytes()?;
    let mut instance = Vec::new();
    instance
        .try_reserve(8 + source_bytes.len() + 32 + width)
        .map_err(|_| Error::Capacity)?;
    instance.extend_from_slice(&opening_id.to_le_bytes());
    instance.extend_from_slice(&source_bytes);
    instance.extend_from_slice(&certificate.id);
    put_fields(&mut instance, a)?;
    put_fields(&mut instance, b)?;
    instance.extend_from_slice(v.to_le_bytes().as_ref());
    t.absorb(AbsorbLabel::Opening, &instance)?;
    t.absorb(AbsorbLabel::OpeningRow, &proof[1..row_end])?;
    // RFC-0010 A9 §4: dot(u, b) = v.
    let mut dot = K::from_i64(0);
    for (x, y) in u.iter().zip(b) {
        dot = dot + *x * *y;
    }
    if dot != v {
        return Err(Error::ValueMismatch);
    }
    // RFC-0010 A14 item 3: the column nonce follows OpeningRow.
    if p.column_bits > 0 {
        t.verify_grind(p.column_bits, nonce(proof, row_end)?)?;
    }
    let block = &proof[row_end + column_nonce..];
    responses(
        t,
        source,
        a,
        &u,
        block,
        ChallengeLabel::OpeningColumn,
        count,
    )?;
    t.absorb(AbsorbLabel::OpeningColumns, block)?;
    Ok(())
}

/// A point opening: `a = eq(point[..ell])`, `b = eq(point[ell..])` (A9 §4).
pub fn verify_point<K: ChallengeField + Eq>(
    t: &mut Transcript<K>,
    opening_id: u64,
    certificate: &VerifiedCertificate<K>,
    point: &[K],
    v: K,
    proof: &[u8],
) -> Result<(), Error>
where
    K::Bytes: for<'a> TryFrom<&'a [u8]>,
{
    let ell = usize::from(certificate.source.ell);
    if point.len() != ell + usize::from(certificate.source.m) {
        return Err(Error::FunctionalShape);
    }
    let (a, b) = (eq_table(&point[..ell])?, eq_table(&point[ell..])?);
    verify_opening(t, opening_id, certificate, &a, &b, v, proof)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A9 §2: the threshold `T = ⌊p/N⌋·N = p − (N − 1)` is exact: `T − 1` maps to
    /// `(T − 1) mod N` and every `x ≥ T` is rejected, so each index has `T/N`
    /// preimages.
    #[test]
    fn decodes_column_candidates_at_the_threshold() {
        let p = u64::from(M31::MODULUS);
        for log in 1..=30u32 {
            let n = 1u64 << log;
            let t = p - (n - 1);
            assert_eq!(decode_index(t - 1, n), Some((t - 1) % n));
            assert_eq!(decode_index(t, n), None);
            assert_eq!(decode_index(p - 1, n), None);
            assert_eq!(decode_index(0, n), Some(0));
        }
    }
}

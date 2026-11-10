//! Source context, finite query policy and unverified wire parsing, RFC-0010 A9 §§1,3,4
//! and A3 items 2-4 (version-2 expander sources).
use core::marker::PhantomData;
use stele_code::{registry, Circle, Code, Encoder};
use stele_field::{Serialize, M31};
use stele_hash::{merkle, ChallengeField};

// RFC-0010 A9 §1: indexed only after the Circle factory validates m and blowup.
const CERT_HALF: [u16; 30] = [
    130, 314, 314, 434, 434, 478, 478, 491, 491, 494, 494, 494, 494, 495, 495, 495, 495, 495, 495,
    495, 495, 495, 495, 495, 495, 495, 495, 495, 495, 495,
];
const OPEN_HALF: [u16; 30] = [
    1, 130, 192, 192, 214, 214, 221, 221, 222, 222, 223, 223, 223, 223, 223, 223, 223, 223, 223,
    223, 223, 223, 223, 223, 223, 223, 223, 223, 223, 223,
];
const CERT_QUARTER: [u16; 29] = [
    130, 314, 314, 314, 314, 314, 314, 314, 314, 314, 314, 314, 314, 314, 314, 314, 314, 314, 314,
    314, 314, 314, 314, 314, 314, 314, 314, 314, 314,
];
const OPEN_QUARTER: [u16; 29] = [
    65, 92, 110, 119, 125, 128, 129, 130, 130, 130, 130, 130, 130, 130, 130, 130, 130, 130, 130,
    130, 130, 130, 130, 130, 130, 130, 130, 130, 130,
];

// RFC-0010 A3 item 4: Policy 1 for version-2 sources, indexed by J-3 for J=3..14.
const CERT_V2: [u16; 12] = [
    478, 11489, 13137, 13377, 13438, 13469, 13469, 13471, 13472, 13472, 13472, 13472,
];
const OPEN_V2: [u16; 12] = [
    221, 5722, 6546, 6666, 6697, 6708, 6713, 6713, 6713, 6714, 6714, 6714,
];
// A3 item 3: policy byte 1 pins these evidence IDs; a changed premise needs a new policy byte.
// Build-time tripwire: both sides are compiled constants, so the construction check
// below cannot fail at runtime; the test at the end of this file fails on any edit.
const CIRCLE_EVIDENCE: &str = "rfc-0010-a2/root-bound-v1";
const EXPANDER_EVIDENCE: &str = "rfc-0010-a1/finite-v2";
const SETUP_EVIDENCE: &str = "rfc-0012-a7/2^256-all-seeds-v2";
const PURPOSE: &[u8; 23] = b"stele/v0.1/field-source";

/// Rejected context, wire bytes or unrepresentable size; never partial acceptance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Unsupported field matrix dimensions or Circle code parameters.
    UnsupportedSource,
    /// Version or complete wire length disagrees with the expected source.
    ProofShape,
    /// A field limb is at least the M31 modulus.
    NoncanonicalField,
    /// The producer's row-major matrix does not have exactly R*C elements.
    MessageShape,
    /// Canonical encoding failed; preserve the encoder's cause.
    Encoder(stele_code::Error),
    /// Merkle construction/path failed; preserve its cause and work observation.
    Merkle(merkle::Error),
    /// Transcript validation, sampling or local accounting failed.
    Transcript(stele_hash::Error),
    /// An authenticated column fails its encoded-row equation.
    ColumnMismatch,
    /// Coefficient lengths disagree with the expected source.
    FunctionalShape,
    /// The scalar functional does not equal the expected value.
    ValueMismatch,
    /// Prepared material belongs to a different verified source/context.
    CertificateContext,
    /// Retained row belongs to a different source or exact row-weight vector (A10).
    RowContext,
    /// Revealed mask-row coefficients lack full M31 rank; abort (RFC-0013 A2 item 1).
    MaskRank,
    /// A hiding source was already opened once; refuse another (RFC-0013 A2 item 1).
    MaskBudget,
    /// A size or allocation cannot be represented or satisfied on this platform.
    Capacity,
}

/// Select the verifier-derived query count; no proof-supplied mode byte.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProofKind {
    /// Standalone proximity certificate.
    Certificate,
    /// One general functional opening against a verified certificate.
    Opening,
}

/// Conditional mathematical parameters, not a verified certificate or profile decision.
/// Consumers rederive them from their expected Source; supplied metadata is not authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Parameters {
    /// Codeword length N.
    pub length: u64,
    /// Accepted Circle or v2 distance lower bound D (RFC-0010 A3 item 3).
    pub distance: u64,
    /// Integer radius e=floor((D-1)/3).
    pub radius: u64,
    /// Least positive q_c for the exact 130-bit certificate miss inequality.
    pub certificate_queries: u16,
    /// Least positive q_o for the exact 130-bit opening miss inequality.
    pub opening_queries: u16,
    /// RFC-0012 A15: the v2 setup term 200431782/2^160 applies (J>=4), once per ledger.
    pub setup_term: bool,
}

/// Verifier-owned canonical M31 matrix context, with QM31 or OM31 challenges.
/// Logical and padded dimensions coincide. Construction authenticates no root.
/// ```compile_fail
/// use stele_field::M31;
/// use stele_pcs::Source;
/// let source = Source::<M31>::new(0, 0, 0, 1, [0; 32]);
/// ```
#[derive(Clone, Copy, Debug)]
pub struct Source<K: ChallengeField> {
    id: u64,
    ell: u8,
    rows: usize,
    code: [u8; 55],
    code_len: usize,
    columns: usize,
    length: usize,
    parameters: Parameters,
    root: merkle::Digest,
    hiding: bool,
    field: PhantomData<K>,
}

/// Exact canonical source bytes: 105 for version 1, 139 for version 2 (A3 item 2).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceBytes {
    bytes: [u8; 139],
    len: usize,
}
impl core::ops::Deref for SourceBytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl<K: ChallengeField> Source<K> {
    /// Validate a version-1 Circle context without allocating any matrix or proof.
    pub fn new(id: u64, ell: u8, m: u8, blowup: u8, root: merkle::Digest) -> Result<Self, Error> {
        let code = Circle::new(u32::from(m), u32::from(blowup)).map_err(|error| match error {
            stele_code::Error::Capacity => Error::Capacity,
            _ => Error::UnsupportedSource,
        })?;
        Self::from_code_id(id, ell, &code.code_id(), root)
    }

    /// Validate a Circle (version 1) or v2 expander (version 2, J=3..14) identity.
    /// Every other identity, including J=15, rejects before any transcript work.
    pub fn from_code_id(
        id: u64,
        ell: u8,
        code: &[u8],
        root: merkle::Digest,
    ) -> Result<Self, Error> {
        if ell > 30 {
            return Err(Error::UnsupportedSource);
        }
        let rows = 1usize.checked_shl(u32::from(ell)).ok_or(Error::Capacity)?;
        let encoder = Encoder::from_code_id(code).map_err(|error| match error {
            stele_code::Error::Capacity => Error::Capacity,
            _ => Error::UnsupportedSource,
        })?;
        // The factory validated the identity: Circle m,b or v2 J in 3..=15 exist.
        let (certificate_queries, opening_queries, evidence, setup) = if code.len() == 21 {
            let m = usize::from(code[19]);
            if code[20] == 1 {
                (CERT_HALF[m], OPEN_HALF[m], CIRCLE_EVIDENCE, None)
            } else {
                (CERT_QUARTER[m], OPEN_QUARTER[m], CIRCLE_EVIDENCE, None)
            }
        } else {
            // A3 item 2: N=2^31 at J=15 exceeds the RFC-0012 A10 sampler domain.
            let j = usize::from(code[22]);
            if j > 14 {
                return Err(Error::UnsupportedSource);
            }
            let setup = (j >= 4).then_some(SETUP_EVIDENCE);
            (CERT_V2[j - 3], OPEN_V2[j - 3], EXPANDER_EVIDENCE, setup)
        };
        let code_parameters = registry::parameters(&encoder);
        if code_parameters.distance_evidence != evidence || code_parameters.setup_evidence != setup
        {
            return Err(Error::Encoder(stele_code::Error::InvalidRegistry));
        }
        let info = encoder.info();
        let distance = code_parameters.distance_lower_bound;
        let mut code_bytes = [0; 55];
        code_bytes[..code.len()].copy_from_slice(code);
        Ok(Self {
            id,
            ell,
            rows,
            code: code_bytes,
            code_len: code.len(),
            columns: usize::try_from(info.message_len).map_err(|_| Error::Capacity)?,
            length: usize::try_from(info.codeword_len).map_err(|_| Error::Capacity)?,
            parameters: Parameters {
                length: info.codeword_len,
                distance,
                radius: (distance - 1) / 3,
                certificate_queries,
                opening_queries,
                setup_term: setup.is_some(),
            },
            root,
            hiding: false,
            field: PhantomData,
        })
    }

    /// Version-3 hiding source over `2^ell × 2^m` data (RFC-0010 A15): the context
    /// is Circle `(m+1, b)` with `2R` rows and `2C` columns, salted leaves, and the
    /// admission `R >= 2D` and `q_c + q_o <= C - 1`, before any transcript work.
    pub fn hiding(
        id: u64,
        ell: u8,
        m: u8,
        blowup: u8,
        root: merkle::Digest,
    ) -> Result<Self, Error> {
        if ell >= 30 || m >= 30 {
            return Err(Error::UnsupportedSource);
        }
        let code =
            Circle::new(u32::from(m) + 1, u32::from(blowup)).map_err(|error| match error {
                stele_code::Error::Capacity => Error::Capacity,
                _ => Error::UnsupportedSource,
            })?;
        let mut source = Self::from_code_id(id, ell + 1, &code.code_id(), root)?;
        let p = source.parameters;
        let data_columns = source.columns / 2;
        if source.rows / 2 < 2 * K::DEGREE
            || usize::from(p.certificate_queries) + usize::from(p.opening_queries) >= data_columns
        {
            return Err(Error::UnsupportedSource);
        }
        source.hiding = true;
        Ok(source)
    }

    /// True for a version-3 hiding source (RFC-0013 A2).
    pub fn is_hiding(&self) -> bool {
        self.hiding
    }

    /// Salt bytes at the start of each leaf payload: 32 for hiding sources, else 0.
    pub fn salt_len(&self) -> usize {
        if self.hiding {
            32
        } else {
            0
        }
    }

    /// Parse exact canonical source bytes from an expected statement. Version, degree,
    /// layout, policy and dimensions must be the derived ones; else UnsupportedSource.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let code_len = match bytes.get(23) {
            Some(1 | 3) => 21,
            Some(2) => 55,
            _ => return Err(Error::UnsupportedSource),
        };
        if bytes.len() != 84 + code_len || bytes[..23] != PURPOSE[..] {
            return Err(Error::UnsupportedSource);
        }
        let end = 34 + code_len;
        let id = bytes[25..33]
            .try_into()
            .map_err(|_| Error::UnsupportedSource)?;
        let root = bytes[end + 18..]
            .try_into()
            .map_err(|_| Error::UnsupportedSource)?;
        let source = if bytes[23] == 3 {
            // A15: rows and code are one step above the data; Circle (m+1, b) only.
            let (ell, code) = (bytes[33], &bytes[34..end]);
            if ell == 0 || code[19] == 0 || code[..19] != *b"stele/circle-m31/v1" {
                return Err(Error::UnsupportedSource);
            }
            Self::hiding(
                u64::from_le_bytes(id),
                ell - 1,
                code[19] - 1,
                code[20],
                root,
            )?
        } else {
            Self::from_code_id(u64::from_le_bytes(id), bytes[33], &bytes[34..end], root)?
        };
        // Re-serialization fixes version, degree, R, C, layout 0 and policy 1 exactly.
        if *source.bytes() != *bytes {
            return Err(Error::UnsupportedSource);
        }
        Ok(source)
    }

    /// Exact source bytes, including version, expected root, layout and fixed policy.
    pub fn bytes(&self) -> SourceBytes {
        let mut out = [0; 139];
        let end = 34 + self.code_len;
        out[..23].copy_from_slice(PURPOSE);
        out[23] = match (self.hiding, self.code_len) {
            (true, _) => 3,
            (false, 21) => 1,
            _ => 2,
        };
        out[24] = K::DEGREE as u8;
        out[25..33].copy_from_slice(&self.id.to_le_bytes());
        out[33] = self.ell;
        out[34..end].copy_from_slice(self.code_id());
        out[end..end + 8].copy_from_slice(&(1u64 << self.ell).to_le_bytes());
        out[end + 8..end + 16].copy_from_slice(&(self.columns as u64).to_le_bytes());
        out[end + 17] = 1; // Layout at end+16 stays zero; policy 1 owns the fixed counts.
        out[end + 18..end + 50].copy_from_slice(&self.root);
        SourceBytes {
            bytes: out,
            len: end + 50,
        }
    }

    /// Number of message rows, with no implicit logical padding.
    pub fn rows(&self) -> usize {
        self.rows
    }

    /// Number of message columns, distinct from encoded leaf count.
    pub fn columns(&self) -> usize {
        self.columns
    }

    /// The validated exact code identity, without any proximity or profile credit.
    pub fn code_id(&self) -> &[u8] {
        &self.code[..self.code_len]
    }

    /// Number of encoded symbols N, which is also the Merkle leaf count.
    pub fn codeword_len(&self) -> usize {
        self.length
    }

    /// Expected full column-tree root from this caller-owned context.
    pub fn root(&self) -> merkle::Digest {
        self.root
    }

    /// Number of bottom-up siblings in each individual response.
    pub fn path_height(&self) -> usize {
        self.length.trailing_zeros() as usize
    }

    /// Exact column tree descriptor; field decoding follows authentication.
    pub fn descriptor(&self) -> merkle::Descriptor {
        merkle::Descriptor {
            kind: merkle::Kind::Columns,
            id: self.id,
            count: self.length as u64,
            width: (4u64 << self.ell) + self.salt_len() as u64,
        }
    }

    /// Static parameters under RFC-0010 A9 §1 and A3 items 3-4; no floating point.
    pub fn parameters(&self) -> Parameters {
        self.parameters
    }

    /// Query count selected only by this expected context and operation.
    pub fn queries(&self, kind: ProofKind) -> u16 {
        let p = self.parameters();
        match kind {
            ProofKind::Certificate => p.certificate_queries,
            ProofKind::Opening => p.opening_queries,
        }
    }

    fn sizes(&self, kind: ProofKind) -> Result<(usize, usize, usize), Error> {
        let row = self
            .columns()
            .checked_mul(4 * K::DEGREE)
            .ok_or(Error::Capacity)?;
        let width = self
            .rows()
            .checked_mul(4)
            .and_then(|n| n.checked_add(self.salt_len()))
            .ok_or(Error::Capacity)?;
        let stride = width
            .checked_add(32 * self.path_height())
            .ok_or(Error::Capacity)?;
        let total = stride
            .checked_mul(usize::from(self.queries(kind)))
            .and_then(|n| n.checked_add(row))
            .and_then(|n| n.checked_add(1))
            .ok_or(Error::Capacity)?;
        Ok((row, stride, total))
    }

    /// Complete version/row/response byte size, checked before allocation or execution.
    pub fn proof_size(&self, kind: ProofKind) -> Result<usize, Error> {
        Ok(self.sizes(kind)?.2)
    }

    /// Canonical functional frame size, including all coefficients, RFC-0010 A9 §4.
    pub fn opening_frame_size(&self) -> Result<usize, Error> {
        self.rows()
            .checked_add(self.columns())
            .and_then(|n| n.checked_add(1))
            .and_then(|n| n.checked_mul(4 * K::DEGREE))
            .and_then(|n| n.checked_add(8 + self.bytes().len() + 32))
            .ok_or(Error::Capacity)
    }

    /// Parse exact wire shape and canonical row limbs without allocation.
    /// Responses remain unauthenticated: the actual consumer must check their paths
    /// before canonical column decoding. This result grants no verification credit.
    pub fn parse<'a>(&self, kind: ProofKind, bytes: &'a [u8]) -> Result<Wire<'a>, Error> {
        let (row, stride, total) = self.sizes(kind)?;
        if bytes.len() != total || bytes.first() != Some(&1) {
            return Err(Error::ProofShape);
        }
        let end = 1 + row; // sizes checked this addition inside the larger total.
        for limb in bytes[1..end].chunks_exact(4) {
            let encoded = limb.try_into().map_err(|_| Error::NoncanonicalField)?;
            M31::from_le_bytes(encoded).ok_or(Error::NoncanonicalField)?;
        }
        Ok(Wire {
            row: &bytes[1..end],
            block: &bytes[end..],
            stride,
            width: stride - 32 * self.path_height(),
        })
    }
}

/// Borrowed individual draw response, retaining duplicates and original order.
#[derive(Clone, Copy, Debug)]
pub struct Response<'a> {
    /// Unauthenticated canonical-field candidate bytes; authenticate before decoding.
    pub payload: &'a [u8],
    /// Exact bottom-up sibling bytes, in consecutive 32-byte digests.
    pub siblings: &'a [u8],
}

/// Unverified parsed bytes, never a certificate handle or functional-opening receipt.
#[derive(Clone, Copy, Debug)]
pub struct Wire<'a> {
    row: &'a [u8],
    block: &'a [u8],
    stride: usize,
    width: usize,
}
impl<'a> Wire<'a> {
    /// Full canonical K row, in source column order.
    pub fn row_bytes(&self) -> &'a [u8] {
        self.row
    }
    /// Complete ordered response block for the final transcript absorb.
    pub fn response_bytes(&self) -> &'a [u8] {
        self.block
    }

    /// All individual responses, with no proof-supplied indices or deduplication.
    pub fn responses(&self) -> impl ExactSizeIterator<Item = Response<'a>> + '_ {
        self.block.chunks_exact(self.stride).map(|bytes| Response {
            payload: &bytes[..self.width],
            siblings: &bytes[self.width..],
        })
    }
}

#[cfg(test)]
#[test]
fn matches_reference_pinned_evidence_ids() {
    assert_eq!(CIRCLE_EVIDENCE, registry::CIRCLE_DISTANCE_EVIDENCE);
    assert_eq!(EXPANDER_EVIDENCE, registry::EXPANDER_DISTANCE_EVIDENCE);
    assert_eq!(SETUP_EVIDENCE, registry::EXPANDER_SETUP_EVIDENCE);
}

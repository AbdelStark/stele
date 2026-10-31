//! Source context, finite query policy and unverified wire parsing, RFC-0010 A9 §§1,3,4.
use core::marker::PhantomData;
use stele_code::Circle;
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

/// Rejected context, wire bytes or unrepresentable size; never partial acceptance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Unsupported field matrix dimensions or Circle code parameters.
    UnsupportedSource,
    /// Version or complete wire length disagrees with the expected source.
    ProofShape,
    /// A field limb is at least the M31 modulus.
    NoncanonicalField,
    /// A size cannot be represented on this platform.
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
    /// Accepted Circle distance lower bound D.
    pub distance: u64,
    /// Integer radius e=floor((D-1)/3).
    pub radius: u64,
    /// Least positive q_c for the exact 130-bit certificate miss inequality.
    pub certificate_queries: u16,
    /// Least positive q_o for the exact 130-bit opening miss inequality.
    pub opening_queries: u16,
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
    code: Circle,
    root: merkle::Digest,
    field: PhantomData<K>,
}

impl<K: ChallengeField> Source<K> {
    /// Validate fixed dimensions and policy without allocating any matrix or proof.
    pub fn new(id: u64, ell: u8, m: u8, blowup: u8, root: merkle::Digest) -> Result<Self, Error> {
        if ell > 30 {
            return Err(Error::UnsupportedSource);
        }
        let rows = 1usize.checked_shl(u32::from(ell)).ok_or(Error::Capacity)?;
        let code = Circle::new(u32::from(m), u32::from(blowup)).map_err(|error| match error {
            stele_code::Error::Capacity => Error::Capacity,
            _ => Error::UnsupportedSource,
        })?;
        Ok(Self {
            id,
            ell,
            rows,
            code,
            root,
            field: PhantomData,
        })
    }

    /// Exact version-1 source bytes, including expected root, layout and fixed policy.
    pub fn bytes(&self) -> [u8; 105] {
        let mut out = [0; 105];
        out[..23].copy_from_slice(b"stele/v0.1/field-source");
        out[23] = 1;
        out[24] = K::DEGREE as u8;
        out[25..33].copy_from_slice(&self.id.to_le_bytes());
        out[33] = self.ell;
        out[34..55].copy_from_slice(&self.code.code_id());
        out[55..63].copy_from_slice(&(1u64 << self.ell).to_le_bytes());
        out[63..71].copy_from_slice(&(self.columns() as u64).to_le_bytes());
        out[72] = 1; // Layout at offset 71 stays zero; policy 1 owns the fixed counts.
        out[73..].copy_from_slice(&self.root);
        out
    }

    /// Number of message rows, with no implicit logical padding.
    pub fn rows(&self) -> usize {
        self.rows
    }

    /// Number of message columns, distinct from encoded leaf count.
    pub fn columns(&self) -> usize {
        self.code.message_len()
    }

    /// Number of bottom-up siblings in each individual response.
    pub fn path_height(&self) -> usize {
        self.code.codeword_len().trailing_zeros() as usize
    }

    /// Exact column tree descriptor; field decoding follows authentication.
    pub fn descriptor(&self) -> merkle::Descriptor {
        merkle::Descriptor {
            kind: merkle::Kind::Columns,
            id: self.id,
            count: self.code.codeword_len() as u64,
            width: 4u64 << self.ell,
        }
    }

    /// Static parameters under RFC-0010 A9 §1; no floating-point parameter selection.
    pub fn parameters(&self) -> Parameters {
        let id = self.code.code_id();
        let (m, b) = (id[19], id[20]);
        let (certificate_queries, opening_queries) = if b == 1 {
            (CERT_HALF[usize::from(m)], OPEN_HALF[usize::from(m)])
        } else {
            (CERT_QUARTER[usize::from(m)], OPEN_QUARTER[usize::from(m)])
        };
        let length = self.code.codeword_len() as u64;
        let distance = if m == 0 {
            length
        } else {
            length - self.columns() as u64
        };
        Parameters {
            length,
            distance,
            radius: (distance - 1) / 3,
            certificate_queries,
            opening_queries,
        }
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
        let width = self.rows().checked_mul(4).ok_or(Error::Capacity)?;
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

    /// All individual responses, with no proof-supplied indices or deduplication.
    pub fn responses(&self) -> impl ExactSizeIterator<Item = Response<'a>> + '_ {
        self.block.chunks_exact(self.stride).map(|bytes| Response {
            payload: &bytes[..self.width],
            siblings: &bytes[self.width..],
        })
    }
}

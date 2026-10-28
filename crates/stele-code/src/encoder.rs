//! Closed code identity, approved fields and resource boundaries, RFC-0010 A4.
use super::{reserved, Circle, Error};
use alloc::vec::Vec;
use core::mem::size_of;
use stele_field::{Field, CM31, M31, OM31, QM31};
mod expander;
mod private {
    pub trait SealedCode {}
    pub trait SealedField {}
}

/// The only fields supported by the closed encoder (RFC-0010 A4).
/// ```compile_fail
/// fn supported<K: stele_code::CodeField>() {}
/// supported::<stele_field::CM31>();
/// ```
/// ```compile_fail,E0277
/// fn supported<K: stele_code::CodeField>() {}
/// supported::<stele_field::KoalaBear>();
/// ```
/// An external field implementation satisfies every Field requirement, but cannot
/// supply the private seal. Both examples use the same complete implementation.
#[doc = concat!("```\n", include_str!("encoder/field-doctest.md"),
    "\nfn field<K: Field>() {}\nfield::<Other>();\n```\n",
    "```compile_fail,E0277\n", include_str!("encoder/field-doctest.md"),
    "\nimpl stele_code::CodeField for Other {\n",
    "const DEGREE: u8 = 1;\n",
    "fn mul_base(self, c: M31) -> Self { Self(self.0 * c) }\n}\n```")]
pub trait CodeField: Field + private::SealedField {
    /// Canonical number of M31 limbs.
    const DEGREE: u8;
    /// Multiply each limb once by a base-field coefficient, including zero.
    fn mul_base(self, coefficient: M31) -> Self;
}
fn scale_cm(value: CM31, c: M31) -> CM31 {
    CM31(value.0 * c, value.1 * c)
}
impl private::SealedField for M31 {}
impl private::SealedField for QM31 {}
impl private::SealedField for OM31 {}
impl CodeField for M31 {
    const DEGREE: u8 = 1;
    fn mul_base(self, c: M31) -> Self {
        self * c
    }
}
impl CodeField for QM31 {
    const DEGREE: u8 = 4;
    fn mul_base(self, c: M31) -> Self {
        QM31(scale_cm(self.0, c), scale_cm(self.1, c))
    }
}
impl CodeField for OM31 {
    const DEGREE: u8 = 8;
    fn mul_base(self, c: M31) -> Self {
        OM31(self.0.mul_base(c), self.1.mul_base(c))
    }
}

/// Mathematical dimensions/work counts; never a PCS parameter certificate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncoderInfo {
    /// Number of message symbols.
    pub message_len: u64,
    /// Number of encoded symbols.
    pub codeword_len: u64,
    /// Number of generated sparse edges, including zero coefficients.
    pub sparse_edges: u64,
    /// Number of generated sparse rows across all levels.
    pub row_count: u64,
}
/// Closed encoder operations; returned metadata is never accepted as authority.
/// ```compile_fail
/// use stele_code::{Code, CodeField, EncoderInfo, Error};
/// struct Other;
/// impl Code for Other {
///     fn code_id(&self) -> &[u8] { &[] }
///     fn info(&self) -> EncoderInfo { EncoderInfo { message_len: 0, codeword_len: 0, sparse_edges: 0, row_count: 0 } }
///     fn encode<K: CodeField>(&self, _: &[K]) -> Result<Vec<K>, Error> { Err(Error::RowShape) }
///     fn eval_row<K: CodeField>(&self, _: &[K], _: &[usize]) -> Result<Vec<K>, Error> { Err(Error::RowShape) }
/// }
/// ```
pub trait Code: private::SealedCode {
    /// Complete canonical identity, including the seed at the base-only size.
    fn code_id(&self) -> &[u8];
    /// Derived mathematical sizes/counts, with no distance or profile information.
    fn info(&self) -> EncoderInfo;
    /// Encode an exact-length canonical row, returning no partial result on error.
    fn encode<K: CodeField>(&self, row: &[K]) -> Result<Vec<K>, Error>;
    /// Select full-word coordinates, preserving duplicates and order.
    fn eval_row<K: CodeField>(&self, row: &[K], columns: &[usize]) -> Result<Vec<K>, Error>;
}
/// A validated A2 Circle or A4 v2 identity. Fields cannot be supplied externally.
#[derive(Debug)]
pub struct Encoder {
    id: [u8; 55],
    len: usize,
    info: EncoderInfo,
}
impl private::SealedCode for Encoder {}

fn add(a: u64, b: u64) -> Result<u64, Error> {
    a.checked_add(b).ok_or(Error::Capacity)
}
fn mul(a: u64, b: u64) -> Result<u64, Error> {
    a.checked_mul(b).ok_or(Error::Capacity)
}
fn hash(frame: &[u8; 74]) -> [u8; 32] {
    *blake3::hash(frame).as_bytes()
}
fn zeros<K: CodeField>(len: usize) -> Result<Vec<K>, Error> {
    let mut out = reserved(len)?;
    out.resize(len, K::from_i64(0));
    Ok(out)
}
impl Encoder {
    /// Validate/copy a complete identity without hashing or graph/FFT allocation.
    pub fn from_code_id(bytes: &[u8]) -> Result<Self, Error> {
        // A4 identity bounds establish every shift <=30 and codeword length <=2^31.
        let (message_len, codeword_len, mut sparse_edges, mut row_count) =
            if bytes.len() == 21 && &bytes[..19] == b"stele/circle-m31/v1" {
                let (m, b) = (bytes[19], bytes[20]);
                if !(1..=2).contains(&b) || m > 30 - b {
                    return Err(Error::InvalidCodeId);
                }
                (1u64 << m, 1u64 << (m + b), 0, 0)
            } else if bytes.len() == 55
                && &bytes[..22] == b"stele/expander-seed/v2"
                && (3..=15).contains(&bytes[22])
            {
                let n = 1u64 << (2 * bytes[22]);
                (n, 2 * n, 0, 0)
            } else {
                return Err(Error::InvalidCodeId);
            };
        if bytes.len() == 55 {
            for level in 4..=bytes[22] {
                let n = 1u64 << (2 * level);
                let (a, b) = expander::degrees(level);
                sparse_edges = add(sparse_edges, add(mul(n, a as u64)?, mul(n / 2, b as u64)?)?)?;
                row_count = add(row_count, add(n, n / 2)?)?;
            }
        }
        let mut id = [0; 55];
        id[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            id,
            len: bytes.len(),
            info: EncoderInfo {
                message_len,
                codeword_len,
                sparse_edges,
                row_count,
            },
        })
    }
    fn validate<K: CodeField>(&self, row: &[K]) -> Result<(), Error> {
        if u64::try_from(row.len()).map_err(|_| Error::Capacity)? != self.info.message_len {
            return Err(Error::RowShape);
        }
        if size_of::<K>() != 4 * usize::from(K::DEGREE) || ![4, 8].contains(&size_of::<usize>()) {
            return Err(Error::Capacity);
        }
        Ok(())
    }
    // A4: requested payloads, not actual capacities, allocator overhead or RSS.
    fn payload<K: CodeField>(&self, selected: u64, pointer: u64) -> Result<u64, Error> {
        let p = self.info;
        let w = 4 * u64::from(K::DEGREE);
        let owned = if self.len == 55 {
            let fields = add(
                add(add(p.codeword_len, (p.message_len - 64) / 3)?, 128)?,
                selected,
            )?;
            add(mul(fields, w)?, add(127 * 4, mul(21, pointer)?)?)?
        } else {
            let fields = mul(add(p.codeword_len, selected)?, w)?;
            let headers = mul(u64::from(p.codeword_len.trailing_zeros()), mul(3, pointer)?)?;
            // A2: inverse k-1+k/2 twiddles/prefixes <= forward N-1 (N>=2k).
            add(fields, add(mul(p.codeword_len - 1, 4)?, headers)?)?
        };
        mul(p.sparse_edges, u64::from(K::DEGREE))?;
        mul(p.row_count, 64)?;
        Ok(owned
            .max(mul(p.message_len, w)?)
            .max(mul(selected, pointer)?))
    }
    fn capacity<K: CodeField>(&self, selected: usize) -> Result<(usize, usize), Error> {
        let pointer = size_of::<usize>() as u64;
        if ![4, 8].contains(&pointer)
            || self.payload::<K>(selected as u64, pointer)? > isize::MAX as u64
        {
            return Err(Error::Capacity);
        }
        let scratch = if self.len == 55 {
            (self.info.message_len - 64) / 3
        } else {
            0
        };
        Ok((
            usize::try_from(self.info.codeword_len).map_err(|_| Error::Capacity)?,
            usize::try_from(scratch).map_err(|_| Error::Capacity)?,
        ))
    }
    fn encode_with<K: CodeField>(
        &self,
        row: &[K],
        hash: &mut impl FnMut(&[u8; 74]) -> [u8; 32],
    ) -> Result<Vec<K>, Error> {
        self.validate(row)?;
        let (length, scratch) = self.capacity::<K>(0)?;
        if self.len == 21 {
            return Circle::new(u32::from(self.id[19]), u32::from(self.id[20]))?.encode(row);
        }
        let mut output = zeros(length)?;
        let mut work = zeros(scratch)?;
        expander::run(
            &self.id[23..],
            self.id[22],
            row,
            &mut output,
            &mut work,
            hash,
        )?;
        Ok(output)
    }
    fn eval_with<K: CodeField>(
        &self,
        row: &[K],
        columns: &[usize],
        hash: &mut impl FnMut(&[u8; 74]) -> [u8; 32],
    ) -> Result<Vec<K>, Error> {
        self.validate(row)?;
        if columns.iter().any(|c| *c as u64 >= self.info.codeword_len) {
            return Err(Error::Column);
        }
        if columns.is_empty() {
            return Ok(Vec::new());
        }
        self.capacity::<K>(columns.len())?;
        let mut selected = reserved(columns.len())?;
        let encoded = self.encode_with(row, hash)?;
        selected.extend(columns.iter().map(|c| encoded[*c]));
        Ok(selected)
    }
}
impl Code for Encoder {
    fn code_id(&self) -> &[u8] {
        &self.id[..self.len]
    }
    fn info(&self) -> EncoderInfo {
        self.info
    }
    fn encode<K: CodeField>(&self, row: &[K]) -> Result<Vec<K>, Error> {
        self.encode_with(row, &mut hash)
    }
    fn eval_row<K: CodeField>(&self, row: &[K], columns: &[usize]) -> Result<Vec<K>, Error> {
        self.eval_with(row, columns, &mut hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn code(j: u8) -> Encoder {
        let mut id = [0; 55];
        id[..22].copy_from_slice(b"stele/expander-seed/v2");
        id[22] = j;
        Encoder::from_code_id(&id).expect("identity")
    }
    #[test]
    fn rejects_invalid_requests_before_generation() {
        let encoder = code(4);
        let row = [M31::ONE; 256];
        let mut calls = 0;
        let mut forbidden = |_: &[u8; 74]| {
            calls += 1;
            [0; 32]
        };
        assert_eq!(
            encoder.encode_with(&row[..255], &mut forbidden),
            Err(Error::RowShape)
        );
        assert_eq!(
            encoder.eval_with(&row, &[512], &mut forbidden),
            Err(Error::Column)
        );
        assert!(encoder
            .eval_with(&row, &[], &mut forbidden)
            .expect("empty")
            .is_empty());
        let base = code(3);
        assert_eq!(
            base.encode_with(&row[..64], &mut forbidden)
                .expect("base")
                .len(),
            128
        );
        assert_eq!(calls, 0);
    }
    #[test]
    fn rejects_capacity_overflow_and_preserves_u64_work_counts() {
        for j in 3..=15 {
            let code = code(j);
            let n = 1u64 << (2 * j);
            assert_eq!(
                code.payload::<M31>(0, 8).expect("payload"),
                (2 * n + (n - 64) / 3 + 128) * 4 + 127 * 4 + 21 * 8
            );
            assert_eq!(
                code.payload::<OM31>(7, 4).expect("payload"),
                (2 * n + (n - 64) / 3 + 128 + 7) * 32 + 127 * 4 + 21 * 4
            );
            assert_eq!(code.capacity::<OM31>(usize::MAX), Err(Error::Capacity));
        }
        let code = code(13);
        assert!(code.payload::<M31>(0, 4).expect("32-bit payload") < 1 << 31);
        assert!(64 * code.info.row_count > 1 << 32);
    }
    #[test]
    fn rejects_outer_inner_and_late_sampling_exhaustion() {
        let code = code(5);
        let row = [M31::ONE; 1024];
        for (level, kind, index, stream) in [
            (5, 0, 0u32, 0),
            (4, 0, 0, 1),
            (4, 1, 127, 0),
            (5, 1, 511, 1),
        ] {
            let mut fault = |frame: &[u8; 74]| {
                if frame[66] == level
                    && frame[67] == kind
                    && frame[68..72] == index.to_le_bytes()
                    && frame[72] == stream
                {
                    [if stream == 0 { 0 } else { 255 }; 32]
                } else {
                    hash(frame)
                }
            };
            assert_eq!(
                code.encode_with(&row, &mut fault),
                Err(Error::SamplingExhausted)
            );
            assert_eq!(row, [M31::ONE; 1024]);
        }
    }
    #[test]
    fn matches_reference_capped_block_counts_and_zero_edges() {
        let code = code(4);
        let mut calls = 0;
        let mut counted = |frame: &[u8; 74]| {
            calls += 1;
            hash(frame)
        };
        assert_eq!(
            code.encode_with(&[M31::ZERO; 256], &mut counted)
                .expect("zero"),
            alloc::vec![M31::ZERO;512]
        );
        assert_eq!(calls, 3162); // Independent materialized sampler KAT, RFC-0010 A4.
        let mut coefficient_streams = 0;
        let mut zero = |frame: &[u8; 74]| {
            if frame[72] == 1 {
                if frame[73] == 0 {
                    coefficient_streams += 1;
                }
                [0; 32]
            } else {
                hash(frame)
            }
        };
        let row = [M31::ONE; 256];
        let word = code
            .encode_with(&row, &mut zero)
            .expect("zero coefficients");
        assert_eq!(&word[..256], row);
        assert_eq!(&word[256..], [M31::ZERO; 256]);
        assert_eq!(coefficient_streams, code.info.row_count);
    }
}

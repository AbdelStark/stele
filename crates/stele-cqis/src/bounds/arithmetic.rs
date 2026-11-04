//! RFC-0025 static §§1–5: closed model arithmetic records, without proof admission.
use super::PRIME;
use alloc::vec::Vec;
mod affine;
mod attention;
mod decoding;
mod flow;
mod function;
mod norm;
mod physical;
mod request;
mod weighted;
mod word;
pub use affine::{Affine, Embedding, Weight};
pub use attention::{AttentionShape, Maximum, Rotary, Score};
pub use decoding::{Logits, Sampling, Temperature};
pub use flow::{Gated, Residual, Row};
pub use function::{Activation, Exponential};
pub use request::Request;
pub use weighted::{Normalize, Weighted};
use word::Word;

const CAPACITY: usize = 1 << 17;
const COLUMNS: usize = 269;

/// Rejected RFC-0025 derivation; RFC-0022's existing error domain is unchanged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Parameters are outside the closed schema domain.
    Parameters,
    /// Exact integer arithmetic exceeds its supported width.
    Arithmetic,
    /// A static equality side is not strictly below p/2.
    FieldBound,
    /// A bounded record, column or allocation cannot hold the result.
    Capacity,
    /// Supplied bytes differ from the complete regenerated expected record.
    Encoding,
    /// The worst-case scaled score reaches or exceeds 2^31.
    ScoreBound,
    /// A full 1024-slot rounded block exceeds 32767.
    BlockBound,
}

fn field_bound(value: u64) -> Result<u32, Error> {
    super::field_bound(value).map_err(|e| match e {
        super::Error::Parameters => Error::Parameters,
        super::Error::Arithmetic => Error::Arithmetic,
        super::Error::FieldBound => Error::FieldBound,
        super::Error::Capacity => Error::Capacity,
        super::Error::Encoding => Error::Encoding,
    })
}

/// Complete canonical metadata derived from separate checked parameters.
/// This neither authenticates parameters nor enforces their arithmetic relations.
/// ```compile_fail
/// fn change(r: &mut stele_cqis::bounds::arithmetic::Record) { r.bytes[0] = 1; }
/// ```
#[derive(Debug, Eq, PartialEq)]
pub struct Record {
    bytes: Vec<u8>,
}
impl Record {
    /// Full canonical frame, retaining every high zero and boundary carry.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Compare every byte to the regenerated expected record.
    pub fn validate_encoding(&self, raw: &[u8]) -> Result<(), Error> {
        if raw != self.as_bytes() {
            return Err(Error::Encoding);
        }
        Ok(())
    }
}

// Closed schema implementations alone can supply terms; no generic public API.
type Term = (u32, Word, Word);
fn term(a: impl Into<Word>, b: impl Into<Word>) -> Term {
    (1, a.into(), b.into())
}

struct Builder {
    bytes: Vec<u8>,
    bits: u8,
    roles: u8,
    written: u8,
}
impl Builder {
    fn new(
        schema: u8,
        params: &[u8],
        bits: u8,
        scalars: &[Word],
        shifts: &[i16],
        roles: u8,
    ) -> Result<Self, Error> {
        if !matches!(bits, 4 | 8) {
            return Err(Error::Parameters);
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(CAPACITY)
            .map_err(|_| Error::Capacity)?;
        let mut out = Self {
            bytes,
            bits,
            roles,
            written: 0,
        };
        out.append(b"stele/v0.1/cqis/model-arithmetic")?;
        out.append(&1u32.to_le_bytes())?;
        out.append(&[schema])?;
        out.append(
            &u16::try_from(params.len())
                .map_err(|_| Error::Capacity)?
                .to_le_bytes(),
        )?;
        out.append(params)?;
        out.append(&(PRIME as u32).to_le_bytes())?;
        out.append(&[
            bits,
            u8::try_from(scalars.len()).map_err(|_| Error::Capacity)?,
        ])?;
        for value in scalars {
            out.append(&value.bytes())?;
        }
        out.append(&[u8::try_from(shifts.len()).map_err(|_| Error::Capacity)?])?;
        for shift in shifts {
            out.append(&shift.to_le_bytes())?;
        }
        out.append(&[roles])?;
        Ok(out)
    }
    fn append(&mut self, raw: &[u8]) -> Result<(), Error> {
        self.bytes
            .len()
            .checked_add(raw.len())
            .filter(|n| *n <= CAPACITY)
            .ok_or(Error::Capacity)?;
        self.bytes.extend_from_slice(raw);
        Ok(())
    }
    fn column(&mut self, terms: &[Term]) -> Result<(), Error> {
        if terms.is_empty() || terms.len() > 4 || self.written >= self.roles {
            return Err(Error::Capacity);
        }
        let mut z = Word::from(0);
        let mut size = 1;
        for &(count, a, c) in terms {
            if count == 0 {
                return Err(Error::Parameters);
            }
            z = z.add(a.mul(c)?.mul(u64::from(count).into())?)?;
            size = size.max(a.width(self.bits) + c.width(self.bits) - 1);
        }
        size = size.max(z.width(self.bits));
        if size > COLUMNS {
            return Err(Error::Capacity);
        }
        let mut raw = [0u64; COLUMNS];
        for &(count, a, c) in terms {
            for i in 0..a.width(self.bits) {
                for j in 0..c.width(self.bits) {
                    let product = u64::from(count)
                        * u64::from(a.cap(i, self.bits))
                        * u64::from(c.cap(j, self.bits));
                    raw[i + j] = raw[i + j].checked_add(product).ok_or(Error::Arithmetic)?;
                }
            }
        }
        let mut carries = [0u32; COLUMNS + 1];
        let mut left = [0u32; COLUMNS];
        let mut right = [0u32; COLUMNS];
        let radix = 1u64 << self.bits;
        for i in 0..size {
            let lhs = raw[i]
                .checked_add(u64::from(carries[i]))
                .ok_or(Error::Arithmetic)?;
            let carry = if i + 1 == size { 0 } else { lhs / radix };
            let rhs = u64::from(z.cap(i, self.bits))
                .checked_add(radix * carry)
                .ok_or(Error::Arithmetic)?;
            left[i] = field_bound(lhs)?;
            right[i] = field_bound(rhs)?;
            carries[i + 1] = u32::try_from(carry).map_err(|_| Error::Arithmetic)?;
        }
        self.append(&[self.written + 1, terms.len() as u8])?;
        for &(count, a, c) in terms {
            self.append(&count.to_le_bytes())?;
            self.append(&a.bytes())?;
            self.append(&c.bytes())?;
            for value in [a, c] {
                self.append(&(value.width(self.bits) as u16).to_le_bytes())?;
            }
            for value in [a, c] {
                for i in 0..value.width(self.bits) {
                    self.append(&[value.cap(i, self.bits)])?;
                }
            }
        }
        self.append(&z.bytes())?;
        self.append(&(size as u16).to_le_bytes())?;
        for i in 0..size {
            self.append(&[z.cap(i, self.bits)])?;
        }
        for values in [&carries[..size + 1], &left[..size], &right[..size]] {
            for value in values {
                self.append(&value.to_le_bytes())?;
            }
        }
        self.written += 1;
        Ok(())
    }
    fn rounding(&mut self, maximum: Word, divisor: Word) -> Result<(), Error> {
        let quotient = maximum.quotient_cap(divisor, 32768)?;
        let remainder = divisor.sub(1.into())?;
        self.column(&[term(maximum.mul(2.into())?, 1), term(maximum, 2)])?;
        self.column(&[term(maximum, 1), term(maximum, 1)])?;
        self.column(&[term(quotient, divisor)])?;
        self.column(&[term(quotient.mul(divisor)?, 1), term(remainder, 1)])?;
        self.column(&[term(remainder, 1), term(remainder, 1), term(1, 1)])?;
        self.column(&[term(remainder, 2)])?;
        self.column(&[
            term(remainder.mul(2.into())?, 1),
            term(remainder, 1),
            term(1, 1),
        ])?;
        self.column(&[term(divisor, 1), term(remainder, 1)])
    }
    fn finish(self) -> Result<Record, Error> {
        if self.written != self.roles {
            return Err(Error::Capacity);
        }
        Ok(Record { bytes: self.bytes })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_unfaithful_columns_and_incomplete_or_oversized_frames() {
        let mut b = Builder::new(1, &[], 8, &[], &[], 1).expect("builder");
        assert_eq!(
            b.column(&[(16385, 32768.into(), 32768.into())]),
            Err(Error::FieldBound)
        );
        assert_eq!(b.column(&[(0, 1.into(), 1.into())]), Err(Error::Parameters));
        assert_eq!(b.column(&[]), Err(Error::Capacity));
        assert_eq!(
            b.column(&[term(Word::power(2303).expect("wide"), 0)]),
            Err(Error::Capacity)
        );
        assert_eq!(b.written, 0);
        assert_eq!(b.finish(), Err(Error::Capacity));
        for bits in [4, 8] {
            let mut b = Builder::new(1, &[], bits, &[], &[], 1).expect("builder");
            // Zero products retain all 269 source columns and explicit high zeros.
            b.column(&[term(Word::power(i16::from(bits) * 268).expect("wide"), 0)])
                .expect("zero product");
            let r = b.finish().expect("complete");
            assert!(r.as_bytes().ends_with(&[0; 4]));
        }
        let mut b = Builder::new(1, &[], 8, &[], &[], 1).expect("builder");
        b.column(&[(16384, 32768.into(), 32768.into())])
            .expect("strict field boundary");
        assert_eq!(b.column(&[term(1, 1)]), Err(Error::Capacity));
        let before = b.bytes.len();
        assert_eq!(b.append(&[0; CAPACITY]), Err(Error::Capacity));
        assert_eq!(b.bytes.len(), before);
        assert!(b.finish().is_ok());
    }
}

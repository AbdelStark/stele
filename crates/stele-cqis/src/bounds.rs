//! RFC-0022 §§2-6: immutable static records, without source or proof admission.
use crate::{functions::Descriptor, Format, Requant};
mod schema;
mod wide;
use wide::U160;

const PRIME: u64 = (1 << 31) - 1;
const CAPACITY: usize = 8192;

/// A rejected static derivation or supplied canonical record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The checked function is not one of the closed record schemas.
    Parameters,
    /// Exact integer arithmetic exceeds its supported width.
    Arithmetic,
    /// A static equality side is not strictly below p/2.
    FieldBound,
    /// A bounded record or column buffer cannot hold the result.
    Capacity,
    /// Supplied bytes differ from the complete regenerated expected record.
    Encoding,
}

/// Complete canonical bounds derived only from separate checked parameters.
/// This does not authenticate parameters or enforce any proof relation/range.
/// ```compile_fail
/// fn change(record: &mut stele_cqis::bounds::Record) { record.bytes[0]=1; }
/// ```
#[derive(Debug, Eq, PartialEq)]
pub struct Record {
    bytes: [u8; CAPACITY],
    length: usize,
}

impl Record {
    /// Derive RFC-0022 §2.2 for an existing scalar configuration/target format.
    pub fn requant(config: Requant, format: Format) -> Result<Self, Error> {
        schema::requant(config, format)
    }
    /// Derive RFC-0022 §2.3; a different checked function rejects.
    pub fn rmsnorm(function: Descriptor) -> Result<Self, Error> {
        schema::rmsnorm(function)
    }
    /// Full immutable canonical bytes, including every scalar and column bound.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.length]
    }
    /// Validate against this generated expected record, without allocation.
    pub fn validate_encoding(&self, raw: &[u8]) -> Result<(), Error> {
        if raw != self.as_bytes() {
            return Err(Error::Encoding);
        }
        Ok(())
    }
    fn append(&mut self, raw: &[u8]) -> Result<(), Error> {
        let end = self.length.checked_add(raw.len()).ok_or(Error::Capacity)?;
        let target = self
            .bytes
            .get_mut(self.length..end)
            .ok_or(Error::Capacity)?;
        target.copy_from_slice(raw);
        self.length = end;
        Ok(())
    }
    fn header(
        kind: u8,
        params: &[u8],
        scalars: &[U160],
        shifts: &[i16],
        roles: u8,
    ) -> Result<Self, Error> {
        let mut out = Self {
            bytes: [0; CAPACITY],
            length: 0,
        };
        out.append(b"stele/v0.1/cqis/bounds")?;
        out.append(&1u32.to_le_bytes())?;
        out.append(&[kind])?;
        out.append(
            &u16::try_from(params.len())
                .map_err(|_| Error::Capacity)?
                .to_le_bytes(),
        )?;
        out.append(params)?;
        out.append(&(PRIME as u32).to_le_bytes())?;
        out.append(&[8, u8::try_from(scalars.len()).map_err(|_| Error::Capacity)?])?;
        for scalar in scalars {
            out.append(&scalar.bytes())?;
        }
        out.append(&[u8::try_from(shifts.len()).map_err(|_| Error::Capacity)?])?;
        for shift in shifts {
            out.append(&shift.to_le_bytes())?;
        }
        out.append(&[roles])?;
        Ok(out)
    }
    fn column(&mut self, id: u8, count: u32, a: U160, b: U160) -> Result<(), Error> {
        let z = a.mul(b)?.mul(u64::from(count).into())?;
        // Private canonical u160 widths are in 1..=20 (RFC-0022 §3).
        let la = a.width();
        let lb = b.width();
        let k = (la + lb - 1).max(z.width());
        if count == 0 || k > 20 {
            return Err(Error::Capacity);
        }
        let mut carries = [0u32; 21];
        let mut lhs = [0u32; 20];
        let mut rhs = [0u32; 20];
        for column in 0..k {
            let mut raw = 0u64;
            for i in 0..la {
                if let Some(j) = column.checked_sub(i).filter(|j| *j < lb) {
                    raw = raw
                        .checked_add(u64::from(a.cap(i)) * u64::from(b.cap(j)))
                        .ok_or(Error::Arithmetic)?;
                }
            }
            let left = raw
                .checked_mul(u64::from(count))
                .and_then(|v| v.checked_add(u64::from(carries[column])))
                .ok_or(Error::Arithmetic)?;
            let carry = if column + 1 < k { left / 256 } else { 0 };
            let right = carry
                .checked_mul(256)
                .and_then(|v| v.checked_add(u64::from(z.cap(column))))
                .ok_or(Error::Arithmetic)?;
            lhs[column] = field_bound(left)?;
            rhs[column] = field_bound(right)?;
            carries[column + 1] = u32::try_from(carry).map_err(|_| Error::Arithmetic)?;
        }
        self.append(&[id])?;
        self.append(&count.to_le_bytes())?;
        for value in [a, b, z] {
            self.append(&value.bytes())?;
        }
        self.append(&[la as u8, lb as u8, k as u8])?;
        for (value, length) in [(a, la), (b, lb), (z, k)] {
            for i in 0..length {
                self.append(&[value.cap(i)])?;
            }
        }
        for values in [&carries[..k + 1], &lhs[..k], &rhs[..k]] {
            for value in values {
                self.append(&value.to_le_bytes())?;
            }
        }
        Ok(())
    }
}

fn field_bound(value: u64) -> Result<u32, Error> {
    if value.checked_mul(2).ok_or(Error::Arithmetic)? >= PRIME {
        return Err(Error::FieldBound);
    }
    u32::try_from(value).map_err(|_| Error::Arithmetic)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_field_endpoints_capacity_and_arithmetic_overflow() {
        assert_eq!(field_bound((PRIME - 1) / 2), Ok(((PRIME - 1) / 2) as u32));
        assert_eq!(field_bound(PRIME.div_ceil(2)), Err(Error::FieldBound));
        assert_eq!(field_bound(u64::MAX), Err(Error::Arithmetic));
        let mut r = Record {
            bytes: [0; CAPACITY],
            length: CAPACITY,
        };
        assert_eq!(r.append(&[1]), Err(Error::Capacity));
        assert_eq!(r.length, CAPACITY);
        assert_eq!(r.bytes, [0; CAPACITY]);
        r.length = 0;
        assert_eq!(
            r.column(1, 16385, 32768.into(), 32768.into()),
            Err(Error::FieldBound)
        );
        assert_eq!(r.column(1, 0, 1.into(), 1.into()), Err(Error::Capacity));
        let wide = U160::from(1).shl(159).expect("wide");
        assert_eq!(r.column(1, 1, wide, 2.into()), Err(Error::Arithmetic));
        // Zero product still requires width(A)+width(B)-1 columns.
        assert_eq!(r.column(1, 1, wide, 0.into()), Ok(()));
    }
}

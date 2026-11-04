//! RFC-0025 §2.1/conversion §§1–2: exact finite IEEE dyadics and minimal scales.
use crate::model::Error;
use core::cmp::Ordering;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Scalar {
    negative: bool,
    magnitude: u64,
    power: i16,
}
impl Scalar {
    pub const ZERO: Self = Self {
        negative: false,
        magnitude: 0,
        power: 0,
    };
    pub fn width(dtype: u8) -> Result<u64, Error> {
        match dtype {
            1 | 2 => Ok(2),
            3 => Ok(4),
            4 => Ok(8),
            _ => Err(Error::SourceDtype),
        }
    }
    pub fn decode(dtype: u8, raw: &[u8]) -> Result<Self, Error> {
        let (eb, fb) = match dtype {
            1 => (5, 10),
            2 => (8, 7),
            3 => (8, 23),
            4 => (11, 52),
            _ => return Err(Error::SourceDtype),
        };
        let size = Self::width(dtype)? as usize;
        if raw.len() != size {
            return Err(Error::SourceShape);
        }
        let mut bytes = [0; 8];
        bytes[..size].copy_from_slice(raw);
        let word = u64::from_le_bytes(bytes);
        let exponent = (word >> fb) & ((1 << eb) - 1);
        if exponent == (1 << eb) - 1 {
            return Err(Error::SourceNonfinite);
        }
        let mut magnitude = word & ((1 << fb) - 1);
        let bias = (1 << (eb - 1)) - 1;
        let mut power = if exponent == 0 {
            1 - bias - fb
        } else {
            magnitude += 1 << fb;
            exponent as i16 - bias - fb
        };
        if magnitude == 0 {
            return Ok(Self::ZERO);
        }
        let trailing = magnitude.trailing_zeros();
        magnitude >>= trailing;
        power += trailing as i16;
        Ok(Self {
            negative: word >> (size * 8 - 1) != 0,
            magnitude,
            power,
        })
    }
    fn compare(self, other: Self) -> Ordering {
        if self.magnitude == 0 || other.magnitude == 0 {
            return self.magnitude.cmp(&other.magnitude);
        }
        let left = 64 - self.magnitude.leading_zeros();
        let right = 64 - other.magnitude.leading_zeros();
        (i32::from(self.power) + left as i32)
            .cmp(&(i32::from(other.power) + right as i32))
            // Equal top-bit positions: align the <=53 exact bits at bit 63.
            .then_with(|| {
                (self.magnitude << self.magnitude.leading_zeros())
                    .cmp(&(other.magnitude << other.magnitude.leading_zeros()))
            })
    }
    pub fn maximum(self, other: Self) -> Self {
        let mut value = if self.compare(other) == Ordering::Less {
            other
        } else {
            self
        };
        value.negative = false;
        value
    }
    pub fn exponent(self, bits: u8) -> Result<i16, Error> {
        let bound = u64::from(limit(bits)?) * 65535;
        if self.magnitude == 0 {
            return Ok(0);
        }
        let mut e = self.power + (64 - self.magnitude.leading_zeros()) as i16
            - (64 - bound.leading_zeros()) as i16;
        if self.compare(Self {
            negative: false,
            magnitude: bound,
            power: e,
        }) == Ordering::Greater
        {
            e += 1;
        }
        if !(-1099..=1024).contains(&e) {
            return Err(Error::ScaleExponent);
        }
        Ok(e)
    }
    pub fn mantissa(self, exponent: i16, bits: u8) -> Result<u16, Error> {
        let (q, fraction, _) =
            self.ratio(i32::from(self.power) - i32::from(exponent), limit(bits)?)?;
        let value = q
            .checked_add(u64::from(fraction))
            .ok_or(Error::ConversionOverflow)?
            .max(1);
        u16::try_from(value).map_err(|_| Error::ScaleMantissa)
    }
    pub fn weight(self, exponent: i16, mantissa: u16, bits: u8) -> Result<i16, Error> {
        let q = limit(bits)?;
        self.round(i32::from(self.power) - i32::from(exponent), mantissa, q, q)
    }
    pub fn vector(self, fraction: u8) -> Result<i16, Error> {
        if fraction > 30 {
            return Err(Error::Units);
        }
        self.round(i32::from(self.power) + i32::from(fraction), 1, 32767, 32768)
    }
    fn round(
        self,
        shift: i32,
        denominator: u16,
        positive: u16,
        negative: u16,
    ) -> Result<i16, Error> {
        let (q, _, half) = self.ratio(shift, denominator)?;
        let value = q
            .checked_add(u64::from(half))
            .ok_or(Error::ConversionOverflow)?;
        let bound = if self.negative { negative } else { positive };
        if value > u64::from(bound) {
            return Err(Error::ConversionOverflow);
        }
        let signed = if self.negative {
            -(value as i32)
        } else {
            value as i32
        };
        i16::try_from(signed).map_err(|_| Error::ConversionOverflow)
    }
    /// Floor quotient, nonzero remainder, and remainder >= half denominator.
    /// Numerators have <=53 bits; denominators start at <=16 bits. A positive
    /// shift beyond 64 numerator bits necessarily overflows every allowed output.
    /// A denominator with >numerator_bits+1 bits is strictly above twice n, so
    /// rounding is zero while ceiling is one. Other divisions fit u64 exactly.
    fn ratio(self, shift: i32, denominator: u16) -> Result<(u64, bool, bool), Error> {
        if denominator == 0 {
            return Err(Error::ScaleMantissa);
        }
        if self.magnitude == 0 {
            return Ok((0, false, false));
        }
        let bits = 64 - self.magnitude.leading_zeros();
        let (n, d) = if shift >= 0 {
            if i64::from(bits) + i64::from(shift) > 64 {
                return Err(Error::ConversionOverflow);
            }
            (self.magnitude << shift, u64::from(denominator))
        } else {
            let k = shift.unsigned_abs();
            let dbits = 16 - denominator.leading_zeros();
            if u64::from(dbits) + u64::from(k) > u64::from(bits) + 1 {
                return Ok((0, true, false));
            }
            (self.magnitude, u64::from(denominator) << k)
        };
        let (q, r) = (n / d, n % d);
        // In both branches d<=2^54, so doubling a remainder cannot overflow.
        Ok((q, r != 0, 2 * r >= d))
    }
}
fn limit(bits: u8) -> Result<u16, Error> {
    match bits {
        4 => Ok(7),
        8 => Ok(127),
        _ => Err(Error::Physical),
    }
}

#[cfg(test)]
#[path = "scalar_tests.rs"]
mod tests;

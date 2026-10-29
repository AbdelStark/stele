//! RFC-0021 §§2.2,3: exact sigmoid/SiLU/softcap with strict endpoint rounding.
use super::{exp, natural::Natural, Descriptor, Error, Kind};
use core::cmp::Ordering;

// An endpoint is an exact signed rational. A negative zero has the same rounded
// value as zero; it cannot be a half-integer. All owned arithmetic is fallible.
struct Endpoint {
    negative: bool,
    numerator: Natural,
    denominator: Natural,
}

impl Endpoint {
    fn rounded(&self, side: i8) -> Result<i32, Error> {
        if !matches!(side, -1..=1) {
            return Err(Error::Interval);
        }
        let (q, r) = self.numerator.div_rem(&self.denominator)?;
        let comparison = r.shl(1)?.cmp(&self.denominator);
        let mut magnitude = q.to_u32()?;
        if comparison != Ordering::Less {
            magnitude = magnitude.checked_add(1).ok_or(Error::Interval)?;
        }
        // RFC-0021 §3: exclude a positive half from below or a negative half
        // from above. Closing a finite exponential tail here changes the function.
        if comparison == Ordering::Equal
            && ((!self.negative && side < 0) || (self.negative && side > 0))
        {
            magnitude = magnitude.checked_sub(1).ok_or(Error::Interval)?;
        }
        let value = i32::try_from(magnitude).map_err(|_| Error::Interval)?;
        if self.negative {
            value.checked_neg().ok_or(Error::Interval)
        } else {
            Ok(value)
        }
    }
}

fn strict_exp(n: &Natural, d: &Natural, bits: usize) -> Result<(Natural, Natural, usize), Error> {
    if !matches!(bits, 32 | 64 | 128 | 256) {
        return Err(Error::Precision);
    }
    if d.is_zero() {
        return Err(Error::Interval);
    }
    if n.cmp(&d.mul_u64(bits as u64)?) != Ordering::Less {
        return Ok((Natural::zero(), Natural::from_u64(1)?, bits));
    }
    exp::enclosure_ratio(n, d, bits)
}

fn interval(d: &Descriptor, t: i32, bits: usize) -> Result<(Endpoint, Endpoint), Error> {
    let p = d.parameters();
    let magnitude = u64::from(t.unsigned_abs());
    let cap = if d.kind == Kind::Softcap {
        u64::from(u16::from_le_bytes([p[2], p[3]]))
    } else {
        1
    };
    let cap_f = if d.kind == Kind::Softcap { p[4] } else { 0 };
    let mut numerator = Natural::from_u64(magnitude)?;
    let mut denominator = Natural::from_u64(1)?.shl(usize::from(p[0]))?;
    if d.kind == Kind::Softcap {
        numerator = numerator.shl(usize::from(cap_f) + 1)?;
        denominator = denominator.mul_u64(cap)?;
    }
    let (lo, hi, precision) = strict_exp(&numerator, &denominator, bits)?;
    let unit = Natural::from_u64(1)?.shl(precision)?;
    let endpoint = |z: &Natural| -> Result<Endpoint, Error> {
        let mut den = unit.add(z)?;
        let num = match d.kind {
            Kind::Sigmoid if t >= 0 => unit.try_clone()?,
            Kind::Sigmoid => z.try_clone()?,
            Kind::Silu => {
                den = den.shl(usize::from(p[0]))?;
                (if t >= 0 { &unit } else { z }).mul_u64(magnitude)?
            }
            Kind::Softcap => {
                den = den.shl(usize::from(cap_f))?;
                unit.sub(z)?.mul_u64(cap)?
            }
            _ => return Err(Error::Parameters),
        };
        Ok(Endpoint {
            negative: t < 0 && d.kind != Kind::Sigmoid,
            numerator: num.shl(usize::from(p[1]))?,
            denominator: den,
        })
    };
    // Positive sigmoid/SiLU/softcap and negative SiLU decrease with z;
    // negative sigmoid and negative softcap increase with z.
    if t >= 0 || d.kind == Kind::Silu {
        Ok((endpoint(&hi)?, endpoint(&lo)?))
    } else {
        Ok((endpoint(&lo)?, endpoint(&hi)?))
    }
}

pub(super) fn certify(d: &Descriptor, t: i32) -> Result<i32, Error> {
    if !matches!(d.kind, Kind::Sigmoid | Kind::Silu | Kind::Softcap) || i16::try_from(t).is_err() {
        return Err(Error::Parameters);
    }
    for bits in [32, 64, 128, 256] {
        let (low, high) = interval(d, t, bits)?;
        let strict = i8::from(t != 0);
        let a = low.rounded(strict)?;
        let b = high.rounded(-strict)?;
        if a == b {
            return i16::try_from(a).map(i32::from).map_err(|_| Error::Overflow);
        }
    }
    Err(Error::Precision)
}

#[cfg(test)]
#[path = "activation_tests.rs"]
mod tests;

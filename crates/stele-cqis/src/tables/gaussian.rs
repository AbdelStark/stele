//! RFC-0021 §§2.2,3: Machin normalizer and distinct exact/tanh GeLU certification.
use super::{
    activation::{strict_exp, Endpoint},
    natural::Natural,
    Descriptor, Error, Kind,
};
use core::cmp::Ordering;

#[path = "gaussian_exact.rs"]
mod exact;

struct Ratio {
    n: Natural,
    d: Natural,
}

fn atan(k: u64, bits: usize) -> Result<(Ratio, Ratio), Error> {
    if !matches!(k, 5 | 239) || !(40..=280).contains(&bits) {
        return Err(Error::Parameters);
    }
    let one = Natural::from_u64(1)?;
    let mut partial = one.try_clone()?;
    let mut divisor = Natural::from_u64(k)?;
    let mut power = one;
    for step in 1..=512u64 {
        // D_n = k^(2n+1) product_{j=1..n}(2j+1). The new Taylor term's
        // numerator is product_{j=1..n-1}(2j+1); no rational approximation.
        let factor = k
            .checked_mul(k)
            .and_then(|v| v.checked_mul(2 * step + 1))
            .ok_or(Error::Interval)?;
        let next_divisor = divisor.mul_u64(factor)?;
        power = power.mul_u64(2 * step - 1)?;
        let scaled = partial.mul_u64(factor)?;
        let next = if step % 2 == 1 {
            scaled.sub(&power)?
        } else {
            scaled.add(&power)?
        };
        if power.shl(bits)?.cmp(&next_divisor) == Ordering::Less {
            let previous = Ratio {
                n: partial,
                d: divisor,
            };
            let current = Ratio {
                n: next,
                d: next_divisor,
            };
            return Ok(if step % 2 == 1 {
                (current, previous)
            } else {
                (previous, current)
            });
        }
        partial = next;
        divisor = next_divisor;
    }
    Err(Error::Precision)
}

fn machin(a: &Ratio, b: &Ratio) -> Result<Ratio, Error> {
    let n =
        a.n.mul(&b.d)?
            .mul_u64(16)?
            .sub(&b.n.mul(&a.d)?.mul_u64(4)?)?;
    let d = a.d.mul(&b.d)?;
    if n.cmp(&d.mul_u64(3)?) != Ordering::Greater || n.cmp(&d.mul_u64(4)?) != Ordering::Less {
        return Err(Error::Interval);
    }
    Ok(Ratio { n, d })
}

fn root_floor(pi: &Ratio, bits: usize) -> Result<Natural, Error> {
    // sqrt(1/(2*pi))*2^bits is < 2^bits. Test each binary root digit;
    // the final exact inequalities are checked against the original rational.
    let numerator = pi.d.shl(2 * bits)?;
    let denominator = pi.n.mul_u64(2)?;
    let quotient = numerator.div_rem(&denominator)?.0;
    let mut root = Natural::zero();
    let one = Natural::from_u64(1)?;
    for bit in (0..bits).rev() {
        let candidate = root.add(&one.shl(bit)?)?;
        if candidate.mul(&candidate)?.cmp(&quotient) != Ordering::Greater {
            root = candidate;
        }
    }
    let next = root.add(&one)?;
    if root.mul(&root)?.mul(&denominator)?.cmp(&numerator) == Ordering::Greater
        || next.mul(&next)?.mul(&denominator)?.cmp(&numerator) != Ordering::Greater
    {
        return Err(Error::Interval);
    }
    Ok(root)
}

struct Normalizer {
    low: Natural,
    high: Natural,
    precision: usize,
}

fn normalizer(bits: usize) -> Result<Normalizer, Error> {
    if !(32..=272).contains(&bits) {
        return Err(Error::Precision);
    }
    let (a0, a1) = atan(5, bits + 8)?;
    let (b0, b1) = atan(239, bits + 8)?;
    let low_pi = machin(&a0, &b1)?;
    let high_pi = machin(&a1, &b0)?;
    if low_pi.n.mul(&high_pi.d)?.cmp(&high_pi.n.mul(&low_pi.d)?) != Ordering::Less {
        return Err(Error::Interval);
    }
    let low = root_floor(&high_pi, bits)?;
    let high = root_floor(&low_pi, bits)?.add(&Natural::from_u64(1)?)?;
    if low.is_zero()
        || low.cmp(&high) != Ordering::Less
        || high.shl(1)?.cmp(&Natural::from_u64(1)?.shl(bits)?) != Ordering::Less
    {
        return Err(Error::Interval);
    }
    Ok(Normalizer {
        low,
        high,
        precision: bits,
    })
}

// Four immutable exact normalizers are owned by a single table generation.
// Lazy construction preserves the reference precision order and returns errors
// before exposing a table. Cache state never changes an entry or an identity.
pub(super) struct Gaussian {
    normalizers: [Option<Normalizer>; 4],
}

impl Gaussian {
    pub(super) fn new() -> Self {
        Self {
            normalizers: core::array::from_fn(|_| None),
        }
    }

    pub(super) fn certify(&mut self, d: &Descriptor, t: i32) -> Result<i32, Error> {
        if !matches!(d.kind, Kind::Gelu | Kind::GeluTanh) || i16::try_from(t).is_err() {
            return Err(Error::Parameters);
        }
        if t == 0 {
            return Ok(0);
        }
        for (i, bits) in [32, 64, 128, 256].into_iter().enumerate() {
            let needs_normalizer = d.kind == Kind::GeluTanh
                || u64::from(t.unsigned_abs()) < (8u64 << d.parameters()[0]);
            if needs_normalizer && self.normalizers[i].is_none() {
                self.normalizers[i] = Some(normalizer(bits + 8)?);
            }
            let c = self.normalizers[i].as_ref();
            let (low, high) = if d.kind == Kind::Gelu {
                exact::interval(d, t, bits, c)?
            } else {
                tanh_interval(d, t, bits, c.ok_or(Error::Interval)?)?
            };
            let a = low.rounded(1)?;
            let b = high.rounded(-1)?;
            if a == b {
                return i16::try_from(a).map(i32::from).map_err(|_| Error::Overflow);
            }
        }
        Err(Error::Precision)
    }
}

fn tanh_interval(
    d: &Descriptor,
    t: i32,
    bits: usize,
    c: &Normalizer,
) -> Result<(Endpoint, Endpoint), Error> {
    let p = d.parameters();
    let a = Natural::from_u64(u64::from(t.unsigned_abs()))?;
    let denominator = Natural::from_u64(1)?.shl(usize::from(p[0]))?;
    // v = a/d + (8943/200000)*(a/d)^3, with the specified exact constant.
    let vn = a.mul(
        &denominator
            .mul(&denominator)?
            .mul_u64(200000)?
            .add(&a.mul(&a)?.mul_u64(8943)?)?,
    )?;
    let vd = denominator
        .mul(&denominator)?
        .mul(&denominator)?
        .mul_u64(200000)?;
    let exponent_d = vd.shl(c.precision)?;
    let (z0, _, p0) = strict_exp(&vn.mul(&c.high)?.shl(2)?, &exponent_d, bits)?;
    let (_, z1, p1) = strict_exp(&vn.mul(&c.low)?.shl(2)?, &exponent_d, bits)?;
    if z0.shl(p1)?.cmp(&z1.shl(p0)?) != Ordering::Less
        || z1.cmp(&Natural::from_u64(1)?.shl(p1)?) == Ordering::Greater
    {
        return Err(Error::Interval);
    }
    let endpoint = |z: Natural, precision: usize| -> Result<Endpoint, Error> {
        let unit = Natural::from_u64(1)?.shl(precision)?;
        let den = unit.add(&z)?.mul(&denominator)?;
        let num = if t > 0 { unit } else { z };
        Ok(Endpoint {
            negative: t < 0,
            numerator: num.mul(&a)?.shl(usize::from(p[1]))?,
            denominator: den,
        })
    };
    // q=z/(1+z); both a(1-q) and -a*q decrease as z increases.
    Ok((endpoint(z1, p1)?, endpoint(z0, p0)?))
}

#[cfg(test)]
#[path = "gaussian_tests.rs"]
mod tests;

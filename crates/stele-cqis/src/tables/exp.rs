//! RFC-0021 §3: exact alternating-series exp enclosures and fixed rounding schedule.
use super::{natural::Natural, Error};
use core::cmp::Ordering;

fn enclosure(n: u64, f: u8, bits: usize) -> Result<(Natural, Natural, usize), Error> {
    if n > 1 << 31 || f > 30 {
        return Err(Error::Parameters);
    }
    enclosure_ratio(&Natural::from_u64(n)?, &Natural::from_u64(1u64 << f)?, bits)
}

pub(super) fn enclosure_ratio(
    n: &Natural,
    d: &Natural,
    bits: usize,
) -> Result<(Natural, Natural, usize), Error> {
    if d.is_zero() {
        return Err(Error::Interval);
    }
    if !matches!(bits, 32 | 64 | 128 | 256) {
        return Err(Error::Precision);
    }
    let one = Natural::from_u64(1)?;
    let mut denominator = d.try_clone()?;
    if n.cmp(&d.mul_u64(bits as u64 + 1)?) != Ordering::Less {
        return Ok((Natural::zero(), one, bits + 1));
    }
    let mut squarings = 0usize;
    let twice = n.shl(1)?;
    while twice.cmp(&denominator) == Ordering::Greater {
        denominator = denominator.shl(1)?;
        squarings = squarings.checked_add(1).ok_or(Error::Interval)?;
    }
    let precision = bits
        .checked_add(squarings)
        .and_then(|b| b.checked_add(4))
        .ok_or(Error::Interval)?;
    let unit = one.shl(precision)?;
    if n.is_zero() {
        return Ok((unit.try_clone()?, unit, precision));
    }
    let (mut partial, mut divisor, mut power) =
        (one.try_clone()?, one.try_clone()?, one.try_clone()?);
    for step in 1..=512u64 {
        let factor = denominator.mul_u64(step)?;
        let next_divisor = divisor.mul(&factor)?;
        power = power.mul(n)?;
        let scaled = partial.mul(&factor)?;
        let next = if step % 2 == 1 {
            scaled.sub(&power)?
        } else {
            scaled.add(&power)?
        };
        // Common denominator denominator^step*step! gives the exact partial
        // sums. Adjacent bounds differ by n^step/(denominator^step*step!), with no gcd
        // or approximate per-term rounding. This is the reference stopping rule.
        if power.shl(precision)?.cmp(&next_divisor) != Ordering::Greater {
            let (lower, ld, upper, ud) = if step % 2 == 1 {
                (&next, &next_divisor, &partial, &divisor)
            } else {
                (&partial, &divisor, &next, &next_divisor)
            };
            let mut low = lower.shl(precision)?.div_rem(ld)?.0;
            let (q, r) = upper.shl(precision)?.div_rem(ud)?;
            let mut high = if r.is_zero() { q } else { q.add(&one)? };
            let ceil_bias = unit.sub(&one)?;
            for _ in 0..squarings {
                low = low.mul(&low)?.shr(precision)?;
                high = high.mul(&high)?.add(&ceil_bias)?.shr(precision)?;
            }
            if low.cmp(&high) == Ordering::Greater
                || high.cmp(&unit) == Ordering::Greater
                || high.sub(&low)?.shl(bits)?.cmp(&unit) != Ordering::Less
            {
                return Err(Error::Interval);
            }
            return Ok((low, high, precision));
        }
        partial = next;
        divisor = next_divisor;
    }
    Err(Error::Precision)
}

fn rounded(value: &Natural, e: u8, precision: usize) -> Result<u32, Error> {
    let bias = Natural::from_u64(1)?.shl(precision.checked_sub(1).ok_or(Error::Interval)?)?;
    value
        .shl(usize::from(e))?
        .add(&bias)?
        .shr(precision)?
        .to_u32()
}

pub(super) fn certify(n: u64, f: u8, e: u8) -> Result<i32, Error> {
    if n > 1 << 31 || f > 30 || e > 14 {
        return Err(Error::Parameters);
    }
    for bits in [32, 64, 128, 256] {
        let (low, high, precision) = enclosure(n, f, bits)?;
        let a = rounded(&low, e, precision)?;
        let b = rounded(&high, e, precision)?;
        if a == b {
            return i32::try_from(a).map_err(|_| Error::Interval);
        }
    }
    Err(Error::Precision)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    #[test]
    fn matches_reference_ten_thousand_exact_exp_entries() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../research/cqis-tables/native-exp-entries.json"
        ))
        .expect("two exact Python methods");
        let hex = vectors["records"].as_str().expect("records");
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
            .collect();
        assert_eq!(bytes.len(), 10000 * 8);
        for row in bytes.chunks_exact(8) {
            let n = u64::from(u32::from_le_bytes(row[..4].try_into().expect("n")));
            let expected = i32::from(u16::from_le_bytes(row[6..8].try_into().expect("value")));
            assert_eq!(certify(n, row[4], row[5]), Ok(expected));
        }
    }

    #[test]
    fn accepts_all_precision_levels_and_rejects_kernel_domain_errors() {
        for bits in [32, 64, 128, 256] {
            let (lo, hi, p) = enclosure(1, 1, bits).expect("certified enclosure");
            assert_eq!(rounded(&lo, 12, p), Ok(2484));
            assert_eq!(rounded(&hi, 12, p), Ok(2484));
        }
        for (n, f, e) in [((1 << 31) + 1, 0, 0), (1, 31, 0), (1, 0, 15)] {
            assert_eq!(certify(n, f, e), Err(Error::Parameters));
        }
        assert_eq!(enclosure(1, 1, 33), Err(Error::Precision));
    }
}

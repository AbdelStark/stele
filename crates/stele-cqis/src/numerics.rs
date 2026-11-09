//! RFC-0025 §2.2–2.4: exact numerical rounding, never field or proof arithmetic.
use crate::tables::{self, natural::Natural};
use core::cmp::Ordering;

#[cfg(test)]
mod parity;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Error {
    Capacity,
    Arithmetic,
    Range,
}
impl From<tables::Error> for Error {
    fn from(value: tables::Error) -> Self {
        if value == tables::Error::Capacity {
            Self::Capacity
        } else {
            Self::Arithmetic
        }
    }
}

pub(crate) fn natural(value: u128) -> Result<Natural, Error> {
    Ok(Natural::from_u64((value >> 64) as u64)?
        .shl(64)?
        .add(&Natural::from_u64(value as u64)?)?)
}

fn signed(magnitude: u128, negative: bool) -> Result<i64, Error> {
    let value = i128::try_from(magnitude).map_err(|_| Error::Range)?;
    i64::try_from(if negative { -value } else { value }).map_err(|_| Error::Range)
}

pub(crate) fn round_ratio(n: i128, d: u128) -> Result<i64, Error> {
    if d == 0 {
        return Err(Error::Arithmetic);
    }
    let (q, r) = (n.unsigned_abs() / d, n.unsigned_abs() % d);
    let value = q.checked_add(u128::from(r >= d - r)).ok_or(Error::Range)?;
    signed(value, n < 0)
}

fn shifted(value: i128, shift: usize) -> Option<i128> {
    if value == 0 {
        return Some(0);
    }
    if shift >= 127 {
        return None;
    }
    value.checked_mul(1i128 << shift)
}

/// Common non-negative shift and the two aligned left shifts of `scaled_sum`.
fn exponents(le: i32, re: i32) -> Result<(usize, usize, usize), Error> {
    let shift = 0i64.max(-i64::from(le)).max(-i64::from(re));
    let sh = usize::try_from(shift).map_err(|_| Error::Arithmetic)?;
    let ls = usize::try_from(i64::from(le) + shift).map_err(|_| Error::Arithmetic)?;
    let rs = usize::try_from(i64::from(re) + shift).map_err(|_| Error::Arithmetic)?;
    Ok((sh, ls, rs))
}

/// The exact i128 (numerator, divisor) pair `scaled_sum` rounds on its fast
/// path, or None when it must use bounded wide scratch instead.
pub(crate) fn scaled_parts(
    left: i128,
    le: i32,
    right: i128,
    re: i32,
    divisor: u64,
) -> Result<Option<(i128, u128)>, Error> {
    let (sh, ls, rs) = exponents(le, re)?;
    let fast = shifted(left, ls)
        .zip(shifted(right, rs))
        .and_then(|(l, r)| l.checked_add(r));
    Ok(fast.zip(
        (sh < 128)
            .then(|| 1u128 << sh)
            .and_then(|p| u128::from(divisor).checked_mul(p)),
    ))
}

/// R((left*2^le + right*2^re)/divisor), with exactly one signed rounding.
/// Closed callers bound coefficients below 2^69 and aligned words below 2^2200
/// (the full [-1099,1024] physical exponent domain), inside Natural's fixed cap.
/// The i128 path is an exact representation choice; failure uses the same integer
/// expression in bounded wide scratch and never changes a CQIS parameter.
pub(crate) fn scaled_sum(
    left: i128,
    le: i32,
    right: i128,
    re: i32,
    divisor: u64,
) -> Result<i64, Error> {
    if divisor == 0 {
        return Err(Error::Arithmetic);
    }
    if let Some((n, d)) = scaled_parts(left, le, right, re, divisor)? {
        return round_ratio(n, d);
    }
    let (sh, ls, rs) = exponents(le, re)?;
    let l = natural(left.unsigned_abs())?.shl(ls)?;
    let r = natural(right.unsigned_abs())?.shl(rs)?;
    let (magnitude, negative) = if (left < 0) == (right < 0) {
        (l.add(&r)?, left < 0)
    } else if l.cmp(&r) != Ordering::Less {
        (l.sub(&r)?, left < 0)
    } else {
        (r.sub(&l)?, right < 0)
    };
    let denominator = Natural::from_u64(divisor)?.shl(sh)?;
    let (q, r) = magnitude.div_rem(&denominator)?;
    // Every current consumer requires at most signed int32. Reject before
    // narrowing; a wide quotient is never truncated into an accepted output.
    let value = u64::from(q.to_u32().map_err(|_| Error::Range)?)
        + u64::from(r.shl(1)?.cmp(&denominator) != Ordering::Less);
    signed(u128::from(value), negative)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accepts_signed_ties_cancellation_and_full_physical_exponents() {
        assert_eq!(scaled_sum(3, -1, 0, 0, 1), Ok(2));
        assert_eq!(scaled_sum(-3, -1, 0, 0, 1), Ok(-2));
        assert_eq!(scaled_sum(1, -1, -1, -1, 1), Ok(0));
        assert_eq!(scaled_sum(1, 1024, -1, 1024, 1), Ok(0));
        assert_eq!(scaled_sum(1, -1099, 1, -1, 1), Ok(1));
        assert_eq!(scaled_sum(-1, -1099, 1, -1, 1), Ok(0));
        assert_eq!(scaled_sum(1, 1024, 1, -1099, 1), Err(Error::Range));
        assert_eq!(scaled_sum(1, 0, 1, 0, 0), Err(Error::Arithmetic));
        assert_eq!(round_ratio(i128::MIN, 1 << 127), Ok(-1));
        assert_eq!(round_ratio(1, 0), Err(Error::Arithmetic));
    }
}

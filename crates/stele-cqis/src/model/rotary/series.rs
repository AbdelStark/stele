//! RFC-0025 §2.4: log/exp/Machin/trigonometric enclosures using exact outward rounding.
use super::fixed::{Grid, Interval};
use crate::tables::{natural::Natural, Error};
use core::cmp::Ordering;

// For 0<=z<=1/3, ln((1+z)/(1-z)) = 2 sum z^(2k+1)/(2k+1).
// After removing the next power, the remaining positive tail is <=3*that power.
fn atanh(grid: &Grid, z: &Interval) -> Result<Interval, Error> {
    let square = grid.mul(z, z)?;
    let mut power = z.try_clone()?;
    let mut total = Interval::exact(Natural::zero())?;
    for k in 0..512u64 {
        total = total.add(&power.divide_integer(2 * k + 1)?)?;
        power = grid.mul(&power, &square)?;
        if power.hi.cmp(&Natural::from_u64(1)?) != Ordering::Greater {
            let mut out = total.scale(2)?;
            out.hi = out.hi.add(&power.hi.mul_u64(3)?)?;
            return Ok(out);
        }
    }
    Err(Error::Precision)
}

pub(super) fn logarithm(grid: &Grid, n: u64, d: u64) -> Result<Interval, Error> {
    if d == 0 || n < d {
        return Err(Error::Parameters);
    }
    // n/d = 2^k*x, 1<=x<2; reduced denominator never exceeds the u64 numerator.
    let mut reduced = u128::from(d);
    let mut k = 0;
    while 2 * reduced <= u128::from(n) {
        reduced *= 2;
        k += 1;
    }
    let n = Natural::from_u64(n)?;
    let d = Natural::from_u64(u64::try_from(reduced).map_err(|_| Error::Interval)?)?;
    let z = grid.ratio(&n.sub(&d)?, &n.add(&d)?)?;
    let rest = atanh(grid, &z)?;
    if k == 0 {
        return Ok(rest);
    }
    let third = grid.ratio(&Natural::from_u64(1)?, &Natural::from_u64(3)?)?;
    rest.add(&atanh(grid, &third)?.scale(k)?)
}

// Adjacent alternating partial sums enclose the real function. Keeping positive
// and negative terms separately preserves outward rounding through subtraction.
fn alternating(
    grid: &Grid,
    initial: Interval,
    multiplier: &Interval,
    denominator: impl Fn(u64) -> u64,
) -> Result<Interval, Error> {
    let mut positive = initial.try_clone()?;
    let mut negative = Interval::exact(Natural::zero())?;
    let mut term = initial;
    let mut previous = positive.try_clone()?;
    for k in 1..=512u64 {
        term = grid
            .mul(&term, multiplier)?
            .divide_integer(denominator(k))?;
        if k % 2 == 1 {
            negative = negative.add(&term)?;
        } else {
            positive = positive.add(&term)?;
        }
        let current = positive.nonnegative_sub(&negative)?;
        if term.hi.cmp(&Natural::from_u64(1)?) != Ordering::Greater {
            return previous.hull(&current);
        }
        previous = current;
    }
    Err(Error::Precision)
}

pub(super) fn negative_exp(grid: &Grid, x: &Interval) -> Result<Interval, Error> {
    let eighth = grid.unit.shr(3)?;
    let mut small = x.try_clone()?;
    let mut halves = 0;
    while small.hi.cmp(&eighth) == Ordering::Greater {
        small = small.divide_integer(2)?;
        halves += 1;
        if halves > 8 {
            return Err(Error::Interval);
        }
    }
    let mut result = alternating(grid, grid.one()?, &small, |k| k)?;
    for _ in 0..halves {
        result = grid.cap_one(grid.mul(&result, &result)?)?;
    }
    grid.cap_one(result)
}

fn atan(grid: &Grid, divisor: u64) -> Result<Interval, Error> {
    let z = grid.ratio(&Natural::from_u64(1)?, &Natural::from_u64(divisor)?)?;
    let square = grid.mul(&z, &z)?;
    let mut power = z.try_clone()?;
    let mut positive = z.try_clone()?;
    let mut negative = Interval::exact(Natural::zero())?;
    let mut previous = z;
    for k in 1..=512u64 {
        power = grid.mul(&power, &square)?;
        let term = power.divide_integer(2 * k + 1)?;
        if k % 2 == 1 {
            negative = negative.add(&term)?;
        } else {
            positive = positive.add(&term)?;
        }
        let current = positive.nonnegative_sub(&negative)?;
        if term.hi.cmp(&Natural::from_u64(1)?) != Ordering::Greater {
            return previous.hull(&current);
        }
        previous = current;
    }
    Err(Error::Precision)
}

pub(super) fn pi(grid: &Grid) -> Result<Interval, Error> {
    let result = atan(grid, 5)?
        .scale(16)?
        .nonnegative_sub(&atan(grid, 239)?.scale(4)?)?;
    if result.lo.cmp(&grid.unit.mul_u64(3)?) != Ordering::Greater
        || result.hi.cmp(&grid.unit.mul_u64(4)?) != Ordering::Less
    {
        return Err(Error::Interval);
    }
    Ok(result)
}

pub(super) fn small_trig(grid: &Grid, y: &Interval) -> Result<(Interval, Interval), Error> {
    if y.hi.cmp(&grid.unit.shr(3)?) == Ordering::Greater {
        return Err(Error::Parameters);
    }
    let square = grid.mul(y, y)?;
    let c = alternating(grid, grid.one()?, &square, |k| (2 * k - 1) * (2 * k))?;
    let s = alternating(grid, y.try_clone()?, &square, |k| (2 * k) * (2 * k + 1))?;
    Ok((c, s))
}

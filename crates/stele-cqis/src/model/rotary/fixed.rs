//! RFC-0025 §2.4: outward fixed-point intervals for certified rotary preparation.
//! At 512 fractional bits, these operations use fewer than 2048 scratch bits:
//! angle endpoints have <=533 bits; rational endpoint cross-products add at most 212.
use crate::tables::{natural::Natural, Error};
use core::cmp::Ordering;

pub(super) struct Interval {
    pub lo: Natural,
    pub hi: Natural,
}
impl Interval {
    pub fn exact(value: Natural) -> Result<Self, Error> {
        Ok(Self {
            lo: value.try_clone()?,
            hi: value,
        })
    }
    pub fn try_clone(&self) -> Result<Self, Error> {
        Ok(Self {
            lo: self.lo.try_clone()?,
            hi: self.hi.try_clone()?,
        })
    }
    pub fn add(&self, other: &Self) -> Result<Self, Error> {
        Ok(Self {
            lo: self.lo.add(&other.lo)?,
            hi: self.hi.add(&other.hi)?,
        })
    }
    // The caller proves the real result nonnegative; intersecting its lower
    // enclosure with zero is then sound, including near a scaling threshold.
    pub fn nonnegative_sub(&self, other: &Self) -> Result<Self, Error> {
        Ok(Self {
            lo: if self.lo.cmp(&other.hi) == Ordering::Less {
                Natural::zero()
            } else {
                self.lo.sub(&other.hi)?
            },
            hi: self.hi.sub(&other.lo)?,
        })
    }
    pub fn scale(&self, n: u64) -> Result<Self, Error> {
        Ok(Self {
            lo: self.lo.mul_u64(n)?,
            hi: self.hi.mul_u64(n)?,
        })
    }
    pub fn divide_integer(&self, n: u64) -> Result<Self, Error> {
        let d = Natural::from_u64(n)?;
        Ok(Self {
            lo: self.lo.div_rem(&d)?.0,
            hi: ceil_div(&self.hi, &d)?,
        })
    }
    pub fn hull(&self, other: &Self) -> Result<Self, Error> {
        Ok(Self {
            lo: if self.lo.cmp(&other.lo) == Ordering::Less {
                &self.lo
            } else {
                &other.lo
            }
            .try_clone()?,
            hi: if self.hi.cmp(&other.hi) == Ordering::Greater {
                &self.hi
            } else {
                &other.hi
            }
            .try_clone()?,
        })
    }
}

pub(super) fn ceil_div(n: &Natural, d: &Natural) -> Result<Natural, Error> {
    let (q, r) = n.div_rem(d)?;
    if r.is_zero() {
        Ok(q)
    } else {
        q.add(&Natural::from_u64(1)?)
    }
}

pub(super) struct Grid {
    pub bits: usize,
    pub unit: Natural,
    bias: Natural,
}
impl Grid {
    pub fn new(bits: usize) -> Result<Self, Error> {
        if !matches!(bits, 128 | 256 | 512) {
            return Err(Error::Precision);
        }
        let one = Natural::from_u64(1)?;
        let unit = one.shl(bits)?;
        let bias = unit.sub(&one)?;
        Ok(Self { bits, unit, bias })
    }
    pub fn one(&self) -> Result<Interval, Error> {
        Interval::exact(self.unit.try_clone()?)
    }
    pub fn ratio(&self, n: &Natural, d: &Natural) -> Result<Interval, Error> {
        let n = n.shl(self.bits)?;
        Ok(Interval {
            lo: n.div_rem(d)?.0,
            hi: ceil_div(&n, d)?,
        })
    }
    pub fn mul(&self, a: &Interval, b: &Interval) -> Result<Interval, Error> {
        Ok(Interval {
            lo: a.lo.mul(&b.lo)?.shr(self.bits)?,
            hi: a.hi.mul(&b.hi)?.add(&self.bias)?.shr(self.bits)?,
        })
    }
    pub fn divide(&self, a: &Interval, b: &Interval) -> Result<Interval, Error> {
        Ok(Interval {
            lo: a.lo.shl(self.bits)?.div_rem(&b.hi)?.0,
            hi: ceil_div(&a.hi.shl(self.bits)?, &b.lo)?,
        })
    }
    pub fn cap_one(&self, a: Interval) -> Result<Interval, Error> {
        if a.lo.cmp(&self.unit) == Ordering::Greater {
            return Err(Error::Interval);
        }
        Ok(Interval {
            lo: a.lo,
            hi: if a.hi.cmp(&self.unit) == Ordering::Greater {
                self.unit.try_clone()?
            } else {
                a.hi
            },
        })
    }
}

pub(super) struct Signed {
    negative: bool,
    magnitude: Natural,
}
impl Signed {
    pub fn new(negative: bool, magnitude: Natural) -> Self {
        Self {
            negative: negative && !magnitude.is_zero(),
            magnitude,
        }
    }
    pub fn try_clone(&self) -> Result<Self, Error> {
        Ok(Self::new(self.negative, self.magnitude.try_clone()?))
    }
    pub fn cmp(&self, other: &Self) -> Ordering {
        match (self.negative, other.negative) {
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            (true, true) => other.magnitude.cmp(&self.magnitude),
            _ => self.magnitude.cmp(&other.magnitude),
        }
    }
    pub fn sub(&self, other: &Self) -> Result<Self, Error> {
        if self.negative != other.negative {
            return Ok(Self::new(
                self.negative,
                self.magnitude.add(&other.magnitude)?,
            ));
        }
        if self.magnitude.cmp(&other.magnitude) == Ordering::Less {
            Ok(Self::new(
                !self.negative,
                other.magnitude.sub(&self.magnitude)?,
            ))
        } else {
            Ok(Self::new(
                self.negative,
                self.magnitude.sub(&other.magnitude)?,
            ))
        }
    }
    pub fn mul(&self, other: &Self) -> Result<Self, Error> {
        Ok(Self::new(
            self.negative != other.negative,
            self.magnitude.mul(&other.magnitude)?,
        ))
    }
    pub fn double(&self) -> Result<Self, Error> {
        Ok(Self::new(self.negative, self.magnitude.shl(1)?))
    }
    pub fn down(&self, bits: usize, upper: bool) -> Result<Self, Error> {
        let mut q = self.magnitude.shr(bits)?;
        let remainder = q.shl(bits)?.cmp(&self.magnitude) != Ordering::Equal;
        if remainder && (upper != self.negative) {
            q = q.add(&Natural::from_u64(1)?)?;
        }
        Ok(Self::new(self.negative, q))
    }
    pub fn rounded(&self, bits: usize) -> Result<i16, Error> {
        let shift = bits.checked_sub(14).ok_or(Error::Precision)?;
        let bias = Natural::from_u64(1)?.shl(shift.checked_sub(1).ok_or(Error::Precision)?)?;
        let q = self.magnitude.add(&bias)?.shr(shift)?.to_u32()?;
        let q = i16::try_from(q).map_err(|_| Error::Interval)?;
        Ok(if self.negative { -q } else { q })
    }
}

pub(super) struct SignedInterval {
    pub lo: Signed,
    pub hi: Signed,
}
impl SignedInterval {
    pub fn positive(a: Interval) -> Self {
        Self {
            lo: Signed::new(false, a.lo),
            hi: Signed::new(false, a.hi),
        }
    }
    pub fn clip(self, grid: &Grid) -> Result<Self, Error> {
        let low = Signed::new(true, grid.unit.try_clone()?);
        let high = Signed::new(false, grid.unit.try_clone()?);
        let lo = if self.lo.cmp(&low) == Ordering::Less {
            low
        } else {
            self.lo
        };
        let hi = if self.hi.cmp(&high) == Ordering::Greater {
            high
        } else {
            self.hi
        };
        if lo.cmp(&hi) == Ordering::Greater {
            return Err(Error::Interval);
        }
        Ok(Self { lo, hi })
    }
    pub fn double_product(&self, b: &Self, grid: &Grid) -> Result<Self, Error> {
        let mut lo = self.lo.mul(&b.lo)?;
        let mut hi = lo.try_clone()?;
        for (a, b) in [(&self.lo, &b.hi), (&self.hi, &b.lo), (&self.hi, &b.hi)] {
            let p = a.mul(b)?;
            if p.cmp(&lo) == Ordering::Less {
                lo = p.try_clone()?;
            }
            if p.cmp(&hi) == Ordering::Greater {
                hi = p;
            }
        }
        Self {
            lo: lo.double()?.down(grid.bits, false)?,
            hi: hi.double()?.down(grid.bits, true)?,
        }
        .clip(grid)
    }
    pub fn double_square_minus_one(&self, grid: &Grid) -> Result<Self, Error> {
        let a = self.lo.mul(&self.lo)?;
        let b = self.hi.mul(&self.hi)?;
        let zero = Signed::new(false, Natural::zero());
        let low = if self.lo.cmp(&zero) != Ordering::Greater && self.hi.cmp(&zero) != Ordering::Less
        {
            zero
        } else if a.cmp(&b) == Ordering::Less {
            a.try_clone()?
        } else {
            b.try_clone()?
        };
        let high = if a.cmp(&b) == Ordering::Greater { a } else { b };
        let one = Signed::new(false, grid.unit.try_clone()?);
        Self {
            lo: low.double()?.down(grid.bits, false)?.sub(&one)?,
            hi: high.double()?.down(grid.bits, true)?.sub(&one)?,
        }
        .clip(grid)
    }
}

//! RFC-0025 §2.4 and encoding §4: integer-certified rotary coefficients.
//! Frequencies and angles remain intervals of the exact real functions. Only
//! uniquely certified final Q14 endpoints become coefficients; no Q14 recurrence.
use super::{codec::reserved, Rotation};
use crate::tables::{natural::Natural, Error};
use alloc::vec::Vec;
use core::cmp::Ordering;
mod fixed;
mod series;
use fixed::{ceil_div, Grid, Interval, SignedInterval};

fn natural128(n: u128) -> Result<Natural, Error> {
    Natural::from_u64((n >> 64) as u64)?
        .shl(64)?
        .add(&Natural::from_u64(n as u64)?)
}

struct Kernel {
    grid: Grid,
    log_theta: Interval,
    pi: Option<Interval>,
    frequencies: Vec<Option<Interval>>,
}
impl Kernel {
    fn new(p: Rotation, bits: usize) -> Result<Self, Error> {
        let grid = Grid::new(bits)?;
        let (n, d) = p.rationals()[0];
        let log_theta = series::logarithm(&grid, n, d)?;
        let pi = if p.family() == 2 {
            Some(series::pi(&grid)?)
        } else {
            None
        };
        let count = usize::from(p.width() / 2);
        let mut frequencies = reserved(count).map_err(|_| Error::Capacity)?;
        frequencies.resize_with(count, || None);
        Ok(Self {
            grid,
            log_theta,
            pi,
            frequencies,
        })
    }
    fn frequency(&self, p: Rotation, j: u16) -> Result<Interval, Error> {
        let x = self
            .log_theta
            .scale(2 * u64::from(j))?
            .divide_integer(u64::from(p.width()))?;
        let f = series::negative_exp(&self.grid, &x)?;
        let [_, factor, low, high] = p.rationals();
        match p.family() {
            0 => Ok(f),
            1 => self
                .grid
                .cap_one(f.scale(factor.1)?.divide_integer(factor.0)?),
            2 => {
                let pi = self.pi.as_ref().ok_or(Error::Interval)?;
                let raw = self
                    .grid
                    .divide(&f.scale(u64::from(p.original()))?, &pi.scale(2)?)?;
                // Keep the narrow high-low difference exact: rounding a u64
                // rational threshold first can erase the entire transition.
                let span_n = natural128(
                    u128::from(high.0) * u128::from(low.1) - u128::from(low.0) * u128::from(high.1),
                )?;
                let span_d = natural128(u128::from(high.1) * u128::from(low.1))?;
                let threshold = self.grid.unit.mul_u64(low.0)?;
                let denominator = span_n.mul_u64(low.1)?;
                let endpoint = |v: &Natural, upper: bool| -> Result<Natural, Error> {
                    let v = v.mul_u64(low.1)?;
                    if v.cmp(&threshold) != Ordering::Greater {
                        return Ok(Natural::zero());
                    }
                    let n = v.sub(&threshold)?.mul(&span_d)?;
                    let q = if upper {
                        ceil_div(&n, &denominator)?
                    } else {
                        n.div_rem(&denominator)?.0
                    };
                    if q.cmp(&self.grid.unit) == Ordering::Greater {
                        self.grid.unit.try_clone()
                    } else {
                        Ok(q)
                    }
                };
                let blend = Interval {
                    lo: endpoint(&raw.lo, false)?,
                    hi: endpoint(&raw.hi, true)?,
                };
                let constant = Interval::exact(self.grid.unit.mul_u64(factor.1)?)?;
                let weight = constant
                    .add(&blend.scale(factor.0 - factor.1)?)?
                    .divide_integer(factor.0)?;
                self.grid.cap_one(self.grid.mul(&f, &weight)?)
            }
            _ => Err(Error::Parameters),
        }
    }
    fn enclosure(
        &mut self,
        p: Rotation,
        position: u32,
        pair: u16,
    ) -> Result<(SignedInterval, SignedInterval), Error> {
        let index = usize::from(pair);
        if self
            .frequencies
            .get(index)
            .ok_or(Error::Parameters)?
            .is_none()
        {
            self.frequencies[index] = Some(self.frequency(p, pair)?);
        }
        let frequency = self.frequencies[index].as_ref().ok_or(Error::Interval)?;
        let mut angle = frequency.scale(u64::from(position))?;
        let eighth = self.grid.unit.shr(3)?;
        let mut halves = 0;
        while angle.hi.cmp(&eighth) == Ordering::Greater {
            angle = angle.divide_integer(2)?;
            halves += 1;
            if halves > 23 {
                return Err(Error::Interval);
            }
        }
        let (c, s) = series::small_trig(&self.grid, &angle)?;
        let (mut c, mut s) = (SignedInterval::positive(c), SignedInterval::positive(s));
        for _ in 0..halves {
            let next_s = s.double_product(&c, &self.grid)?;
            let next_c = c.double_square_minus_one(&self.grid)?;
            (c, s) = (next_c, next_s);
        }
        Ok((c.clip(&self.grid)?, s.clip(&self.grid)?))
    }
}

struct Generator {
    rotation: Rotation,
    kernels: [Option<Kernel>; 3],
}
impl Generator {
    fn new(rotation: Rotation) -> Self {
        Self {
            rotation,
            kernels: [None, None, None],
        }
    }
    fn enclosure(
        &mut self,
        position: u32,
        pair: u16,
        bits: usize,
    ) -> Result<(SignedInterval, SignedInterval), Error> {
        let index = match bits {
            128 => 0,
            256 => 1,
            512 => 2,
            _ => return Err(Error::Precision),
        };
        if position >= self.rotation.length() || pair >= self.rotation.width() / 2 {
            return Err(Error::Parameters);
        }
        if position == 0 {
            let grid = Grid::new(bits)?;
            return Ok((
                SignedInterval::positive(grid.one()?),
                SignedInterval::positive(Interval::exact(Natural::zero())?),
            ));
        }
        if self.kernels[index].is_none() {
            self.kernels[index] = Some(Kernel::new(self.rotation, bits)?);
        }
        self.kernels[index]
            .as_mut()
            .ok_or(Error::Interval)?
            .enclosure(self.rotation, position, pair)
    }
    fn coefficient(&mut self, position: u32, pair: u16) -> Result<(i16, i16), Error> {
        for bits in [128, 256, 512] {
            let (c, s) = self.enclosure(position, pair, bits)?;
            let c0 = c.lo.rounded(bits)?;
            let c1 = c.hi.rounded(bits)?;
            let s0 = s.lo.rounded(bits)?;
            let s1 = s.hi.rounded(bits)?;
            if c0 == c1 && s0 == s1 {
                return Ok((c0, s0));
            }
        }
        Err(Error::Precision)
    }
}

impl Rotation {
    /// Certify one exact real-frequency Q14 coefficient pair. Source/Registry
    /// authority and the position/pair proof consumers remain separate.
    pub fn coefficient(self, position: u32, pair: u16) -> Result<(i16, i16), super::Error> {
        Generator::new(self)
            .coefficient(position, pair)
            .map_err(super::Error::Generation)
    }
    /// Regenerate and hash every canonical coefficient in position-major order.
    /// Rows are at most 32768 bytes; no research materialization cap applies.
    pub fn data_digest(self) -> Result<[u8; 32], super::Error> {
        let mut digest = blake3::Hasher::new();
        digest.update(b"stele/v0.1/cqis/rotation-data");
        digest.update(blake3::hash(&self.encode()?).as_bytes());
        let row_length = 2 * usize::from(self.width());
        let mut row = reserved(row_length)?;
        row.resize(row_length, 0);
        let mut generator = Generator::new(self);
        for position in 0..self.length() {
            for (pair, output) in row.chunks_exact_mut(4).enumerate() {
                let pair = u16::try_from(pair).map_err(|_| super::Error::Capacity)?;
                let (c, s) = generator
                    .coefficient(position, pair)
                    .map_err(super::Error::Generation)?;
                output[..2].copy_from_slice(&c.to_le_bytes());
                output[2..].copy_from_slice(&s.to_le_bytes());
            }
            digest.update(&row);
        }
        Ok(*digest.finalize().as_bytes())
    }
}

#[cfg(test)]
mod tests;

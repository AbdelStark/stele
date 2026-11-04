//! RFC-0025 encoding §4: complete rotation metadata; coefficient generation is separate.
use super::{
    codec::{gcd, Reader, Writer},
    Error,
};
use alloc::vec::Vec;
const PREFIX: &[u8] = b"stele/v0.1/cqis/rotation";

/// Checked exact rational frequency parameters, without regenerated coefficients.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Rotation {
    width: u16,
    length: u32,
    family: u8,
    layout: u8,
    original: u32,
    rationals: [(u64, u64); 4],
}
impl Rotation {
    /// Validate every field and its family-specific canonical form.
    pub fn decode(raw: &[u8]) -> Result<Self, Error> {
        if raw.len() > 128 {
            return Err(Error::Capacity);
        }
        let mut r = Reader(raw);
        r.prefix(PREFIX)?;
        let width = r.u16()?;
        let length = r.u32()?;
        let family = r.u8()?;
        let layout = r.u8()?;
        let original = r.u32()?;
        let mut rationals = [(0, 1); 4];
        for pair in &mut rationals {
            *pair = (r.u64()?, r.u64()?);
        }
        r.end()?;
        if !(2..=16384).contains(&width)
            || width % 2 != 0
            || !(1..=1 << 20).contains(&length)
            || family > 2
            || layout > 1
            || (family == 2 && !(1..=1 << 20).contains(&original))
            || (family != 2 && original != 0)
        {
            return Err(Error::Rotation);
        }
        for (n, d) in rationals {
            if d == 0 || gcd(n, d) != 1 || u128::from(n) > u128::from(d) * (1 << 32) {
                return Err(Error::Rotation);
            }
        }
        let [theta, factor, low, high] = rationals;
        if theta.0 < theta.1
            || factor.0 < factor.1
            || (family == 0 && factor != (1, 1))
            || (family != 2 && (low != (0, 1) || high != (0, 1)))
            || (family == 2
                && (low.0 == 0
                    || u128::from(low.0) * u128::from(high.1)
                        >= u128::from(high.0) * u128::from(low.1)))
        {
            return Err(Error::Rotation);
        }
        Ok(Self {
            width,
            length,
            family,
            layout,
            original,
            rationals,
        })
    }
    /// Re-encode exact canonical fields, without truncating any rational word.
    pub fn encode(self) -> Result<Vec<u8>, Error> {
        let mut w = Writer::new(128)?;
        w.push(PREFIX)?;
        w.push(&self.width.to_le_bytes())?;
        w.push(&self.length.to_le_bytes())?;
        w.push(&[self.family, self.layout])?;
        w.push(&self.original.to_le_bytes())?;
        for (n, d) in self.rationals {
            w.push(&n.to_le_bytes())?;
            w.push(&d.to_le_bytes())?;
        }
        Ok(w.finish())
    }
    /// Number of rotated channels per head.
    pub fn width(self) -> u16 {
        self.width
    }
    /// Absolute position capacity.
    pub fn length(self) -> u32 {
        self.length
    }
    /// Base=0, linear=1, llama3=2.
    pub fn family(self) -> u8 {
        self.family
    }
    /// Adjacent=0, split=1.
    pub fn layout(self) -> u8 {
        self.layout
    }
    /// Original context for llama3, otherwise zero.
    pub fn original(self) -> u32 {
        self.original
    }
    /// Theta, factor, low and high as complete reduced numerator/denominator pairs.
    pub fn rationals(self) -> [(u64, u64); 4] {
        self.rationals
    }
}

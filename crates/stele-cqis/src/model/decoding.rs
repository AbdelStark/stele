//! RFC-0025 sampled-decoding bytes: complete temperature, top-p and exp selection.
use super::{
    block::{exponential, selection, write_selection},
    codec::{gcd, Reader, Writer},
    Error,
};
use crate::functions::Representation;
use alloc::vec::Vec;

/// Checked sampled policy; seed, prompt and stopping parameters belong to Request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Sampling {
    temperature: (u32, u32),
    top_p: (u32, u32),
    exp: Representation,
}
impl Sampling {
    /// Positive reduced temperature numerator and denominator.
    pub fn temperature(&self) -> (u32, u32) {
        self.temperature
    }
    /// Reduced top-p ratio in (0,1].
    pub fn top_p(&self) -> (u32, u32) {
        self.top_p
    }
    /// Explicit exp function, including its selected representation.
    pub fn exponential(&self) -> &Representation {
        &self.exp
    }
}

/// Closed greedy/sampled policy. Numerical execution and proof consumers are separate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Decoding {
    /// First maximum, with the exact request stopping rules.
    Greedy,
    /// Temperature/top-p sampling with an explicit exp selection.
    Sampled(Sampling),
}
impl Decoding {
    pub(super) fn read(raw: &[u8]) -> Result<Self, Error> {
        let mut r = Reader(raw);
        let out = match r.u8()? {
            0 => Self::Greedy,
            1 => {
                let (tn, td, pn, pd) = (r.u32()?, r.u32()?, r.u32()?, r.u32()?);
                if tn == 0
                    || td == 0
                    || pn == 0
                    || pd == 0
                    || pn > pd
                    || gcd(u64::from(tn), u64::from(td)) != 1
                    || gcd(u64::from(pn), u64::from(pd)) != 1
                {
                    return Err(Error::Decoding);
                }
                let exp = selection(&mut r)?;
                exponential(&exp)?;
                Self::Sampled(Sampling {
                    temperature: (tn, td),
                    top_p: (pn, pd),
                    exp,
                })
            }
            _ => return Err(Error::Decoding),
        };
        r.end()?;
        Ok(out)
    }
    /// Exact standalone Decoding bytes, excluding the enclosing u32 length.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut w = Writer::new(345)?;
        match self {
            Self::Greedy => w.push(&[0])?,
            Self::Sampled(s) => {
                w.push(&[1])?;
                for v in [s.temperature.0, s.temperature.1, s.top_p.0, s.top_p.1] {
                    w.push(&v.to_le_bytes())?;
                }
                write_selection(&mut w, &s.exp)?;
            }
        }
        Ok(w.finish())
    }
    /// Sampling configuration, absent for greedy mode.
    pub fn sampling(&self) -> Option<&Sampling> {
        match self {
            Self::Greedy => None,
            Self::Sampled(s) => Some(s),
        }
    }
}

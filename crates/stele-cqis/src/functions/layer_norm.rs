//! RFC-0025 §2.3 / RFC-0021 A3: exact-mean affine LayerNorm, no proof admission.
use super::{Descriptor, Kind, NormError};
use crate::numerics::{self, natural};
use alloc::vec::Vec;
use core::cmp::Ordering;

impl From<numerics::Error> for NormError {
    fn from(value: numerics::Error) -> Self {
        match value {
            numerics::Error::Capacity => Self::Capacity,
            numerics::Error::Arithmetic => Self::Arithmetic,
            numerics::Error::Range => Self::Overflow,
        }
    }
}
fn table_error(value: crate::tables::Error) -> NormError {
    numerics::Error::from(value).into()
}

/// Scalar pieces of one exact-mean LayerNorm row (RFC-0021 A3), in its symbols:
/// S, Q, V=dQ-S^2, (N,P), a, M=floor(A/D), J=rsqrt(M) and e.
#[derive(Clone, Copy, Debug)]
pub(crate) struct LayerParts {
    pub sum: i64,
    pub squares: u64,
    pub variance: u64,
    pub ratio: (u128, u128),
    pub exponent: i32,
    pub mantissa: u32,
    pub reciprocal: i128,
    pub shift: i32,
}

impl Descriptor {
    /// Evaluate one complete exact-mean affine LayerNorm row under this descriptor.
    /// Gain and bias retain their original fractions. The mean is never rounded;
    /// normalization and bias are combined before the only output rounding.
    /// This returns numerical values, not authenticated sources or proof evidence.
    /// All output allocation is fallible; any failure returns no partial row.
    pub fn evaluate_layernorm(
        &self,
        input: &[i16],
        gain: &[i16],
        bias: &[i16],
    ) -> Result<Vec<i16>, NormError> {
        Ok(self.layernorm_row(input, gain, bias)?.0)
    }
    /// As `evaluate_layernorm`, also returning the row's scalar pieces.
    pub(crate) fn layernorm_row(
        &self,
        input: &[i16],
        gain: &[i16],
        bias: &[i16],
    ) -> Result<(Vec<i16>, LayerParts), NormError> {
        if self.kind != Kind::LayerNorm {
            return Err(NormError::Function);
        }
        let p = self.parameters();
        let d = u16::from_le_bytes([p[0], p[1]]);
        if [input.len(), gain.len(), bias.len()]
            .iter()
            .any(|n| *n != usize::from(d))
        {
            return Err(NormError::Shape);
        }
        let en = u128::from(u32::from_le_bytes([p[6], p[7], p[8], p[9]]));
        let ed = u128::from(u32::from_le_bytes([p[10], p[11], p[12], p[13]]));
        // d<=2^14, |X|<=2^15: |S|<=2^29, Q<=2^44, V<=2^58.
        let s: i64 = input.iter().map(|x| i64::from(*x)).sum();
        let q: u64 = input
            .iter()
            .map(|x| u64::from(x.unsigned_abs()).pow(2))
            .sum();
        let v = (u64::from(d) * q)
            .checked_sub(s.unsigned_abs().pow(2))
            .ok_or(NormError::Arithmetic)?;
        let unit = u128::from(d).pow(2) << (2 * u32::from(p[2]));
        let (n0, den0) = (ed * u128::from(v) + en * unit, ed * unit);
        // N<2^121 and P<2^120, but normalized A/D can exceed u128. Retain
        // exact wide words through the mantissa division; no discarded remainder.
        let (n, den) = (natural(n0)?, natural(den0)?);
        let mut a = (n.bits() as i32 - den.bits() as i32 - 14).div_euclid(2);
        let scaled = |a: i32| -> Result<_, NormError> {
            Ok((
                n.shl((-2 * a).max(0) as usize).map_err(table_error)?,
                den.shl((2 * a).max(0) as usize).map_err(table_error)?,
            ))
        };
        let (mut aa, mut dd) = scaled(a)?;
        if aa.cmp(&dd.shl(14).map_err(table_error)?) == Ordering::Less {
            a -= 1;
            (aa, dd) = scaled(a)?;
        }
        let (m, remainder) = aa.div_rem(&dd).map_err(table_error)?;
        let m = m.to_u32().map_err(table_error)?;
        if !(-23..=9).contains(&a)
            || !(16384..65536).contains(&m)
            || remainder.cmp(&dd) != Ordering::Less
        {
            return Err(NormError::Arithmetic);
        }
        let j = i128::from(crate::tables::rsqrt_value(m).map_err(table_error)?);
        let e = i32::from(p[2]) + i32::from(p[3]) + 21 + a - i32::from(p[4]);
        let mut outputs = Vec::new();
        outputs
            .try_reserve_exact(input.len())
            .map_err(|_| NormError::Capacity)?;
        for ((x, h), b) in input.iter().zip(gain).zip(bias) {
            let centered = i64::from(d) * i64::from(*x) - s;
            let product = i128::from(centered) * i128::from(*h) * j;
            let value = numerics::scaled_sum(
                product,
                -e,
                i128::from(d) * i128::from(*b),
                i32::from(p[4]) - i32::from(p[5]),
                u64::from(d),
            )?;
            outputs.push(i16::try_from(value).map_err(|_| NormError::Overflow)?);
        }
        let parts = LayerParts {
            sum: s,
            squares: q,
            variance: v,
            ratio: (n0, den0),
            exponent: a,
            mantissa: m,
            reciprocal: j,
            shift: e,
        };
        Ok((outputs, parts))
    }
}

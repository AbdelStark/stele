//! RFC-0025 flow appendix §§1–3: row conversion, residual alignment, gated product.
use super::{field_bound, term, Builder, Error, Record, Word};

/// Complete-row parameters; all domains are checked when deriving the record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Row {
    /// Original complete row width, in 1..=16384.
    pub dimension: u16,
    /// Wide int16=0 or exact gated product=1.
    pub kind: u8,
    /// Source fraction, at most 30 for wide or 44 for gated.
    pub fraction: u8,
    /// Dynamic=0 or static=1.
    pub policy: u8,
    /// Zero for dynamic; positive configured scale for static.
    pub scale: u32,
}
impl Row {
    pub(super) fn check(self) -> Result<(), Error> {
        let maximum = if self.kind == 0 { 65535 } else { 8454661 };
        if !(1..=16384).contains(&self.dimension)
            || self.kind > 1
            || self.fraction > if self.kind == 0 { 30 } else { 44 }
            || !((self.policy == 0 && self.scale == 0)
                || (self.policy == 1 && (1..=maximum).contains(&self.scale)))
        {
            return Err(Error::Parameters);
        }
        Ok(())
    }
    pub(super) fn scale_bound(self) -> u64 {
        if self.policy == 1 {
            u64::from(self.scale)
        } else if self.kind == 0 {
            259
        } else {
            8454661
        }
    }
}

/// One-round residual alignment parameters, checked during derivation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Residual {
    /// Original row width, in 1..=16384.
    pub dimension: u16,
    /// The two original source fractions, each in 0..=30.
    pub input_fractions: [u8; 2],
    /// Output fraction, in 0..=30.
    pub output_fraction: u8,
}

/// Exact gated-product parameters, checked during derivation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Gated {
    /// Original hidden width, in 1..=16384.
    pub dimension: u16,
    /// Up-projection fraction, in 0..=30.
    pub up_fraction: u8,
    /// Configured SiLU output fraction, in 0..=14.
    pub activation_fraction: u8,
}

impl Record {
    /// Derive schema 4, including the complete gated static-scale domain.
    pub fn row(p: Row) -> Result<Self, Error> {
        p.check()?;
        let h = if p.kind == 0 { 32768u64 } else { 1 << 30 };
        let high = if p.kind == 0 { h - 1 } else { h };
        let s = p.scale_bound();
        let d = u64::from(p.dimension);
        let scalars = [
            h,
            high,
            h + high,
            s,
            s - 1,
            d - 1,
            127,
            254 * s,
            2 * s - 1,
            4 * s - 1,
            2 * s,
            254,
            127,
            508,
            254,
            2 * d - 1,
            126,
        ]
        .map(Word::from);
        for side in [4 * s - 1, 2 * s, 254, 127, 508, 254, 2 * d - 1] {
            field_bound(side)?;
        }
        let mut params = [0u8; 9];
        params[..2].copy_from_slice(&p.dimension.to_le_bytes());
        params[2..5].copy_from_slice(&[p.kind, p.fraction, p.policy]);
        params[5..].copy_from_slice(&p.scale.to_le_bytes());
        let dynamic = p.policy == 0;
        let mut b = Builder::new(
            4,
            &params,
            8,
            &scalars[..if dynamic { 17 } else { 16 }],
            &[],
            if dynamic { 8 } else { 5 },
        )?;
        if dynamic {
            b.column(&[term(s, 127)])?;
            b.column(&[term(h, 1), term(126, 1)])?;
            b.column(&[term(h, 1), term(h, 1), term(1, 1)])?;
        }
        b.column(&[term(h + high, 1), term(h, 2)])?;
        b.column(&[term(h, 1), term(h, 1)])?;
        b.column(&[term(h, 2), term(s, 1)])?;
        b.column(&[term(127, 2 * s)])?;
        b.column(&[term(254 * s, 1), term(2 * s - 1, 1)])?;
        b.finish()
    }
    /// Derive schema 5, retaining the two aligned sources and one rounding.
    pub fn residual(p: Residual) -> Result<Self, Error> {
        let [fx, fy] = p.input_fractions;
        let fo = p.output_fraction;
        if !(1..=16384).contains(&p.dimension) || [fx, fy, fo].iter().any(|f| *f > 30) {
            return Err(Error::Parameters);
        }
        let common = fx.max(fy).max(fo);
        let shifts = [common, common - fx, common - fy, common - fo].map(i16::from);
        let (l, r, d) = (
            Word::power(shifts[1])?,
            Word::power(shifts[2])?,
            Word::power(shifts[3])?,
        );
        let maximum = l.add(r)?.mul(32768.into())?;
        let scalars = [
            u64::from(p.dimension - 1).into(),
            32768.into(),
            65535.into(),
            l,
            r,
            d,
            maximum,
            maximum.quotient_cap(d, 32768)?,
            32768.into(),
            131071.into(),
            65536.into(),
        ];
        let mut params = [0; 5];
        params[..2].copy_from_slice(&p.dimension.to_le_bytes());
        params[2..].copy_from_slice(&[fx, fy, fo]);
        let mut b = Builder::new(5, &params, 8, &scalars, &shifts, 9)?;
        b.column(&[term(65535, l), term(65535, r)])?;
        b.rounding(maximum, d)?;
        b.finish()
    }
    /// Derive schema 6 with the legal positive 2^30 gated endpoint.
    pub fn gated(p: Gated) -> Result<Self, Error> {
        if !(1..=16384).contains(&p.dimension) || p.up_fraction > 30 || p.activation_fraction > 14 {
            return Err(Error::Parameters);
        }
        let square = 65535u64.pow(2);
        let scalars = [
            u64::from(p.up_fraction + p.activation_fraction),
            32768,
            65535,
            square,
            1 << 30,
            1 << 31,
            u64::from(p.dimension - 1),
            131071,
            65536,
        ]
        .map(Word::from);
        let mut params = [0; 4];
        params[..2].copy_from_slice(&p.dimension.to_le_bytes());
        params[2..].copy_from_slice(&[p.up_fraction, p.activation_fraction]);
        let mut b = Builder::new(6, &params, 8, &scalars, &[], 3)?;
        b.column(&[term(65535, 65535)])?;
        b.column(&[term(square, 1), term(1 << 31, 1)])?;
        b.column(&[term(1 << 31, 1), term(65535, 32768), term(65535, 32768)])?;
        b.finish()
    }
}

//! RFC-0025 static appendix §§3–5: complete affine and aligned embedding records.
use super::{field_bound, term, Builder, Error, Record, Row, Word};

/// Physical weight format and static maximum over all public channel mantissas.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Weight {
    /// Symmetric weight width, 4 or 8.
    pub bits: u8,
    /// Authenticated tensor exponent, in -1099..=1024.
    pub exponent: i16,
    /// Maximum public channel mantissa, positive. Each source still binds its own.
    pub mantissa: u16,
}
impl Weight {
    fn check(self) -> Result<(), Error> {
        if !matches!(self.bits, 4 | 8)
            || !(-1099..=1024).contains(&self.exponent)
            || self.mantissa == 0
        {
            return Err(Error::Parameters);
        }
        Ok(())
    }
    fn magnitude(self) -> u64 {
        (1u64 << (self.bits - 1)) - 1
    }
    fn parameters(self) -> [u8; 5] {
        let mut raw = [0; 5];
        raw[0] = self.bits;
        raw[1..3].copy_from_slice(&self.exponent.to_le_bytes());
        raw[3..].copy_from_slice(&self.mantissa.to_le_bytes());
        raw
    }
}

/// Affine parameters; source dimension is the projection's inner dimension.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Affine {
    /// Complete source row and conversion policy.
    pub source: Row,
    /// Corresponding physical matrix format and maximum channel mantissa.
    pub weight: Weight,
    /// Output fraction, in 0..=30.
    pub output_fraction: u8,
    /// Original physical bias fraction when present, in 0..=30.
    pub bias_fraction: Option<u8>,
}

/// Token and optional position parameters for one aligned embedding rounding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Embedding {
    /// Vocabulary size, in 1..=2^20.
    pub vocabulary: u32,
    /// Context length, in 1..=2^20.
    pub context: u32,
    /// Output fraction, in 0..=30.
    pub output_fraction: u8,
    /// Physical token matrix parameters.
    pub token: Weight,
    /// Physical learned-position matrix parameters, present only for GPT-2.
    pub position: Option<Weight>,
}

impl Record {
    /// Derive schema 1; bias joins the full scaled product before rounding.
    pub fn affine(p: Affine) -> Result<Self, Error> {
        p.source.check()?;
        p.weight.check()?;
        if p.output_fraction > 30 || p.bias_fraction.is_some_and(|f| f > 30) {
            return Err(Error::Parameters);
        }
        let weight = p.weight.magnitude();
        let scale = p.source.scale_bound();
        let accumulator = 127 * weight * u64::from(p.source.dimension);
        // The dot sign left side is 4A, so its strict field bound is 8A<p.
        field_bound(4 * accumulator)?;
        let product = accumulator * u64::from(p.weight.mantissa);
        let total = Word::from(product).mul(scale.into())?;
        let le = p.weight.exponent - i16::from(p.source.fraction) + i16::from(p.output_fraction);
        let re = p
            .bias_fraction
            .map_or(0, |f| i16::from(p.output_fraction) - i16::from(f));
        let shift = 0.max(-le).max(-re);
        let (divisor, left) = (Word::power(shift)?, Word::power(le + shift)?);
        let bias = if p.bias_fraction.is_some() {
            Word::power(re + shift)?
        } else {
            0.into()
        };
        let maximum = total.mul(left)?.add(bias.mul(32768.into())?)?;
        let scalars = [
            weight.into(),
            scale.into(),
            accumulator.into(),
            product.into(),
            total,
            divisor,
            left,
            bias,
            maximum,
            maximum.quotient_cap(divisor, 32768)?,
            32768.into(),
            (4 * accumulator).into(),
            (2 * accumulator).into(),
            131071.into(),
            65536.into(),
        ];
        let mut params = [0; 17];
        params[..2].copy_from_slice(&p.source.dimension.to_le_bytes());
        params[2..7].copy_from_slice(&p.weight.parameters());
        params[7..11].copy_from_slice(&[
            p.source.kind,
            p.source.fraction,
            p.output_fraction,
            p.source.policy,
        ]);
        params[11..15].copy_from_slice(&p.source.scale.to_le_bytes());
        params[15] = u8::from(p.bias_fraction.is_some());
        params[16] = p.bias_fraction.unwrap_or(0);
        let mut b = Builder::new(
            1,
            &params[..if p.bias_fraction.is_some() { 17 } else { 16 }],
            8,
            &scalars,
            &[le, re, shift],
            13,
        )?;
        b.column(&[term(accumulator, u64::from(p.weight.mantissa))])?;
        b.column(&[term(product, scale)])?;
        b.column(&[term(total.mul(2.into())?, 1), term(total, 2)])?;
        b.column(&[term(total, 1), term(total, 1)])?;
        let aligned = [term(total.mul(2.into())?, left), term(65535, bias)];
        b.column(&aligned[..if p.bias_fraction.is_some() { 2 } else { 1 }])?;
        b.rounding(maximum, divisor)?;
        b.finish()
    }
    /// Derive schema 2; extreme token/position exponent gaps retain all high bits.
    pub fn embedding(p: Embedding) -> Result<Self, Error> {
        if !(1..=1 << 20).contains(&p.vocabulary)
            || !(1..=1 << 20).contains(&p.context)
            || p.output_fraction > 30
        {
            return Err(Error::Parameters);
        }
        p.token.check()?;
        if let Some(position) = p.position {
            position.check()?;
        }
        let sources = [p.token, p.position.unwrap_or(p.token)];
        let count = if p.position.is_some() { 2 } else { 1 };
        let exponents = sources.map(|w| w.exponent + i16::from(p.output_fraction));
        let shift = exponents[..count].iter().fold(0, |s, e| s.max(-e));
        let divisor = Word::power(shift)?;
        let mut factors = [Word::from(0); 2];
        let limits = sources.map(|w| w.magnitude() * u64::from(w.mantissa));
        let mut maximum = Word::from(0);
        for i in 0..count {
            factors[i] = Word::power(exponents[i] + shift)?;
            maximum = maximum.add(factors[i].mul(limits[i].into())?)?;
        }
        let mut scalars = [Word::from(0); 16];
        let mut length = 0;
        let mut scalar = |v| {
            scalars[length] = v;
            length += 1;
        };
        scalar(u64::from(p.vocabulary - 1).into());
        scalar(u64::from(p.context - 1).into());
        for limit in &limits[..count] {
            scalar((*limit).into());
        }
        scalar(divisor);
        for factor in &factors[..count] {
            scalar(*factor);
        }
        for value in [maximum, maximum.quotient_cap(divisor, 32768)?, 32768.into()] {
            scalar(value);
        }
        for limit in &limits[..count] {
            scalar((4 * limit).into());
            scalar((2 * limit).into());
        }
        scalar(131071.into());
        scalar(65536.into());
        let mut shifts = [0; 3];
        shifts[..count].copy_from_slice(&exponents[..count]);
        shifts[count] = shift;
        let mut params = [0; 20];
        params[..4].copy_from_slice(&p.vocabulary.to_le_bytes());
        params[4..8].copy_from_slice(&p.context.to_le_bytes());
        params[8] = p.output_fraction;
        params[9..14].copy_from_slice(&p.token.parameters());
        params[14] = u8::from(p.position.is_some());
        if let Some(position) = p.position {
            params[15..].copy_from_slice(&position.parameters());
        }
        let mut b = Builder::new(
            2,
            &params[..if p.position.is_some() { 20 } else { 15 }],
            8,
            &scalars[..length],
            &shifts[..count + 1],
            (count + 9) as u8,
        )?;
        for weight in &sources[..count] {
            b.column(&[term(weight.magnitude(), u64::from(weight.mantissa))])?;
        }
        let aligned = [
            term(2 * limits[0], factors[0]),
            term(2 * limits[1], factors[1]),
        ];
        b.column(&aligned[..count])?;
        b.rounding(maximum, divisor)?;
        b.finish()
    }
}

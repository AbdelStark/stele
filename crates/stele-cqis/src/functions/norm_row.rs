//! RFC-0021 §2.3: exact RMSNorm row generation, without proof/certificate admission.
use super::{Descriptor, Kind};
use alloc::vec::Vec;

/// A rejected RMSNorm evaluation. Failure returns no partial output row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NormError {
    /// The checked descriptor defines a different function.
    Function,
    /// Input/gain lengths differ from the descriptor's dimension.
    Shape,
    /// The owned output allocation cannot be satisfied.
    Capacity,
    /// An exact arithmetic invariant failed; no wrapping or guessed result.
    Arithmetic,
    /// At least one output is outside signed int16.
    Overflow,
}

/// Immutable numerical result only; no authenticated input, claim or certificate.
/// ```compile_fail
/// fn change(row: &mut stele_cqis::functions::NormEvaluation) {
///     row.outputs()[0] = 1;
/// }
/// ```
#[derive(Debug, Eq, PartialEq)]
pub struct NormEvaluation {
    outputs: Vec<i16>,
    statistic: u64,
    ratio: (u128, u128),
    normalized: (u128, u128, u128),
    exponent: i8,
    mantissa: u16,
    reciprocal: u16,
    shift: i32,
}

impl NormEvaluation {
    /// Wide int16 outputs; int8 conversion is a separate operation.
    pub fn outputs(&self) -> &[i16] {
        &self.outputs
    }
    /// Exact S=sum X_i^2.
    pub fn statistic(&self) -> u64 {
        self.statistic
    }
    /// Exact (N,P), including the configured positive epsilon.
    pub fn ratio(&self) -> (u128, u128) {
        self.ratio
    }
    /// Exact (A,D,R) with A=M*D+R and 0<=R<D; the remainder is retained.
    pub fn normalized_ratio(&self) -> (u128, u128, u128) {
        self.normalized
    }
    /// Unique a with 16384<=q/4^a<65536.
    pub fn exponent(&self) -> i8 {
        self.exponent
    }
    /// Valid rsqrt mantissa M, never a padded row.
    pub fn mantissa(&self) -> u16 {
        self.mantissa
    }
    /// Certified fixed-table value J(M).
    pub fn reciprocal(&self) -> u16 {
        self.reciprocal
    }
    /// Signed final shift F+G+21+a-E; negative means exact left shift.
    pub fn shift(&self) -> i32 {
        self.shift
    }
}

fn times_power(value: u128, bits: u32) -> Result<u128, NormError> {
    // checked_shl alone checks the shift count, not discarded high value bits.
    value
        .checked_mul(1u128.checked_shl(bits).ok_or(NormError::Arithmetic)?)
        .ok_or(NormError::Arithmetic)
}

fn scaled(n: u128, p: u128, a: i32) -> Result<(u128, u128), NormError> {
    if a < 0 {
        Ok((times_power(n, 2 * a.unsigned_abs())?, p))
    } else {
        Ok((n, times_power(p, 2 * a.unsigned_abs())?))
    }
}

fn output(product: i64, shift: i32) -> Result<i16, NormError> {
    if product.unsigned_abs() > 1 << 44 || !(-16..=90).contains(&shift) {
        return Err(NormError::Arithmetic);
    }
    let magnitude = u128::from(product.unsigned_abs());
    let rounded = if shift < 0 {
        times_power(magnitude, shift.unsigned_abs())?
    } else {
        let bias = if shift == 0 { 0 } else { 1u128 << (shift - 1) };
        magnitude.checked_add(bias).ok_or(NormError::Arithmetic)? >> shift
    };
    let signed = i64::try_from(rounded).map_err(|_| NormError::Overflow)?;
    i16::try_from(if product < 0 { -signed } else { signed }).map_err(|_| NormError::Overflow)
}

fn reserved(length: usize) -> Result<Vec<i16>, NormError> {
    length
        .checked_mul(core::mem::size_of::<i16>())
        .filter(|n| *n <= isize::MAX as usize)
        .ok_or(NormError::Capacity)?;
    let mut out = Vec::new();
    out.try_reserve_exact(length)
        .map_err(|_| NormError::Capacity)?;
    Ok(out)
}

impl Descriptor {
    /// Generate one exact RMSNorm row under the checked function parameters.
    /// Costs O(d), with one fallibly reserved output row. No transcript, field
    /// identity, input authentication or static certificate is supplied here.
    pub fn evaluate_rmsnorm(
        &self,
        input: &[i16],
        gain: &[i16],
    ) -> Result<NormEvaluation, NormError> {
        if self.kind != Kind::Norm {
            return Err(NormError::Function);
        }
        let p = &self.parameters;
        let d = u16::from_le_bytes([p[0], p[1]]);
        if input.len() != usize::from(d) || gain.len() != input.len() {
            return Err(NormError::Shape);
        }
        let en = u128::from(u32::from_le_bytes([p[5], p[6], p[7], p[8]]));
        let ed = u128::from(u32::from_le_bytes([p[9], p[10], p[11], p[12]]));
        let mut statistic = 0u64;
        for x in input {
            let magnitude = u64::from(x.unsigned_abs());
            statistic = statistic
                .checked_add(magnitude * magnitude)
                .ok_or(NormError::Arithmetic)?;
        }
        let unit = times_power(u128::from(d), 2 * u32::from(p[2]))?;
        let denominator = ed.checked_mul(unit).ok_or(NormError::Arithmetic)?;
        let numerator = ed
            .checked_mul(u128::from(statistic))
            .and_then(|s| {
                en.checked_mul(unit)
                    .and_then(|epsilon| s.checked_add(epsilon))
            })
            .ok_or(NormError::Arithmetic)?;
        // Checked metadata gives N>0,P>0,N<2^107,P<2^106. For the initial
        // a=floor((bitlen(N)-bitlen(P)-14)/2), 2^13<A/D<2^16.
        // If a<0, A<2^16*P<2^122; otherwise A=N<2^107, D<2^124.
        // A correction multiplies A/D by four only when A/D<2^14, preserving
        // A<2^16*P in the negative-a case. Hence exact u128 is sufficient.
        if numerator == 0 || denominator == 0 {
            return Err(NormError::Arithmetic);
        }
        let mut a = (denominator.leading_zeros() as i32 - numerator.leading_zeros() as i32 - 14)
            .div_euclid(2);
        let (mut scaled_n, mut scaled_d) = scaled(numerator, denominator, a)?;
        if scaled_n / scaled_d < 16384 {
            a -= 1;
            (scaled_n, scaled_d) = scaled(numerator, denominator, a)?;
        }
        let m = scaled_n / scaled_d;
        if !(-23..=9).contains(&a) || !(16384..65536).contains(&m) {
            return Err(NormError::Arithmetic);
        }
        let mantissa = u16::try_from(m).map_err(|_| NormError::Arithmetic)?;
        let reciprocal = u16::try_from(
            crate::tables::rsqrt_value(u32::from(mantissa)).map_err(|_| NormError::Arithmetic)?,
        )
        .map_err(|_| NormError::Arithmetic)?;
        let shift = i32::from(p[2]) + i32::from(p[3]) + 21 + a - i32::from(p[4]);
        let mut outputs = reserved(input.len())?;
        for (x, h) in input.iter().zip(gain) {
            let product = i64::from(*x) * i64::from(*h) * i64::from(reciprocal);
            outputs.push(output(product, shift)?);
        }
        Ok(NormEvaluation {
            outputs,
            statistic,
            ratio: (numerator, denominator),
            normalized: (scaled_n, scaled_d, scaled_n % scaled_d),
            exponent: i8::try_from(a).map_err(|_| NormError::Arithmetic)?,
            mantissa,
            reciprocal,
            shift,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accepts_signed_ties_negative_shifts_and_rejects_capacity_overflow() {
        for (x, e, y) in [(-3, 1, -2), (3, 1, 2), (-3, -1, -6), (3, -1, 6), (1, 90, 0)] {
            assert_eq!(output(x, e), Ok(y));
        }
        assert_eq!(reserved(usize::MAX), Err(NormError::Capacity));
        assert_eq!(times_power(1 << 127, 1), Err(NormError::Arithmetic));
        assert_eq!(times_power(1, 128), Err(NormError::Arithmetic));
        assert_eq!(output(1 << 44, -16), Err(NormError::Overflow));
    }
}

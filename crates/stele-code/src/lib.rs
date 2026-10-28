//! Canonical circle/v2 encoding, RFC-0010 A2/A4. Encoding admits no PCS profile.
#![forbid(unsafe_code)]
#![no_std]
#![cfg_attr(not(test), deny(clippy::float_arithmetic))]

extern crate alloc;
use alloc::vec::Vec;
use stele_field::{Field, M31};
mod encoder;
mod measurement;
pub use encoder::{Code, CodeField, Encoder, EncoderInfo};
use measurement::Measurement;
pub use measurement::{EncoderWork, MeasuredEncoding};

/// Invalid encoding request or an allocation that cannot be represented/satisfied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Unsupported message dimension or log blowup.
    InvalidSize,
    /// The row does not have the configured message length.
    RowShape,
    /// A requested column is outside the codeword.
    Column,
    /// The element field does not have M31 characteristic.
    FieldMismatch,
    /// Address-space overflow or allocation failure.
    Capacity,
    /// Unknown, malformed or unsupported canonical code identity.
    InvalidCodeId,
    /// A deterministic row stream exhausted its fixed 256-word cap.
    SamplingExhausted,
}

/// The fixed non-systematic M31 circle map, extended to the element field.
///
/// RFC-0010 A2 fixes the basis, order and normalization. This object supplies no
/// proximity parameters, commitment validation or profile-admission decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Circle {
    log_message: u32,
    log_blowup: u32,
    message_len: usize,
    codeword_len: usize,
}

impl Circle {
    /// Check dimensions without allocating; log blowup is one or two.
    pub fn new(log_message: u32, log_blowup: u32) -> Result<Self, Error> {
        if !(1..=2).contains(&log_blowup) || log_message > 30 - log_blowup {
            return Err(Error::InvalidSize);
        }
        Ok(Self {
            log_message,
            log_blowup,
            message_len: 1usize.checked_shl(log_message).ok_or(Error::Capacity)?,
            codeword_len: 1usize
                .checked_shl(log_message + log_blowup)
                .ok_or(Error::Capacity)?,
        })
    }

    /// Number of input values, ordered on the message domain.
    pub fn message_len(&self) -> usize {
        self.message_len
    }

    /// Number of encoded values, ordered on the larger domain.
    pub fn codeword_len(&self) -> usize {
        self.codeword_len
    }

    /// Canonical base-map identity; surrounding protocols also bind the field.
    pub fn code_id(&self) -> [u8; 21] {
        let mut id = [0; 21];
        id[..19].copy_from_slice(b"stele/circle-m31/v1");
        id[19] = self.log_message as u8;
        id[20] = self.log_blowup as u8;
        id
    }

    fn validate<K: Field>(&self, row: &[K]) -> Result<(), Error> {
        if K::MODULUS != M31::MODULUS {
            return Err(Error::FieldMismatch);
        }
        if row.len() != self.message_len {
            return Err(Error::RowShape);
        }
        Ok(())
    }

    /// Interpolate the exact FFT span, then zero-extend coefficients and evaluate.
    /// Preparation and transforms are included; the borrowed input is retained.
    pub fn encode<K: Field>(&self, row: &[K]) -> Result<Vec<K>, Error> {
        self.encode_recorded(row, &mut Measurement::default())
    }

    fn encode_recorded<K: Field>(
        &self,
        row: &[K],
        measured: &mut Measurement,
    ) -> Result<Vec<K>, Error> {
        self.validate(row)?;
        measured.work.circle_calls += 1;
        let mut output = measured.reserve(self.codeword_len)?;
        output.extend_from_slice(row);
        output.resize(self.codeword_len, K::from_i64(0));
        measured.work.copied_symbols += row.len() as u64;
        measured.work.initialized_symbols += (self.codeword_len - row.len()) as u64;
        transform_recorded(&mut output[..self.message_len], true, measured)?;
        transform_recorded(&mut output, false, measured)?;
        Ok(output)
    }

    /// Encode then select columns, preserving order and duplicates (RFC-0010 A2).
    /// An empty request validates the row/field but performs no transform.
    pub fn eval_row<K: Field>(&self, row: &[K], columns: &[usize]) -> Result<Vec<K>, Error> {
        self.validate(row)?;
        if columns.iter().any(|column| *column >= self.codeword_len) {
            return Err(Error::Column);
        }
        let mut selected = reserved(columns.len())?;
        if !columns.is_empty() {
            let encoded = self.encode(row)?;
            selected.extend(columns.iter().map(|column| encoded[*column]));
        }
        Ok(selected)
    }
}

fn reserved<T>(len: usize) -> Result<Vec<T>, Error> {
    let mut values = Vec::new();
    values.try_reserve_exact(len).map_err(|_| Error::Capacity)?;
    Ok(values)
}

fn multiply(a: (M31, M31), b: (M31, M31)) -> (M31, M31) {
    (a.0 * b.0 - a.1 * b.1, a.0 * b.1 + a.1 * b.0)
}

fn generator_power(mut exponent: u32) -> (M31, M31) {
    let mut g = (M31::from_i64(1717986917), M31::from_i64(1288490189));
    let mut value = (M31::ONE, M31::ZERO);
    while exponent != 0 {
        if exponent & 1 != 0 {
            value = multiply(value, g);
        }
        g = multiply(g, g);
        exponent >>= 1;
    }
    value
}

// RFC-0010 A2: root y, then x quotients under x -> 2*x*x-1; N-1 base elements.
fn twiddles(log: u32, measured: &mut Measurement) -> Result<Vec<Vec<M31>>, Error> {
    let mut levels = measured.reserve(log as usize)?;
    if log == 0 {
        return Ok(levels);
    }
    let half = 1usize << (log - 1);
    let mut ys = measured.reserve(half)?;
    let mut xs = measured.reserve(half / 2)?;
    let mut pt = generator_power(1 << (30 - log));
    let step = multiply(pt, pt);
    for j in 0..half {
        ys.push(pt.1);
        if j < half / 2 {
            xs.push(pt.0);
        }
        pt = multiply(pt, step);
    }
    levels.push(ys);
    if !xs.is_empty() {
        levels.push(xs);
    }
    for level in 2..log as usize {
        let previous = &levels[level - 1];
        let mut next = measured.reserve(previous.len() / 2)?;
        for x in &previous[..previous.len() / 2] {
            let square = *x * *x;
            next.push(square + square - M31::ONE);
        }
        levels.push(next);
    }
    Ok(levels)
}

fn invert_twiddles(levels: &mut [Vec<M31>], measured: &mut Measurement) -> Result<(), Error> {
    for level in levels {
        let mut prefixes = measured.reserve(level.len())?;
        let prefix_bytes = measurement::bytes(&prefixes);
        measured.work.inverse_prefix_elements += level.len() as u64;
        let mut product = M31::ONE;
        for value in level.iter() {
            prefixes.push(product);
            product = product * *value;
        }
        // All factors are nonzero by the fixed-domain argument in RFC-0010 A2.
        let mut inverse = product.pow(u64::from(M31::MODULUS) - 2);
        for (value, prefix) in level.iter_mut().zip(prefixes).rev() {
            let original = *value;
            *value = inverse * prefix;
            inverse = inverse * original;
        }
        measured.release(prefix_bytes);
    }
    Ok(())
}

fn bit_reverse<K>(values: &mut [K], log: u32) {
    for j in 0..values.len() {
        let reversed = j.reverse_bits() >> (usize::BITS - log);
        if j < reversed {
            values.swap(j, reversed);
        }
    }
}

fn transform_recorded<K: Field>(
    values: &mut [K],
    inverse: bool,
    measured: &mut Measurement,
) -> Result<(), Error> {
    if values.len() == 1 {
        return Ok(());
    }
    let log = values.len().trailing_zeros();
    let mut levels = twiddles(log, measured)?;
    let level_bytes =
        measurement::bytes(&levels) + levels.iter().map(measurement::bytes).sum::<usize>();
    measured.work.twiddle_elements += (values.len() - 1) as u64;
    measured.work.circle_transform_additions += values.len() as u64 * u64::from(log);
    measured.work.circle_transform_products +=
        values.len() as u64 / 2 * u64::from(log) + if inverse { values.len() as u64 } else { 0 };
    if inverse {
        invert_twiddles(&mut levels, measured)?;
        for level in &levels {
            let width = 2 * level.len();
            for block in values.chunks_exact_mut(width) {
                for (j, twiddle) in level.iter().enumerate() {
                    let opposite = width - 1 - j;
                    let (a, b) = (block[j], block[opposite]);
                    block[j] = a + b;
                    block[opposite] = (a - b) * K::from_i64(i64::from(twiddle.as_u32()));
                }
                // Reverse pairing writes odd values backward; restore quotient order.
                block[level.len()..].reverse();
            }
        }
        bit_reverse(values, log);
        // Each omitted /2 contributes to N; normalize once before returning (A2).
        let scale = M31::from_u64(values.len() as u64).pow(u64::from(M31::MODULUS) - 2);
        let scale = K::from_i64(i64::from(scale.as_u32()));
        for value in values {
            *value = *value * scale;
        }
    } else {
        bit_reverse(values, log);
        for level in levels.iter().rev() {
            let width = 2 * level.len();
            for block in values.chunks_exact_mut(width) {
                block[level.len()..].reverse();
                for (j, twiddle) in level.iter().enumerate() {
                    let opposite = width - 1 - j;
                    let a = block[j];
                    let b = block[opposite] * K::from_i64(i64::from(twiddle.as_u32()));
                    block[j] = a + b;
                    block[opposite] = a - b;
                }
            }
        }
    }
    measured.release(level_bytes);
    Ok(())
}

#[cfg(test)]
fn transform<K: Field>(values: &mut [K], inverse: bool) -> Result<(), Error> {
    transform_recorded(values, inverse, &mut Measurement::default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_capacity_overflow() {
        assert_eq!(reserved::<M31>(usize::MAX), Err(Error::Capacity));
    }

    #[test]
    fn matches_reference_twiddle_inverses_and_transform_round_trips() {
        for log in 0..=10 {
            let mut measured = Measurement::default();
            let original = twiddles(log, &mut measured).expect("twiddles");
            let mut inverse = original.clone();
            invert_twiddles(&mut inverse, &mut measured).expect("inversion");
            assert_eq!(original.iter().map(Vec::len).sum::<usize>(), (1 << log) - 1);
            for (a, b) in original.iter().flatten().zip(inverse.iter().flatten()) {
                assert_eq!(*a * *b, M31::ONE);
            }
            let mut values: Vec<_> = (0..1 << log).map(M31::from_i64).collect();
            let expected = values.clone();
            transform(&mut values, false).expect("evaluation");
            transform(&mut values, true).expect("interpolation");
            assert_eq!(values, expected);
        }
        assert_eq!(generator_power(1 << 30), (-M31::ONE, M31::ZERO));
        assert_eq!(
            multiply(generator_power(1 << 30), generator_power(1 << 30)),
            (M31::ONE, M31::ZERO)
        );
    }
}

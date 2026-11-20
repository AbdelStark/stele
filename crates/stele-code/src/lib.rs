//! Canonical circle/v2 encoding, RFC-0010 A2/A4. Encoding admits no PCS profile.
#![forbid(unsafe_code)]
#![no_std]
#![cfg_attr(not(test), deny(clippy::float_arithmetic))]

extern crate alloc;
use alloc::vec::Vec;
#[cfg(feature = "std")]
use rayon::prelude::*;
use stele_field::{Field, M31};
mod encoder;
mod measurement;
pub mod registry;
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
    /// No admitted PCS parameter set exists for this request (RFC-0010 A1).
    UnsupportedParameters,
    /// A registry export differs from the compiled catalog (RFC-0010 A1).
    InvalidRegistry,
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

/// Coefficient-form M31 circle Reed–Solomon code (RFC-0029 §1.2, RFC-0010 A17, task E19-03).
///
/// Treats the `2^m` row entries as coefficients in the RFC-0010 A2 tensor basis, zero-pads
/// to `N = 2^(m+b)` (`b ∈ {1, 2, 3, 4}`, `m + b ≤ 30`), and evaluates on `D_(m+b)` with a
/// single forward circle transform. The codeword set and distance (`D = N - C` for `C ≥ 2`,
/// `D = N` for `C = 1`) match [`Circle`]; every codeword column `j` is an inner product with
/// the rank-1 tensor basis vector `g_j` evaluable in `O(m + b)` field operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CircleCoeff {
    log_message: u32,
    log_blowup: u32,
    message_len: usize,
    codeword_len: usize,
}

impl CircleCoeff {
    /// Validate `b ∈ {1, 2, 3, 4}` and `m + b ≤ 30` without allocating (RFC-0010 A17 item 1).
    pub fn new(log_message: u32, log_blowup: u32) -> Result<Self, Error> {
        if !(1..=4).contains(&log_blowup) || log_message > 30 - log_blowup {
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

    /// Parse canonical `stele/circle-coeff-m31/v1 || u8(m) || u8(b)` code identity (27 bytes).
    pub fn from_code_id(id: &[u8]) -> Result<Self, Error> {
        if id.len() != 27 || &id[..25] != b"stele/circle-coeff-m31/v1" {
            return Err(Error::InvalidCodeId);
        }
        Self::new(u32::from(id[25]), u32::from(id[26])).map_err(|_| Error::InvalidCodeId)
    }

    pub fn log_message(&self) -> u32 {
        self.log_message
    }

    pub fn log_blowup(&self) -> u32 {
        self.log_blowup
    }

    pub fn message_len(&self) -> usize {
        self.message_len
    }

    pub fn codeword_len(&self) -> usize {
        self.codeword_len
    }

    /// Canonical coefficient-form code identity (RFC-0010 A17 item 1).
    pub fn code_id(&self) -> [u8; 27] {
        let mut id = [0; 27];
        id[..25].copy_from_slice(b"stele/circle-coeff-m31/v1");
        id[25] = self.log_message as u8;
        id[26] = self.log_blowup as u8;
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

    /// Zero-pad `2^m` coefficients to `N = 2^(m+b)` and run one forward circle transform.
    pub fn encode<K: Field>(&self, row: &[K]) -> Result<Vec<K>, Error> {
        let mut output = reserved(self.codeword_len)?;
        self.encode_into(row, &mut output)?;
        Ok(output)
    }

    /// Encode `row` into a caller-reused buffer `out` (`len == N`), avoiding per-row allocation.
    pub fn encode_into<K: Field>(&self, row: &[K], out: &mut Vec<K>) -> Result<(), Error> {
        self.encode_into_with(row, out, &self.twiddles()?)
    }

    /// The twiddles of this code's `N`-point transform, made once for the rows of a source.
    pub fn twiddles(&self) -> Result<Twiddles, Error> {
        twiddles(
            self.log_message + self.log_blowup,
            &mut Measurement::default(),
        )
        .map(Twiddles)
    }

    /// [`Self::encode_into`] with the twiddles of [`Self::twiddles`]. The coefficients are
    /// placed in bit-reversed order directly, so no swap pass runs: the same codeword.
    pub fn encode_into_with<K: Field>(
        &self,
        row: &[K],
        out: &mut Vec<K>,
        twiddles: &Twiddles,
    ) -> Result<(), Error> {
        self.validate(row)?;
        let log = self.log_message + self.log_blowup;
        if twiddles.0.len() != log as usize {
            return Err(Error::RowShape);
        }
        out.clear();
        if out.capacity() < self.codeword_len {
            out.try_reserve_exact(self.codeword_len - out.len())
                .map_err(|_| Error::Capacity)?;
        }
        out.resize(self.codeword_len, K::from_i64(0));
        if log == 0 {
            out[0] = row[0];
            return Ok(());
        }
        let place = |j: usize, slot: &mut K| {
            if let Some(value) = row.get(j.reverse_bits() >> (usize::BITS - log)) {
                *slot = *value;
            }
        };
        #[cfg(feature = "std")]
        if out.len() >= PARALLEL_LEN {
            out.par_iter_mut()
                .enumerate()
                .with_min_len(PARALLEL_GRAIN)
                .for_each(|(j, slot)| place(j, slot));
        } else {
            out.iter_mut()
                .enumerate()
                .for_each(|(j, slot)| place(j, slot));
        }
        #[cfg(not(feature = "std"))]
        out.iter_mut()
            .enumerate()
            .for_each(|(j, slot)| place(j, slot));
        forward_butterflies(out, &twiddles.0);
        Ok(())
    }

    /// The `m` base-field tensor factors `[f_0, ..., f_{m-1}]` at codeword column `column`
    /// such that `Enc(row)[column] = Σ_{idx=0}^{2^m-1} row[idx] · Π_{k: (idx>>k)&1 == 1} f_k`
    /// (RFC-0029 §2). Runs in `O(m + b)` M31 operations with no domain table allocation.
    pub fn basis_factors(&self, column: usize) -> Result<Vec<M31>, Error> {
        if column >= self.codeword_len {
            return Err(Error::Column);
        }
        let m = self.log_message as usize;
        let mut factors = reserved(m)?;
        if m == 0 {
            return Ok(factors);
        }
        let log = self.log_message + self.log_blowup;
        let half0 = 1usize << (log - 1);
        let (cur, neg_y) = if column < half0 {
            (column, false)
        } else {
            ((2 * half0) - 1 - column, true)
        };
        let exp = (((2 * cur + 1) as u64) << (30 - log)) as u32;
        let pt = generator_power(exp);
        factors.push(if neg_y { -pt.1 } else { pt.1 });
        if m == 1 {
            return Ok(factors);
        }
        let mut x_val = pt.0;
        factors.push(x_val);
        for _ in 2..m {
            let sq = x_val * x_val;
            x_val = sq + sq - M31::ONE;
            factors.push(x_val);
        }
        Ok(factors)
    }

    /// Evaluate the multilinear extension `g̃_column(point)` at an MSB-first `point` of length `m`
    /// in `O(m + b)` field operations (RFC-0029 §2).
    pub fn basis_mle<K: Field>(&self, column: usize, point: &[K]) -> Result<K, Error> {
        if K::MODULUS != M31::MODULUS {
            return Err(Error::FieldMismatch);
        }
        if point.len() != self.log_message as usize {
            return Err(Error::RowShape);
        }
        let factors = self.basis_factors(column)?;
        let one = K::from_i64(1);
        let mut acc = one;
        // `point` is MSB-first: `point[m - 1 - k]` corresponds to bit `k` of the coefficient index.
        let m = factors.len();
        for (k, &f) in factors.iter().enumerate() {
            let r = point[m - 1 - k];
            acc = acc * (one - r + r.mul_m31(f));
        }
        Ok(acc)
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

/// Twiddle levels of one transform size (see [`CircleCoeff::twiddles`]).
pub struct Twiddles(Vec<Vec<M31>>);

/// The butterfly levels of a forward transform over bit-reversed input.
fn forward_butterflies<K: Field>(values: &mut [K], levels: &[Vec<M31>]) {
    for level in levels.iter().rev() {
        let width = 2 * level.len();
        let butterflies = |block: &mut [K]| {
            block[level.len()..].reverse();
            for (j, twiddle) in level.iter().enumerate() {
                let opposite = width - 1 - j;
                let a = block[j];
                let b = block[opposite].mul_m31(*twiddle);
                block[j] = a + b;
                block[opposite] = a - b;
            }
        };
        // Blocks, and the pairs of one block, are independent: any split gives the
        // same values as the loop.
        #[cfg(feature = "std")]
        if values.len() >= PARALLEL_LEN {
            if width <= PARALLEL_GRAIN {
                values
                    .par_chunks_exact_mut(width)
                    .with_min_len(PARALLEL_GRAIN / width)
                    .for_each(butterflies);
            } else {
                for block in values.chunks_exact_mut(width) {
                    let (low, high) = block.split_at_mut(level.len());
                    low.par_iter_mut()
                        .zip(high.par_iter_mut())
                        .zip(level.par_iter())
                        .with_min_len(PARALLEL_GRAIN)
                        .for_each(|((a, b), twiddle)| {
                            let (x, y) = (*a, b.mul_m31(*twiddle));
                            *a = x + y;
                            *b = x - y;
                        });
                    high.reverse();
                }
            }
            continue;
        }
        values.chunks_exact_mut(width).for_each(butterflies);
    }
}

/// A forward transform of at least this many values splits its butterflies on the work pool.
#[cfg(feature = "std")]
const PARALLEL_LEN: usize = 1 << 16;
/// Values per butterfly task.
#[cfg(feature = "std")]
const PARALLEL_GRAIN: usize = 1 << 12;

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
                    block[opposite] = (a - b).mul_m31(*twiddle);
                }
                // Reverse pairing writes odd values backward; restore quotient order.
                block[level.len()..].reverse();
            }
        }
        bit_reverse(values, log);
        // Each omitted /2 contributes to N; normalize once before returning (A2).
        let scale = M31::from_u64(values.len() as u64).pow(u64::from(M31::MODULUS) - 2);
        for value in values {
            *value = value.mul_m31(scale);
        }
    } else {
        bit_reverse(values, log);
        forward_butterflies(values, &levels);
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

    /// A row long enough for the work-pool split (`N = 2^17`) against the independent
    /// basis-factor formula, in both split regimes.
    #[test]
    fn matches_reference_basis_factors_on_a_long_row() {
        let m = 15u32;
        let coeffs: Vec<M31> = (0..1i64 << m)
            .map(|i| M31::from_i64((i * 7919 + 13) % 100_003 - 50_000))
            .collect();
        let cc = CircleCoeff::new(m, 2).expect("circle coeff");
        let cw = cc.encode(&coeffs).expect("encode");
        assert_eq!(cw.len(), 1 << 17);
        for j in [
            0usize,
            1,
            4095,
            4096,
            65_535,
            65_536,
            100_003,
            (1 << 17) - 1,
        ] {
            let factors = cc.basis_factors(j).expect("factors");
            let mut dot = M31::ZERO;
            for (idx, &coeff) in coeffs.iter().enumerate() {
                let g = (0..m as usize)
                    .filter(|k| (idx >> k) & 1 == 1)
                    .fold(M31::ONE, |g, k| g * factors[k]);
                dot = dot + coeff * g;
            }
            assert_eq!(dot, cw[j], "col={j}");
        }
    }

    /// RFC-0029 §1.2 / E19-03: `CircleCoeff` encodes a coefficient row identically to
    /// `Circle` encoding that row's evaluations on `D_m`, and `basis_mle(j, r)` matches
    /// the exact multilinear extension of column `j`'s basis vector `g_j` across all `m, b, j`.
    #[test]
    fn matches_reference_circle_coeff_and_basis_mle() {
        use stele_field::QM31;

        for m in 0..=6u32 {
            let len = 1usize << m;
            let coeffs: Vec<M31> = (0..len)
                .map(|i| M31::from_i64((i as i64 * 37 + 11) % 1009 - 500))
                .collect();
            let mut evals_on_dm = coeffs.clone();
            transform(&mut evals_on_dm, false).expect("eval on D_m");

            for b in 1..=4u32 {
                let cc = CircleCoeff::new(m, b).expect("circle coeff");
                assert_eq!(CircleCoeff::from_code_id(&cc.code_id()), Ok(cc));
                let cw = cc.encode(&coeffs).expect("encode coeff");
                assert_eq!(cw.len(), 1 << (m + b));
                if b <= 2 {
                    let ev = Circle::new(m, b).expect("circle eval");
                    assert_eq!(cw, ev.encode(&evals_on_dm).expect("encode eval"));
                }
                // Check basis_factors and basis_mle on every column (for m <= 4) or sample.
                let step = if m <= 4 { 1 } else { 7 };
                let pt: Vec<QM31> = (0..m)
                    .map(|k| {
                        QM31(
                            stele_field::CM31(
                                M31::from_i64(3 + k as i64 * 17),
                                M31::from_i64(5 + k as i64 * 23),
                            ),
                            stele_field::CM31(
                                M31::from_i64(7 + k as i64 * 29),
                                M31::from_i64(11 + k as i64 * 31),
                            ),
                        )
                    })
                    .collect();
                let one = QM31::from_i64(1);
                for j in (0..cw.len()).step_by(step) {
                    let factors = cc.basis_factors(j).expect("factors");
                    // Reconstruct g_j[idx] = Π_{k: bit k of idx == 1} factors[k].
                    let mut dot = M31::ZERO;
                    let mut mle_direct = QM31::from_i64(0);
                    for (idx, &coeff) in coeffs.iter().enumerate() {
                        let mut g = M31::ONE;
                        let mut eq = one;
                        for k in 0..m as usize {
                            let r = pt[m as usize - 1 - k];
                            if (idx >> k) & 1 == 1 {
                                g = g * factors[k];
                                eq = eq * r;
                            } else {
                                eq = eq * (one - r);
                            }
                        }
                        dot = dot + coeff * g;
                        mle_direct = mle_direct + eq.mul_m31(g);
                    }
                    assert_eq!(dot, cw[j], "m={m} b={b} col={j}");
                    assert_eq!(
                        cc.basis_mle(j, &pt).expect("mle"),
                        mle_direct,
                        "mle m={m} b={b} col={j}"
                    );
                }
            }
        }
        // Reject invalid b or m + b > 30 (RFC-0010 A17).
        assert_eq!(CircleCoeff::new(10, 0), Err(Error::InvalidSize));
        assert_eq!(CircleCoeff::new(10, 5), Err(Error::InvalidSize));
        assert_eq!(CircleCoeff::new(30, 1), Err(Error::InvalidSize));
        assert_eq!(CircleCoeff::new(27, 4), Err(Error::InvalidSize));
        assert!(CircleCoeff::new(26, 4).is_ok());
    }
}

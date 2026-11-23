//! RFC-0025 §2.1–2.5/execution: immutable checked physical bytes and exact projections.
use super::{
    capture::{put, Embedding, Norm, Projection},
    reserved, signed, wide, Error,
};
use crate::{
    functions::Representation,
    model::{Artifact, ArtifactLayout, Model, Preparation, Role, Scales},
    numerics,
    row::QuantisedRow,
};
use alloc::vec::Vec;

struct Record<'a> {
    raw: &'a [u8],
    bits: u8,
    columns: usize,
    rows: usize,
    role: Role,
    layer: Option<u16>,
}
pub(super) struct Data<'a> {
    pub(super) model: &'a Model,
    pub(super) scales: &'a Scales,
    records: Vec<Record<'a>>,
    pub(super) scope: [[u8; 32]; 3],
}
/// Matrix cells from which the rows of a projection split over threads: the vocabulary
/// head, not a block's projections.
#[cfg(feature = "std")]
const PARALLEL_CELLS: usize = 1 << 22;

/// `[row(0), .., row(rows - 1)]`. A row depends only on its index, so with `std` the rows
/// of a large matrix run in blocks on scoped threads: the same values in the same order,
/// and the first failing row's error.
fn rows_in_blocks<T: Copy + Default + Send>(
    rows: usize,
    columns: usize,
    row: impl Fn(usize) -> Result<T, Error> + Sync,
) -> Result<Vec<T>, Error> {
    #[cfg(feature = "std")]
    let workers = if rows.saturating_mul(columns) >= PARALLEL_CELLS {
        crate::workers().min(rows / 64)
    } else {
        1
    };
    #[cfg(not(feature = "std"))]
    let workers = {
        let _ = columns;
        1
    };
    rows_on(rows, workers, row)
}

/// [`rows_in_blocks`] on `workers` threads; one, or a build without `std`, is the loop.
fn rows_on<T: Copy + Default + Send>(
    rows: usize,
    workers: usize,
    row: impl Fn(usize) -> Result<T, Error> + Sync,
) -> Result<Vec<T>, Error> {
    let mut out = reserved(rows)?;
    out.resize(rows, T::default());
    let fill = |first: usize, block: &mut [T]| -> Result<(), Error> {
        for (i, slot) in block.iter_mut().enumerate() {
            *slot = row(first + i)?;
        }
        Ok(())
    };
    #[cfg(feature = "std")]
    if workers > 1 && rows > 0 {
        let per = rows.div_ceil(workers);
        let fill = &fill;
        std::thread::scope(|scope| {
            let mut handles = reserved(workers)?;
            for (b, block) in out.chunks_mut(per).enumerate() {
                handles.push(scope.spawn(move || fill(b * per, block)));
            }
            crate::join_all(handles)
        })?;
        return Ok(out);
    }
    #[cfg(not(feature = "std"))]
    let _ = workers;
    fill(0, &mut out)?;
    Ok(out)
}

impl<'a> Data<'a> {
    pub(super) fn new(
        model: &'a Model,
        prep: &Preparation<'_>,
        scales: &'a Scales,
        raw: &'a [u8],
        expected: &[u8; 32],
    ) -> Result<Self, Error> {
        let artifact = Artifact::decode_expected(model, prep, scales, expected, raw)?;
        let layout = ArtifactLayout::new(model)?;
        let mut records = reserved(layout.records().len())?;
        for record in layout.records() {
            let physical = model
                .shape()
                .physical(record.ordinal())
                .ok_or(Error::Arithmetic)?;
            let offset = usize::try_from(record.payload_offset()).map_err(|_| Error::Capacity)?;
            let length = usize::try_from(record.payload_length()).map_err(|_| Error::Capacity)?;
            records.push(Record {
                raw: raw
                    .get(offset..offset.checked_add(length).ok_or(Error::Capacity)?)
                    .ok_or(Error::Arithmetic)?,
                bits: record.bits(),
                rows: physical.dimensions()[0] as usize,
                columns: physical.dimensions().get(1).copied().unwrap_or(1) as usize,
                role: physical.role(),
                layer: physical.layer(),
            });
        }
        Ok(Self {
            model,
            scales,
            records,
            scope: [model.identity(), scales.identity(), artifact.identity()],
        })
    }
    pub(super) fn ordinal(&self, role: Role, layer: Option<u16>) -> Result<usize, Error> {
        let role = if role == Role::Head && self.model.shape().family() == 0 {
            Role::Token
        } else {
            role
        };
        self.records
            .iter()
            .position(|r| r.role == role && r.layer == layer)
            .ok_or(Error::Arithmetic)
    }
    pub(super) fn code(&self, ordinal: usize, index: usize) -> i16 {
        let r = &self.records[ordinal];
        match r.bits {
            16 => i16::from_le_bytes([r.raw[2 * index], r.raw[2 * index + 1]]),
            8 => i16::from(r.raw[index] as i8),
            _ => {
                let n = (r.raw[index / 2] >> (4 * (index % 2))) & 15;
                if n >= 8 {
                    i16::from(n) - 16
                } else {
                    i16::from(n)
                }
            }
        }
    }
    /// Residual-stream width: 24 for a wide Model (RFC-0004 A14), else 16.
    pub(super) fn width(&self) -> u32 {
        if self.model.wide() {
            24
        } else {
            16
        }
    }
    pub(super) fn linear(
        &self,
        role: Role,
        layer: Option<u16>,
        row: &QuantisedRow,
        fraction: u8,
        capture: Option<&mut Projection>,
    ) -> Result<Vec<i16>, Error> {
        self.affine(role, layer, row, fraction, wide, capture)
    }
    /// O/down projections feed a residual; their outputs take the stream width.
    pub(super) fn linear_residual(
        &self,
        role: Role,
        layer: Option<u16>,
        row: &QuantisedRow,
        fraction: u8,
        capture: Option<&mut Projection>,
    ) -> Result<Vec<i32>, Error> {
        let bits = self.width();
        self.affine(role, layer, row, fraction, |v| signed(v, bits), capture)
    }
    fn affine<T>(
        &self,
        role: Role,
        layer: Option<u16>,
        row: &QuantisedRow,
        fraction: u8,
        output: impl Fn(i64) -> Result<T, Error>,
        mut capture: Option<&mut Projection>,
    ) -> Result<Vec<T>, Error> {
        let ordinal = self.ordinal(role, layer)?;
        if row.exponent().is_some() {
            return self.affine_power(ordinal, row, fraction, output, capture);
        }
        let r = &self.records[ordinal];
        if row.codes().len() != r.columns {
            return Err(Error::Arithmetic);
        }
        let scale = self
            .scales
            .matrix(ordinal as u16)
            .ok_or(Error::Arithmetic)?;
        let bias = if self.model.shape().family() == 1 || role == Role::Head {
            None
        } else {
            Some(self.ordinal(
                match role {
                    Role::Query => Role::QueryBias,
                    Role::Key => Role::KeyBias,
                    Role::Value => Role::ValueBias,
                    Role::Output => Role::OutputBias,
                    Role::Up => Role::UpBias,
                    Role::Down => Role::DownBias,
                    _ => return Err(Error::Arithmetic),
                },
                layer,
            )?)
        };
        let fb = bias.map_or(0, |i| self.model.formats()[i].parameter());
        let shift = i32::from(scale.exponent()) - i32::from(row.fraction()) + i32::from(fraction);
        let mut out = reserved(r.rows)?;
        let scales = row.scales();
        let g = r.columns / scales.len();
        // RFC-0004 A15: A' = sum_i s_k(i)*q_i*w_i (|A'| < 2^51), then one rounding.
        let dot_of = |j: usize| -> i128 {
            if scales.len() > 1 {
                let dot: i64 = if r.bits == 8 {
                    // The same sum, one int32 dot per group (|dot| < 2^28, as in `dot`).
                    let w = &r.raw[j * r.columns..(j + 1) * r.columns];
                    row.codes()
                        .chunks(g)
                        .zip(w.chunks(g))
                        .zip(scales)
                        .map(|((x, w), s)| i64::from(*s) * i64::from(stele_simd::dot_i8(x, w)))
                        .sum()
                } else {
                    row.codes()
                        .iter()
                        .enumerate()
                        .map(|(k, x)| {
                            i64::from(scales[k / g])
                                * i64::from(*x)
                                * i64::from(self.code(ordinal, j * r.columns + k))
                        })
                        .sum()
                };
                i128::from(dot)
            } else {
                self.dot(ordinal, row, j)
            }
        };
        let bias_shift = i32::from(fraction) - i32::from(fb);
        // Each output row's dot, scaled product, bias and rounded value.
        let rows = rows_in_blocks(r.rows, r.columns, |j| {
            let dot = dot_of(j);
            let product = if scales.len() > 1 {
                dot * i128::from(scale.mantissas()[j])
            } else {
                dot * i128::from(scale.mantissas()[j]) * i128::from(row.scale())
            };
            let b = bias.map_or(0, |i| self.code(i, j));
            let value = numerics::scaled_sum(product, shift, i128::from(b), bias_shift, 1)?;
            Ok((dot, product, b, value))
        })?;
        for (dot, product, b, value) in rows {
            if let Some(w) = capture.as_deref_mut() {
                w.push(dot, product, b)?;
                w.output
                    .scaled((product, shift), (i128::from(b), bias_shift), 1, value)?;
            }
            out.push(output(value)?);
        }
        Ok(out)
    }
    /// RFC-0004 A16: a power-of-two row into a matrix with power-of-two channel scales.
    /// `lambda_j = f - fo - e - k_j >= 1` for the channel mantissa `2^k_j`. With
    /// `a' = min(a, lambda_min - 1)` and `a'' = a - a'`, the output is
    /// `R+(A_j / 2^(lambda_j - a')) * 2^a''`: one rounding, half up.
    fn affine_power<T>(
        &self,
        ordinal: usize,
        row: &QuantisedRow,
        fraction: u8,
        output: impl Fn(i64) -> Result<T, Error>,
        mut capture: Option<&mut Projection>,
    ) -> Result<Vec<T>, Error> {
        let r = &self.records[ordinal];
        let codes = row.wide_codes();
        let a = i32::from(row.exponent().ok_or(Error::Arithmetic)?);
        let scale = self
            .scales
            .matrix(ordinal as u16)
            .ok_or(Error::Arithmetic)?;
        let mantissas = scale.mantissas();
        if codes.len() != r.columns
            || mantissas.len() != r.rows
            || mantissas.iter().any(|m| !m.is_power_of_two())
        {
            return Err(Error::Arithmetic);
        }
        let high = i32::from(row.fraction()) - i32::from(fraction) - i32::from(scale.exponent());
        let shift = |m: u16| high - m.trailing_zeros() as i32;
        let low = mantissas.iter().map(|m| shift(*m)).min().unwrap_or(0);
        if low < 1 {
            return Err(Error::Arithmetic);
        }
        let kept = a.min(low - 1);
        let excess = (a - kept) as u32;
        let rows = rows_in_blocks(r.rows, r.columns, |j| {
            let dot: i64 = if r.bits == 8 {
                let w = &r.raw[j * r.columns..(j + 1) * r.columns];
                // |q*w| < 2^18, so 2^12 terms of one block sum exactly in i32.
                codes
                    .chunks(4096)
                    .zip(w.chunks(4096))
                    .map(|(x, w)| {
                        let sum: i32 = x
                            .iter()
                            .zip(w)
                            .map(|(x, w)| i32::from(*x) * i32::from(*w as i8))
                            .sum();
                        i64::from(sum)
                    })
                    .sum()
            } else {
                codes
                    .iter()
                    .enumerate()
                    .map(|(k, x)| {
                        i64::from(*x) * i64::from(self.code(ordinal, j * r.columns + k))
                    })
                    .sum()
            };
            let s = (shift(mantissas[j]) - kept) as u32;
            // |A| < 2^33, so a shift past 62 bits rounds to zero.
            let z = if s > 62 {
                0
            } else {
                (dot + (1i64 << (s - 1))) >> s
            };
            Ok((dot, z))
        })?;
        let mut out = reserved(r.rows)?;
        for (dot, z) in rows {
            let y = z << excess;
            if let Some(w) = capture.as_deref_mut() {
                // The one rounding is the module's; the capture holds the output itself.
                w.push(i128::from(dot), i128::from(dot), 0)?;
                w.output.push(i128::from(y), 1, y)?;
            }
            out.push(output(y)?);
        }
        Ok(out)
    }
    fn dot(&self, ordinal: usize, row: &QuantisedRow, j: usize) -> i128 {
        let r = &self.records[ordinal];
        {
            // Accepted width <=16384 and symmetric int8 operands give |dot|<2^28.
            let dot: i32 = if r.bits == 8 {
                stele_simd::dot_i8(row.codes(), &r.raw[j * r.columns..(j + 1) * r.columns])
            } else {
                row.codes()
                    .iter()
                    .enumerate()
                    .map(|(k, x)| i32::from(*x) * i32::from(self.code(ordinal, j * r.columns + k)))
                    .sum()
            };
            i128::from(dot)
        }
    }
    pub(super) fn embed(
        &self,
        token: u32,
        position: usize,
        mut capture: Option<&mut Embedding>,
    ) -> Result<Vec<i16>, Error> {
        let width = usize::from(self.model.shape().width());
        let t = self.ordinal(Role::Token, None)?;
        let ts = self.scales.matrix(t as u16).ok_or(Error::Arithmetic)?;
        let p = if self.model.shape().family() == 0 {
            Some(self.ordinal(Role::Position, None)?)
        } else {
            None
        };
        let ps = p.and_then(|i| self.scales.matrix(i as u16));
        let f = i32::from(self.model.initial_fraction());
        let mut out = reserved(width)?;
        for k in 0..width {
            let left = i128::from(self.code(t, token as usize * width + k))
                * i128::from(ts.mantissas()[token as usize]);
            let (right, pe) = match (p, ps) {
                (Some(i), Some(s)) => (
                    i128::from(self.code(i, position * width + k))
                        * i128::from(s.mantissas()[position]),
                    i32::from(s.exponent()),
                ),
                _ => (0, 0),
            };
            let (le, re) = (i32::from(ts.exponent()) + f, pe + f);
            let value = numerics::scaled_sum(left, le, right, re, 1)?;
            if let Some(w) = capture.as_deref_mut() {
                w.token = token;
                put(&mut w.token_term, left)?;
                put(&mut w.position_term, right)?;
                w.output.scaled((left, le), (right, re), 1, value)?;
            }
            out.push(wide(value)?);
        }
        Ok(out)
    }
    pub(super) fn normalize(
        &self,
        r: &Representation,
        values: &[i32],
        role: Role,
        layer: Option<u16>,
        capture: Option<&mut Norm>,
    ) -> Result<Vec<i16>, Error> {
        let gain = self.ordinal(role, layer)?;
        let mut gains = reserved(values.len())?;
        for j in 0..values.len() {
            gains.push(self.code(gain, j));
        }
        if self.model.shape().family() == 1 {
            let norm = r.function().evaluate_rmsnorm_wide(values, &gains)?;
            if let Some(w) = capture {
                w.rms(values, &gains, &norm)?;
            }
            return super::copy(norm.outputs());
        }
        // GPT-2 has no wide form: its residual stream is int16 throughout.
        let mut narrow = reserved(values.len())?;
        for v in values {
            narrow.push(wide(i64::from(*v))?);
        }
        let bias = self.ordinal(
            match role {
                Role::FirstGain => Role::FirstBias,
                Role::SecondGain => Role::SecondBias,
                Role::FinalGain => Role::FinalBias,
                _ => return Err(Error::Arithmetic),
            },
            layer,
        )?;
        let mut biases = reserved(values.len())?;
        for j in 0..values.len() {
            biases.push(self.code(bias, j));
        }
        let (outputs, parts) = r.function().layernorm_row(&narrow, &gains, &biases)?;
        if let Some(w) = capture {
            let p = r.function().parameters();
            w.layer(&narrow, (&gains, &biases), (&parts, &outputs), (p[4], p[5]))?;
        }
        Ok(outputs)
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    /// The split of a projection's rows against the plain loop (review of E22-10, second
    /// pass, S1): row counts that do not fill the last block, at 1, 2, 3 and 7 workers.
    /// With two failing rows in different blocks, the lower row's error is returned.
    #[test]
    fn matches_reference_rows_at_every_worker_count_and_returns_the_first_failing_row() {
        let row = |j: usize| -> Result<u64, Error> {
            Ok((j as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 5)
        };
        for rows in [0usize, 1, 2, 6, 7, 100, 101] {
            let expected: Vec<u64> = (0..rows).map(|j| row(j).expect("row")).collect();
            for workers in [1, 2, 3, 7] {
                assert_eq!(
                    rows_on(rows, workers, row),
                    Ok(expected.clone()),
                    "{rows} rows, {workers} workers"
                );
            }
        }
        let failing = |j: usize| match j {
            30 => Err(Error::Range),
            90 => Err(Error::Length),
            _ => Ok(j as u64),
        };
        for workers in [1, 2, 3, 7] {
            assert_eq!(rows_on(101, workers, failing), Err(Error::Range));
        }
    }
}

//! RFC-0025 §2.1–2.5/execution: immutable checked physical bytes and exact projections.
use super::{reserved, signed, wide, Error};
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
    scales: &'a Scales,
    records: Vec<Record<'a>>,
    pub(super) scope: [[u8; 32]; 3],
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
    fn ordinal(&self, role: Role, layer: Option<u16>) -> Result<usize, Error> {
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
    fn code(&self, ordinal: usize, index: usize) -> i16 {
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
    ) -> Result<Vec<i16>, Error> {
        self.affine(role, layer, row, fraction, wide)
    }
    /// O/down projections feed a residual; their outputs take the stream width.
    pub(super) fn linear_residual(
        &self,
        role: Role,
        layer: Option<u16>,
        row: &QuantisedRow,
        fraction: u8,
    ) -> Result<Vec<i32>, Error> {
        let bits = self.width();
        self.affine(role, layer, row, fraction, |v| signed(v, bits))
    }
    fn affine<T>(
        &self,
        role: Role,
        layer: Option<u16>,
        row: &QuantisedRow,
        fraction: u8,
        output: impl Fn(i64) -> Result<T, Error>,
    ) -> Result<Vec<T>, Error> {
        let ordinal = self.ordinal(role, layer)?;
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
        for j in 0..r.rows {
            // RFC-0004 A15: A' = sum_i s_k(i)*q_i*w_i (|A'| < 2^51), then one rounding.
            let product = if scales.len() > 1 {
                let dot: i64 = row
                    .codes()
                    .iter()
                    .enumerate()
                    .map(|(k, x)| {
                        i64::from(scales[k / g])
                            * i64::from(*x)
                            * i64::from(self.code(ordinal, j * r.columns + k))
                    })
                    .sum();
                i128::from(dot) * i128::from(scale.mantissas()[j])
            } else {
                self.dot(ordinal, row, j)
                    * i128::from(scale.mantissas()[j])
                    * i128::from(row.scale())
            };
            let b = bias.map_or(0, |i| self.code(i, j));
            out.push(output(numerics::scaled_sum(
                product,
                shift,
                i128::from(b),
                i32::from(fraction) - i32::from(fb),
                1,
            )?)?);
        }
        Ok(out)
    }
    fn dot(&self, ordinal: usize, row: &QuantisedRow, j: usize) -> i128 {
        let r = &self.records[ordinal];
        {
            // Accepted width <=16384 and symmetric int8 operands give |dot|<2^28.
            let dot: i32 = if r.bits == 8 {
                row.codes()
                    .iter()
                    .zip(&r.raw[j * r.columns..(j + 1) * r.columns])
                    .map(|(x, w)| i32::from(*x) * i32::from(*w as i8))
                    .sum()
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
    pub(super) fn embed(&self, token: u32, position: usize) -> Result<Vec<i16>, Error> {
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
            out.push(wide(numerics::scaled_sum(
                left,
                i32::from(ts.exponent()) + f,
                right,
                pe + f,
                1,
            )?)?);
        }
        Ok(out)
    }
    pub(super) fn normalize(
        &self,
        r: &Representation,
        values: &[i32],
        role: Role,
        layer: Option<u16>,
    ) -> Result<Vec<i16>, Error> {
        let gain = self.ordinal(role, layer)?;
        let mut gains = reserved(values.len())?;
        for j in 0..values.len() {
            gains.push(self.code(gain, j));
        }
        if self.model.shape().family() == 1 {
            let norm = r.function().evaluate_rmsnorm_wide(values, &gains)?;
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
        Ok(r.function().evaluate_layernorm(&narrow, &gains, &biases)?)
    }
}

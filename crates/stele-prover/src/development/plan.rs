//! The development relation of one prefill window (RFC-0026 §3.8, §5, §5.1).
//!
//! [`Layout::declare`] instantiates every module in RFC-0026 §5 order from plan data
//! only (Model, Scales, the public 1-D records and the statement), wiring each module
//! to the `ColumnId`s of its upstream outputs. Prover and verifier both run it.
//! [`Layout::assign`] maps the executor's `Capture` onto each module's capture type and
//! fills the weight columns; it is the prover's only witness path.
//!
//! Weight columns are declared in RFC-0026 §2.2 plan order: the embedding, then per
//! layer Q, K, V, O, gate, up, down, then the head.

use super::{Error, Statement};
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use stele_reductions::development::embedding::{Embedding, EmbeddingCapture, EmbeddingPlan};
use stele_reductions::development::rmsnorm::{RmsNorm, RmsNormPlan, RmsNormRow};
use stele_reductions::development::{
    Attention, AttentionCapture, AttentionPlan, ConversionCapture, Policy, PositionCapture,
    Projection, ProjectionCapture, ProjectionPlan, RowConversion,
};
use stele_reductions::finish::{Finish, FinishCapture, FinishPlan};
use stele_reductions::residual::{Residual, ResidualCapture};
use stele_reductions::rope::Rope;
use stele_reductions::silu::{GatedCapture, GatedConversion, GatedProduct};
use stele_reductions::stele_cqis::execution::capture::{Block, Capture, Quantised};
use stele_reductions::stele_cqis::functions::Descriptor;
use stele_reductions::stele_cqis::model::{Model, Role, Scales};
use stele_reductions::stele_cqis::tables::Table as CqisTable;
use stele_reductions::stele_ir::relation::{ColumnId, Kind, Module, Relation, Values};

/// Plan data the verifier knows: the decoded Model and Scales and the 1-D records
/// (RFC-0026 A2), by artifact ordinal.
pub struct PlanData<'a> {
    pub model: &'a Model,
    pub scales: &'a Scales,
    /// `(ordinal, codes)` of every 1-D record, in artifact record order.
    pub vectors: &'a [(u16, Vec<i16>)],
    /// dev-zk: gain-derived columns at their full widths (E12-27).
    pub zk: bool,
}

impl PlanData<'_> {
    pub(crate) fn ordinal(&self, role: Role, layer: Option<u16>) -> Result<u16, Error> {
        let shape = self.model.shape();
        (0..shape.record_count())
            .find(|&i| {
                shape
                    .physical(i)
                    .is_some_and(|p| p.role() == role && p.layer() == layer)
            })
            .ok_or(Error::UnsupportedModel)
    }

    fn vector(&self, role: Role, layer: Option<u16>) -> Result<Vec<i16>, Error> {
        let ordinal = self.ordinal(role, layer)?;
        self.vectors
            .iter()
            .find(|(o, _)| *o == ordinal)
            .map(|(_, v)| v.clone())
            .ok_or(Error::StatementMismatch)
    }

    /// Projection plan of `(role, layer)` reading a row of fraction `unit`, output fraction `fo`.
    fn projection(
        &self,
        role: Role,
        layer: Option<u16>,
        rows: usize,
        unit: u8,
        fo: u8,
    ) -> Result<ProjectionPlan, Error> {
        let ordinal = self.ordinal(role, layer)?;
        let physical = self
            .model
            .shape()
            .physical(ordinal)
            .ok_or(Error::UnsupportedModel)?;
        let scale = self.scales.matrix(ordinal).ok_or(Error::UnsupportedModel)?;
        let dims = physical.dimensions();
        Ok(ProjectionPlan {
            rows,
            inner: dims[1] as usize,
            outputs: dims[0] as usize,
            weight_bits: self.model.formats()[usize::from(ordinal)].bits(),
            mantissas: scale.mantissas().to_vec(),
            shift: i32::from(scale.exponent()) - i32::from(unit) + i32::from(fo),
        })
    }
}

fn policy(p: stele_reductions::stele_cqis::model::Policy) -> Result<Policy, Error> {
    Ok(match p.mode() {
        0 => Policy::Dynamic,
        1 => Policy::Static(p.scale()),
        2 => Policy::Grouped(p.scale()),
        _ => return Err(Error::UnsupportedModel),
    })
}

fn unsupported<E>(_: E) -> Error {
    Error::UnsupportedModel
}

/// The modules of one layer, in RFC-0026 §5 order.
struct LayerModules {
    norm1: RmsNorm,
    row1: RowConversion,
    q: Projection,
    k: Projection,
    v: Projection,
    rope_q: Rope,
    rope_k: Rope,
    /// Q', K' and V row conversions read by attention (RFC-0026 §5 row 6).
    attention_rows: [RowConversion; 3],
    attention: Attention,
    row_o: RowConversion,
    o: Projection,
    mid: Residual,
    norm2: RmsNorm,
    row2: RowConversion,
    gate: Projection,
    up: Projection,
    gated: GatedProduct,

    down_row: GatedConversion,
    down: Projection,
    residual: Residual,
    norm2_descriptor: Descriptor,
    norm1_descriptor: Descriptor,
    gains: [Vec<i16>; 2],
}

/// Every module of one window, declared into one [`Relation`].
pub struct Layout {
    pub relation: Relation,
    embedding: Embedding,
    layers: Vec<LayerModules>,
    final_descriptor: Descriptor,
    final_gains: Vec<i16>,
    finish: Finish,
    /// Weight columns in plan order, with their `(role, layer)`.
    pub weights: Vec<(ColumnId, Role, Option<u16>)>,
}

fn declared<T>(id: Option<T>) -> Result<T, Error> {
    id.ok_or(Error::UnsupportedModel)
}

impl Layout {
    /// Declare the window's relation from plan data and the statement (RFC-0026 §8 step 2).
    pub fn declare(plan: &PlanData<'_>, statement: &Statement) -> Result<Self, Error> {
        let model = plan.model;
        let shape = model.shape();
        if shape.family() != 1 || model.wide() || shape.groups() != shape.heads() {
            return Err(Error::UnsupportedModel);
        }
        let t = statement.tokens.len();
        let (d, f) = (usize::from(shape.width()), usize::from(shape.hidden()));
        let (heads, hw) = (shape.heads(), shape.head_width());
        let mut relation = Relation::default();
        let mut weights = Vec::new();

        let token = plan.ordinal(Role::Token, None)?;
        let token_scale = plan.scales.matrix(token).ok_or(Error::UnsupportedModel)?;
        let mut embedding = Embedding::new(
            EmbeddingPlan {
                tokens: statement.tokens.clone(),
                vocabulary: shape.vocabulary(),
                width: shape.width(),
                code_bits: model.formats()[usize::from(token)].bits(),
                mantissas: token_scale.mantissas().to_vec(),
                exponent: token_scale.exponent(),
                fraction: model.initial_fraction(),
            },
            "G/embedding",
        )
        .map_err(unsupported)?;
        embedding.declare(&mut relation);
        weights.push((declared(embedding.weight())?, Role::Token, None));
        let mut stream = declared(embedding.output())?;
        let mut incoming = model.initial_fraction();

        let mut layers = Vec::new();
        for (l, block) in model.blocks().iter().enumerate() {
            let layer = Some(l as u16);
            let fr = block.projection_fractions();
            let p = block.policies();
            let norm1_descriptor = *block.first_norm().function();
            let norm2_descriptor = *block.second_norm().function();
            let gains = [
                plan.vector(Role::FirstGain, layer)?,
                plan.vector(Role::SecondGain, layer)?,
            ];
            let s = |name: &str| format!("L{l}/{name}");
            let mut norm1 = RmsNorm::new(
                RmsNormPlan {
                    descriptor: norm1_descriptor,
                    gains: gains[0].clone(),
                    rows: t,
                    fixed_widths: plan.zk,
                },
                stream,
                &s("norm1"),
            )
            .map_err(unsupported)?;
            norm1.declare(&mut relation);
            let mut row1 =
                RowConversion::new(&s("row1"), declared(norm1.output())?, t, d, policy(p[0])?)
                    .map_err(unsupported)?;
            row1.declare(&mut relation);
            let unit1 = norm1_descriptor.parameters()[4];
            let input1 = declared(row1.output())?;
            let project = |relation: &mut Relation,
                           weights: &mut Vec<_>,
                           name: &str,
                           role: Role,
                           input,
                           unit: u8,
                           fo: u8|
             -> Result<Projection, Error> {
                let plan = plan.projection(role, layer, t, unit, fo)?;
                let mut m = Projection::new(&s(name), input, None, plan).map_err(unsupported)?;
                m.declare(relation);
                weights.push((declared(m.weight())?, role, layer));
                Ok(m)
            };
            let q = project(
                &mut relation,
                &mut weights,
                "q",
                Role::Query,
                input1,
                unit1,
                fr[0],
            )?;
            let k = project(
                &mut relation,
                &mut weights,
                "k",
                Role::Key,
                input1,
                unit1,
                fr[1],
            )?;
            let v = project(
                &mut relation,
                &mut weights,
                "v",
                Role::Value,
                input1,
                unit1,
                fr[2],
            )?;
            let mut rope_q = Rope::new(
                l,
                "q",
                declared(q.output())?,
                t,
                heads,
                hw,
                block.rotation(),
            )
            .map_err(unsupported)?;
            rope_q.declare(&mut relation);
            let mut rope_k = Rope::new(
                l,
                "k",
                declared(k.output())?,
                t,
                shape.groups(),
                hw,
                block.rotation(),
            )
            .map_err(unsupported)?;
            rope_k.declare(&mut relation);
            let kv = usize::from(shape.groups()) * usize::from(hw);
            let convert = |relation: &mut Relation, name: &str, input, width, p| {
                let mut row = RowConversion::new(&s(name), input, t, width, policy(p)?)
                    .map_err(unsupported)?;
                row.declare(relation);
                Ok::<_, Error>(row)
            };
            let attention_rows = [
                convert(
                    &mut relation,
                    "row_q",
                    declared(rope_q.columns().map(|c| c.output))?,
                    d,
                    p[1],
                )?,
                convert(
                    &mut relation,
                    "row_k",
                    declared(rope_k.columns().map(|c| c.output))?,
                    kv,
                    p[2],
                )?,
                convert(&mut relation, "row_v", declared(v.output())?, kv, p[3])?,
            ];
            let rows_out = attention_rows
                .iter()
                .map(|row| declared(row.output()))
                .collect::<Result<Vec<_>, _>>()?;
            let mut attention = Attention::new(
                l,
                AttentionPlan {
                    rows: t,
                    heads: usize::from(heads),
                    groups: usize::from(shape.groups()),
                    head_width: usize::from(hw),
                    query: rows_out[0],
                    key: rows_out[1],
                    value: rows_out[2],
                    score_multiplier: block.score_multiplier(),
                    fractions: [fr[0], fr[1], fr[2], block.attention_fraction()],
                    accumulation: block.accumulation(),
                    drop: block.drop(),
                    exponential: *block.exponential(),
                },
            )
            .map_err(unsupported)?;
            attention.declare(&mut relation);
            let mut row_o = RowConversion::new(
                &s("row_o"),
                declared(attention.output())?,
                t,
                d,
                policy(p[4])?,
            )
            .map_err(unsupported)?;
            row_o.declare(&mut relation);
            let o = project(
                &mut relation,
                &mut weights,
                "o",
                Role::Output,
                declared(row_o.output())?,
                block.attention_fraction(),
                fr[3],
            )?;
            let mut mid = Residual::new(
                l,
                "mid",
                (stream, incoming),
                (declared(o.output())?, fr[3]),
                block.mid_fraction(),
                t,
                d,
            )
            .map_err(unsupported)?;
            mid.declare(&mut relation);
            let mid_out = declared(mid.columns().map(|c| c.output))?;
            let mut norm2 = RmsNorm::new(
                RmsNormPlan {
                    descriptor: norm2_descriptor,
                    gains: gains[1].clone(),
                    rows: t,
                    fixed_widths: plan.zk,
                },
                mid_out,
                &s("norm2"),
            )
            .map_err(unsupported)?;
            norm2.declare(&mut relation);
            let mut row2 =
                RowConversion::new(&s("row2"), declared(norm2.output())?, t, d, policy(p[5])?)
                    .map_err(unsupported)?;
            row2.declare(&mut relation);
            let unit2 = norm2_descriptor.parameters()[4];
            let input2 = declared(row2.output())?;
            // RFC-0026 §2.2: gate precedes up in plan order.
            let gate = project(
                &mut relation,
                &mut weights,
                "gate",
                Role::Gate,
                input2,
                unit2,
                fr[5],
            )?;
            let up = project(
                &mut relation,
                &mut weights,
                "up",
                Role::Up,
                input2,
                unit2,
                fr[4],
            )?;
            let table =
                CqisTable::generate(block.activation().components()[0]).map_err(unsupported)?;
            let mut gated = GatedProduct::new(
                l,
                declared(gate.output())?,
                declared(up.output())?,
                t,
                f,
                &table,
            )
            .map_err(unsupported)?;
            gated.declare(&mut relation);
            let high_low = declared(gated.columns())?;
            let mut down_row =
                GatedConversion::new(l, high_low.high, high_low.low, t, f, policy(p[6])?)
                    .map_err(unsupported)?;
            down_row.declare(&mut relation);
            let activation = block.activation().function().parameters();
            let down = project(
                &mut relation,
                &mut weights,
                "down",
                Role::Down,
                declared(down_row.output())?,
                activation[1] + fr[4],
                fr[6],
            )?;
            let mut residual = Residual::new(
                l,
                "out",
                (mid_out, block.mid_fraction()),
                (declared(down.output())?, fr[6]),
                block.output_fraction(),
                t,
                d,
            )
            .map_err(unsupported)?;
            residual.declare(&mut relation);
            stream = declared(residual.columns().map(|c| c.output))?;
            incoming = block.output_fraction();
            layers.push(LayerModules {
                norm1,
                row1,
                q,
                k,
                v,
                rope_q,
                rope_k,
                attention_rows,
                attention,
                row_o,
                o,
                mid,
                norm2,
                row2,
                gate,
                up,
                gated,
                down_row,
                down,
                residual,
                norm1_descriptor,
                norm2_descriptor,
                gains,
            });
        }

        let final_descriptor = *model.final_norm().function();
        let final_gains = plan.vector(Role::FinalGain, None)?;
        // Rows 12-13: final norm, final row, head (its own source, plan order) and argmax.
        let mut finish = Finish::new(
            FinishPlan {
                norm: RmsNormPlan {
                    descriptor: final_descriptor,
                    gains: final_gains.clone(),
                    rows: t,
                    fixed_widths: plan.zk,
                },
                policy: policy(model.final_policy())?,
                head: plan.projection(
                    Role::Head,
                    None,
                    t,
                    final_descriptor.parameters()[4],
                    model.logits_fraction(),
                )?,
                tied: None,
                tokens: statement.tokens.clone(),
                checked: (statement.start as usize, statement.end as usize),
                next: statement.next,
            },
            stream,
            &relation,
        )
        .map_err(unsupported)?;
        finish.declare(&mut relation);
        weights.push((
            declared(finish.columns().map(|c| c.weight))?,
            Role::Head,
            None,
        ));

        Ok(Self {
            relation,
            embedding,
            layers,
            final_descriptor,
            final_gains,
            finish,
            weights,
        })
    }

    /// Fill every witness and weight column from the capture (RFC-0026 §3.8).
    /// `weights[i]` are the `[channel][lane]` codes of `self.weights[i]`.
    pub fn assign(&self, capture: &Capture, weights: &[Vec<Vec<i64>>]) -> Result<Values, Error> {
        let r = &self.relation;
        let mut values = Values::new(r);
        for ((id, _, _), codes) in self.weights.iter().zip(weights) {
            let column = &r.columns[id.0 as usize];
            let lanes = codes.first().map_or(1, Vec::len);
            let mut padded = pad(codes, lanes);
            padded.resize(1 << column.log_len, 0);
            values.set(r, *id, padded).map_err(|_| Error::Witness)?;
        }
        let w = |module: &'static str| move |_| Error::Assign(String::from(module));
        let cuts = capture.full().cuts();
        let embedding = &weights[0];
        self.embedding
            .assign(
                r,
                &EmbeddingCapture {
                    codes: capture
                        .embedding
                        .iter()
                        .map(|e| {
                            embedding[e.token as usize]
                                .iter()
                                .map(|&v| v as i16)
                                .collect()
                        })
                        .collect(),
                    output: cuts[0]
                        .iter()
                        .map(|row| row.iter().map(|&v| v as i16).collect())
                        .collect(),
                },
                &mut values,
            )
            .map_err(w("embedding"))?;
        for (l, m) in self.layers.iter().enumerate() {
            let blocks = &capture.blocks[l];
            let rows1 = norm_rows(&m.norm1_descriptor, &cuts[l], &m.gains[0])?;
            m.norm1.assign(r, &rows1, &mut values).map_err(w("norm1"))?;
            m.row1
                .assign(
                    r,
                    &conversion(blocks.iter().map(|b| &b.first_row)),
                    &mut values,
                )
                .map_err(w("row1"))?;
            let codes = |q: &Quantised| q.codes.clone();
            let scales = |q: &Quantised| q.scales.clone();
            let projection =
                |row: fn(&_) -> &Quantised,
                 out: fn(&_) -> &stele_reductions::stele_cqis::execution::capture::Projection,
                 wi: usize| ProjectionCapture {
                    codes: blocks.iter().map(|b| codes(row(b))).collect(),
                    scales: blocks.iter().map(|b| scales(row(b))).collect(),
                    weights: weights[wi].clone(),
                    outputs: blocks
                        .iter()
                        .map(|b| out(b).output.quotient.clone())
                        .collect(),
                };
            let wi = 1 + 7 * l;
            m.q.assign(
                r,
                &projection(|b| &b.first_row, |b| &b.query, wi),
                &mut values,
            )
            .map_err(w("q"))?;
            m.k.assign(
                r,
                &projection(|b| &b.first_row, |b| &b.key, wi + 1),
                &mut values,
            )
            .map_err(w("k"))?;
            m.v.assign(
                r,
                &projection(|b| &b.first_row, |b| &b.value, wi + 2),
                &mut values,
            )
            .map_err(w("v"))?;
            let flat = |out: fn(&_) -> &[i64]| -> Vec<i16> {
                blocks
                    .iter()
                    .flat_map(|b| out(b).iter().map(|&v| v as i16))
                    .collect()
            };
            m.rope_q
                .assign(r, &flat(|b| &b.query.output.quotient), &mut values)
                .map_err(w("rope_q"))?;
            m.rope_k
                .assign(r, &flat(|b| &b.key.output.quotient), &mut values)
                .map_err(w("rope_k"))?;
            let qkv: [fn(&_) -> &Quantised; 3] =
                [|b: &Block| &b.query_row, |b| &b.key_row, |b| &b.value_row];
            for (row, get) in m.attention_rows.iter().zip(qkv) {
                row.assign(r, &conversion(blocks.iter().map(get)), &mut values)
                    .map_err(w("attention rows"))?;
            }
            let attention = AttentionCapture {
                codes: qkv.map(|get| blocks.iter().map(|b| get(b).codes.clone()).collect()),
                scales: qkv.map(|get| blocks.iter().map(|b| get(b).scales[0]).collect()),
                positions: blocks
                    .iter()
                    .map(|b| PositionCapture::from(&b.attention))
                    .collect(),
            };
            m.attention
                .assign(r, &attention, &mut values)
                .map_err(w("attention"))?;
            m.row_o
                .assign(
                    r,
                    &conversion(blocks.iter().map(|b| &b.attention_row)),
                    &mut values,
                )
                .map_err(w("row_o"))?;
            m.o.assign(
                r,
                &projection(|b| &b.attention_row, |b| &b.output, wi + 3),
                &mut values,
            )
            .map_err(w("o"))?;
            let flat64 = |out: fn(&_) -> &[i64]| -> Vec<i64> {
                blocks.iter().flat_map(|b| out(b).iter().copied()).collect()
            };
            let cut = cuts[l].iter().flatten().map(|&v| i64::from(v)).collect();
            let add = ResidualCapture {
                left: cut,
                right: flat64(|b| &b.output.output.quotient),
                output: flat64(|b| &b.mid.quotient),
            };
            m.mid.assign(r, &add, &mut values).map_err(w("mid"))?;
            let mid = rows(blocks.iter().map(|b| &b.mid.quotient));
            let mid32: Vec<Vec<i32>> = mid
                .iter()
                .map(|x| x.iter().map(|&v| v as i32).collect())
                .collect();
            let rows2 = norm_rows(&m.norm2_descriptor, &mid32, &m.gains[1])?;
            m.norm2.assign(r, &rows2, &mut values).map_err(w("norm2"))?;
            m.row2
                .assign(
                    r,
                    &conversion(blocks.iter().map(|b| &b.second_row)),
                    &mut values,
                )
                .map_err(w("row2"))?;
            m.gate
                .assign(
                    r,
                    &projection(|b| &b.second_row, |b| &b.gate, wi + 4),
                    &mut values,
                )
                .map_err(w("gate"))?;
            m.up.assign(
                r,
                &projection(|b| &b.second_row, |b| &b.up, wi + 5),
                &mut values,
            )
            .map_err(w("up"))?;
            m.gated
                .assign(
                    r,
                    &GatedCapture {
                        gate: flat(|b| &b.gate.output.quotient),
                        up: flat(|b| &b.up.output.quotient),
                    },
                    &mut values,
                )
                .map_err(w("gated"))?;
            m.down_row
                .assign(r, &flat64(|b| &b.gated), &mut values)
                .map_err(w("down_row"))?;
            m.down
                .assign(
                    r,
                    &projection(|b| &b.down_row, |b| &b.down, wi + 6),
                    &mut values,
                )
                .map_err(w("down"))?;
            let add = ResidualCapture {
                left: flat64(|b| &b.mid.quotient),
                right: flat64(|b| &b.down.output.quotient),
                output: flat64(|b| &b.residual.quotient),
            };
            m.residual
                .assign(r, &add, &mut values)
                .map_err(w("residual"))?;
        }
        let heads = &capture.head;
        let finish = FinishCapture {
            norm: norm_rows(
                &self.final_descriptor,
                &cuts[self.layers.len()],
                &self.final_gains,
            )?,
            row: conversion(heads.iter().map(|h| &h.row)),
            head: ProjectionCapture {
                codes: heads.iter().map(|h| h.row.codes.clone()).collect(),
                scales: heads.iter().map(|h| h.row.scales.clone()).collect(),
                weights: weights[weights.len() - 1].clone(),
                outputs: heads
                    .iter()
                    .map(|h| h.logits.output.quotient.clone())
                    .collect(),
            },
        };
        self.finish
            .assign(r, &finish, &mut values)
            .map_err(w("finish"))?;
        Ok(values)
    }
}

fn norm_rows(
    descriptor: &Descriptor,
    inputs: &[Vec<i32>],
    gains: &[i16],
) -> Result<Vec<RmsNormRow>, Error> {
    inputs
        .iter()
        .map(|x| {
            descriptor
                .evaluate_rmsnorm_wide(x, gains)
                .map(|e| RmsNormRow::new(x, &e))
                .map_err(|_| Error::Witness)
        })
        .collect()
}

fn rows<'a>(it: impl Iterator<Item = &'a Vec<i64>>) -> Vec<Vec<i64>> {
    it.cloned().collect()
}

fn conversion<'a>(it: impl Iterator<Item = &'a Quantised>) -> ConversionCapture {
    let mut c = ConversionCapture::default();
    for q in it {
        c.inputs.push(q.input.clone());
        c.codes.push(q.codes.clone());
        c.scales.push(q.scales.clone());
    }
    c
}

/// Row-major `rows × lanes` with each row padded to a power of two (RFC-0026 §2.1).
pub(crate) fn pad(rows: &[Vec<i64>], lanes: usize) -> Vec<i64> {
    let stride = lanes.next_power_of_two();
    let mut out = vec![0; rows.len().next_power_of_two() * stride];
    for (i, row) in rows.iter().enumerate() {
        out[i * stride..i * stride + row.len()].copy_from_slice(row);
    }
    out
}

/// Weight kinds of `relation` in declaration order, for the RFC-0026 §2.2 plan check.
pub(crate) fn weight_columns(relation: &Relation) -> Vec<ColumnId> {
    (0..relation.columns.len() as u32)
        .map(ColumnId)
        .filter(|id| relation.columns[id.0 as usize].kind == Kind::Weight)
        .collect()
}

//! Affine projection of converted int8 rows (RFC-0026 §5 row 4 and A25; RFC-0025 §2.2/2.5,
//! wide int24 outputs RFC-0004 A14, grouped rows RFC-0004 A15, gated scales RFC-0004 A8;
//! `SCALED-LINEAR.md`).
//!
//! Family 1, no bias: `Y_j = R(V_j * m_j * u * 2^l)` with one round-half-away and
//! int16 (or int24 for wide O/down under RFC-0004 A14) rejection, where `l = e - f + fo` and
//! - per-row input: `V = A = sum_i q_i*w_ji` (one matmul) and `u = s`;
//! - grouped int16 input: `V = A' = sum_i s_k(i)*q_i*w_ji` and `u = 1`. The folded value
//!   `q_i*s_k(i) = b0_i + 256*b1_i` is split into digit rows, `C_t = sum_i b_t,i*w_ji`
//!   is one matmul per digit and `V = C_0 + 256*C_1` (RFC-0004 A15 digit rows);
//! - grouped gated input (`scale_bound > 259`): `s_k` is split into unsigned bytes `s_c`
//!   on the group domain, `q_i*s_k(i) = sum_t 256^t b_t,i` is proven by a radix-256 byte
//!   chain with balanced signed-8 digits `b_t`, and `V = sum_t 256^t C_t`.
//!
//! Wide values never appear in one relation (limb rule, RFC-0026 §3.5):
//! - sign chain: `sum_t 256^t C_t = (1-2*tau) * sum_k 256^k v_k` with byte limbs `v_k`;
//! - scale bytes: `s = sum_c 256^c s_c`;
//! - rounding chain, for `l < 0` with `K = -l`:
//!   `sum v_a*m_b*s_c*256^(a+b+c) + 2^(K-1) = Ymag*2^K + rho`, `rho` in `[0, 2^K)` as
//!   byte limbs; for `l >= 0`: `sum v_a*m_b*s_c*256^(a+b+c+l/8) = Ymag'` and
//!   `Ymag = 2^(l mod 8) * Ymag'`. When `K > bits(Pmax) + 1` the rounding is
//!   identically zero and `Ymag = 0` replaces the chain;
//! - output: for int16, `Y = mask * (1 - 2*tau) * Ymag`, signed 16, zero on padding;
//!   for int24 (RFC-0004 A14), `Ymag` and `Y` are each composed from three byte limbs
//!   (`u8, u8, u8` and `u8, u8, i8`) and linked by a 3-limb radix-256 output chain.
//!
//! `m_j` is split into two public bytes per channel; padded channels have `m = 0`.
//! Output-uniqueness lemma P and the mutation table:
//! `agents/reviews/e16-05-projections.md`.

use super::{bit_length, log2_ceil, r, signed_for, term, Builder, Chain, RowOutput, Unsupported};
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use stele_ir::relation::{
    ColumnId, Compose, Invalid, Kind, Matmul, Module, Range, Relation, Term, Values, Violation,
    Width, MAX_VARS, MAX_WIDTH_BITS,
};

/// Largest gated dynamic scale, `ceil(2^30/127)` (RFC-0004 A8).
const GATED_SCALE: u32 = 8454661;
/// Largest grouped (int16) scale, `ceil(32768/127)`.
const GROUPED_SCALE: u32 = 259;

/// Plan data of one projection (RFC-0025 §2.5), for one layer and role.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectionPlan {
    /// Real rows `T` and dimensions `d` (inner) and `o` (outputs).
    pub rows: usize,
    pub inner: usize,
    pub outputs: usize,
    /// Weight code bits, 4 or 8.
    pub weight_bits: u8,
    /// Public channel mantissas `m_j`, one per output channel.
    pub mantissas: Vec<u16>,
    /// `l = e - f + fo`: weight exponent minus row fraction plus output fraction.
    pub shift: i32,
    /// Signed output width in bits: `16` (default) or `24` (wide O/down, RFC-0004 A14).
    pub output_bits: u8,
}

/// Executor intermediates of one projection over every real row.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProjectionCapture {
    /// `[row][lane]` input codes and `[row][group]` input scales (the row conversion's).
    pub codes: Vec<Vec<i64>>,
    pub scales: Vec<Vec<u32>>,
    /// `[output][lane]` weight codes; padded weight entries are zero.
    pub weights: Vec<Vec<i64>>,
    /// `[row][output]` projection outputs (int16, or int24 when `output_bits == 24`).
    pub outputs: Vec<Vec<i64>>,
}

#[derive(Clone, Debug)]
pub(crate) struct Columns {
    pub(crate) weight: ColumnId,
    /// Grouped gated only: group-domain scale bytes feeding the fold chain.
    pub(crate) fold_scale_bytes: Vec<ColumnId>,
    /// Grouped only: digit columns `b0..b_{T-1}`.
    pub(crate) digits: Vec<ColumnId>,
    /// One matmul output per digit row.
    pub(crate) sums: Vec<ColumnId>,
    pub(crate) bytes: Vec<ColumnId>,
    pub(crate) sign: ColumnId,
    /// Per-row only: scale bytes.
    pub(crate) scale_bytes: Vec<ColumnId>,
    pub(crate) magnitude: ColumnId,
    /// Wide output only: 3 unsigned byte limbs composing `magnitude`.
    pub(crate) magnitude_bytes: Vec<ColumnId>,
    pub(crate) remainder: Vec<ColumnId>,
    pub(crate) output: ColumnId,
    /// Wide output only: 3 byte limbs (`u8, u8, i8`) composing `output`.
    pub(crate) output_bytes: Vec<ColumnId>,
    pub(crate) chains: Vec<(String, Chain)>,
}

/// Steps of the witness dataflow, in order (see `row::Step`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Step {
    Digits,
    Sums,
    Sign,
    Bytes,
    ScaleBytes,
    Magnitude,
    Remainder,
    Output,
}

/// Values of every witness column; `inputs` are the read-only module inputs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ProjectionWitness {
    /// `[lane]` input codes and `[group]` input scales, padded.
    pub(crate) codes: Vec<i64>,
    pub(crate) scales: Vec<i64>,
    /// `[output][lane]` weights, padded.
    pub(crate) weights: Vec<Vec<i64>>,
    /// `[byte][group]` (grouped gated only).
    pub(crate) fold_scale_bytes: Vec<Vec<i64>>,
    /// `[digit][lane]`.
    pub(crate) digits: Vec<Vec<i64>>,
    /// `[digit][out]`.
    pub(crate) sums: Vec<Vec<i64>>,
    pub(crate) sign: Vec<i64>,
    /// `[byte][out]`.
    pub(crate) bytes: Vec<Vec<i64>>,
    /// `[byte][row]`.
    pub(crate) scale_bytes: Vec<Vec<i64>>,
    pub(crate) magnitude: Vec<i64>,
    /// `[byte][out]` (wide output only).
    pub(crate) magnitude_bytes: Vec<Vec<i64>>,
    /// `[limb][out]`.
    pub(crate) remainder: Vec<Vec<i64>>,
    pub(crate) output: Vec<i64>,
    /// `[byte][out]` (wide output only).
    pub(crate) output_bytes: Vec<Vec<i64>>,
}

/// One projection reading a converted row (RFC-0026 §5 row 4).
pub struct Projection {
    prefix: String,
    input: RowOutput,
    weight: Option<ColumnId>,
    plan: ProjectionPlan,
    pub(crate) columns: Option<Columns>,
    /// Matmul domain cap; tests lower it to force row blocks (RFC-0026 A6).
    pub(crate) limit: u8,
}

/// Bytes needed for `n`.
fn bytes(n: u128) -> usize {
    usize::from(bit_length(n)).div_ceil(8).max(1)
}

/// Positions of a wide identity, filled term by term.
struct Positions(Vec<Vec<Term>>);

impl Positions {
    fn push(&mut self, position: usize, t: Term) {
        if self.0.len() <= position {
            self.0.resize(position + 1, Vec::new());
        }
        self.0[position].push(t);
    }
}

impl Projection {
    /// `weight`: an already-declared weight column to read (a tied head), or `None`
    /// to declare this role's own weight source here, in plan order (RFC-0026 §2.2).
    pub fn new(
        prefix: &str,
        input: RowOutput,
        weight: Option<ColumnId>,
        plan: ProjectionPlan,
    ) -> Result<Self, Unsupported> {
        let shape = plan.rows > 0
            && (1..=16384).contains(&plan.inner)
            && plan.outputs > 0
            && plan.mantissas.len() == plan.outputs
            && matches!(plan.weight_bits, 4 | 8)
            && matches!(plan.output_bits, 16 | 24)
            && log2_ceil(plan.rows) == input.log_rows
            && log2_ceil(plan.inner) == input.log_dimension;
        if !shape {
            return Err(Unsupported::Shape);
        }
        if input.scale_bound == 0 || input.scale_bound > GATED_SCALE {
            return Err(Unsupported::Policy);
        }
        // The sum matmuls are split into row blocks past MAX_VARS (RFC-0026 A6); every
        // other relation lives on the output domain (rows, outputs).
        if input.log_rows + log2_ceil(plan.outputs) > MAX_VARS {
            return Err(Unsupported::Domain);
        }
        let this = Self {
            prefix: prefix.into(),
            input,
            weight,
            plan,
            columns: None,
            limit: MAX_VARS,
        };
        if this.sum_widths().iter().any(|w| w.bits > MAX_WIDTH_BITS) {
            return Err(Unsupported::Domain);
        }
        Ok(this)
    }

    fn grouped(&self) -> bool {
        self.input.log_group < self.input.log_dimension
    }

    /// Grouped input with a scale past the int16 dynamic limit (gated FFN, RFC-0004 A15):
    /// uses byte-decomposed scales and balanced signed-8 digit rows via a fold chain.
    fn wide_grouped(&self) -> bool {
        self.grouped() && self.input.scale_bound > GROUPED_SCALE
    }

    fn wide_output(&self) -> bool {
        self.plan.output_bits == 24
    }

    fn weight_width(&self) -> Width {
        Width::signed(self.plan.weight_bits)
    }

    /// Digit widths of the matmul left operand.
    fn digit_widths(&self) -> Vec<Width> {
        if self.wide_grouped() {
            vec![Width::signed(8); bytes(u128::from(self.input.scale_bound)) + 1]
        } else if self.grouped() {
            vec![Width::unsigned(8), Width::signed(9)]
        } else {
            vec![Width::signed(8)]
        }
    }

    fn sum_bounds(&self) -> Vec<u128> {
        let w = self.weight_width().magnitude();
        self.digit_widths()
            .iter()
            .map(|d| (d.magnitude() * w) << self.input.log_dimension)
            .collect()
    }

    fn sum_widths(&self) -> Vec<Width> {
        self.sum_bounds().into_iter().map(signed_for).collect()
    }

    /// `|V| <= vmax` for every input within its declared widths.
    fn vmax(&self) -> u128 {
        self.sum_bounds()
            .iter()
            .enumerate()
            .map(|(k, c)| c << (8 * k))
            .sum()
    }

    /// The rounding is identically zero: `K > bits(Pmax) + 1`.
    pub(crate) fn vanishing(&self) -> bool {
        // The scale bytes bound s below 2^bits(scale_bound).
        let u_max = if self.grouped() {
            1
        } else {
            (1u128 << bit_length(u128::from(self.input.scale_bound))) - 1
        };
        let pmax = self.vmax() * 65535 * u_max;
        self.shift() < 0 && (-self.shift()) as u32 > u32::from(bit_length(pmax)) + 1
    }

    /// `l`, with a left shift clamped to `output_bits`: for `l >= output_bits` every
    /// `P >= 1` leaves the signed output range and `P = 0` stays 0, so
    /// `min(l, output_bits)` has the same accepted set.
    fn shift(&self) -> i32 {
        self.plan.shift.min(i32::from(self.plan.output_bits))
    }

    /// `(offset bytes, output factor)` of a left shift.
    fn left(&self) -> (usize, i64) {
        let l = self.shift();
        if l >= 0 {
            ((l / 8) as usize, 1i64 << (l % 8))
        } else {
            (0, 1)
        }
    }

    /// Output column (`T x o`, signed 16 or signed 24); `None` before `declare`.
    pub fn output(&self) -> Option<ColumnId> {
        self.columns.as_ref().map(|c| c.output)
    }

    /// The weight column read (declared here unless one was supplied).
    pub fn weight(&self) -> Option<ColumnId> {
        self.columns.as_ref().map(|c| c.weight)
    }

    pub(crate) fn logs(&self) -> (u8, u8, u8, u8) {
        let i = self.input;
        (
            i.log_rows,
            i.log_dimension,
            i.log_group,
            log2_ceil(self.plan.outputs),
        )
    }

    pub(crate) fn real(&self, x: usize) -> bool {
        let (_, _, _, lo) = self.logs();
        (x >> lo) < self.plan.rows && (x & ((1 << lo) - 1)) < self.plan.outputs
    }

    fn output_id(&self) -> ColumnId {
        self.columns.as_ref().map_or(ColumnId(0), |c| c.output)
    }

    /// The capture's inputs over the padded layout; a public (static) scale column
    /// is read as declared.
    pub(crate) fn source(
        &self,
        relation: &Relation,
        capture: &ProjectionCapture,
    ) -> Result<ProjectionWitness, Violation> {
        let (t, ld, lg, lo) = self.logs();
        let plan = &self.plan;
        let real_groups = plan.inner.div_ceil(1 << lg);
        let ok = capture.codes.len() == plan.rows
            && capture.codes.iter().all(|row| row.len() == plan.inner)
            && capture.scales.len() == plan.rows
            && capture.scales.iter().all(|row| row.len() == real_groups)
            && capture.weights.len() == plan.outputs
            && capture.weights.iter().all(|row| row.len() == plan.inner)
            && capture.outputs.len() == plan.rows
            && capture.outputs.iter().all(|row| row.len() == plan.outputs);
        if !ok {
            return Err(Invalid::Column(self.output_id()).into());
        }
        let per_row = 1usize << (ld - lg);
        let scales = match relation.column(self.input.scale).map(|c| &c.kind) {
            Some(Kind::Public(v)) => v.clone(),
            _ => (0..1usize << (t + ld - lg))
                .map(|k| {
                    let (row, group) = (k / per_row, k % per_row);
                    if row < plan.rows && group < real_groups {
                        i64::from(capture.scales[row][group])
                    } else {
                        0
                    }
                })
                .collect(),
        };
        let codes = (0..1usize << (t + ld))
            .map(|x| {
                let (row, i) = (x >> ld, x & ((1 << ld) - 1));
                if row < plan.rows && i < plan.inner {
                    capture.codes[row][i]
                } else {
                    0
                }
            })
            .collect();
        let weights = (0..1usize << lo)
            .map(|j| {
                let mut row = capture.weights.get(j).cloned().unwrap_or_default();
                row.resize(1 << ld, 0);
                row
            })
            .collect();
        Ok(ProjectionWitness {
            codes,
            scales,
            weights,
            ..ProjectionWitness::default()
        })
    }

    /// Recompute every step from `from` on (see `row::RowConversion::complete`).
    pub(crate) fn complete(&self, w: &mut ProjectionWitness, from: Step, frozen: Option<Step>) {
        let (t, ld, lg, lo) = self.logs();
        let (lanes, out) = (1usize << (t + ld), 1usize << (t + lo));
        let at = |step: Step| from <= step && frozen != Some(step);
        let c = self.columns.as_ref();
        let (n_fold_scale, n_bytes, n_scale, n_rem) = c.map_or((0, 0, 0, 0), |c| {
            (
                c.fold_scale_bytes.len(),
                c.bytes.len(),
                c.scale_bytes.len(),
                c.remainder.len(),
            )
        });
        let grouped = self.grouped();
        let wide_grouped = self.wide_grouped();
        let wide_output = self.wide_output();
        if at(Step::Digits) && grouped {
            if wide_grouped {
                let groups = 1usize << (t + ld - lg);
                w.fold_scale_bytes = (0..n_fold_scale)
                    .map(|k| {
                        (0..groups)
                            .map(|g| {
                                let s = w.scales[g];
                                if k + 1 == n_fold_scale {
                                    s >> (8 * k)
                                } else {
                                    (s >> (8 * k)) & 255
                                }
                            })
                            .collect()
                    })
                    .collect();
                let n_digits = self.digit_widths().len();
                let mut digits = vec![Vec::with_capacity(lanes); n_digits];
                for x in 0..lanes {
                    let mut v = i128::from(w.codes[x]) * i128::from(w.scales[x >> lg]);
                    for digit in digits.iter_mut().take(n_digits - 1) {
                        let d = (v + 128).rem_euclid(256) - 128;
                        digit.push(d as i64);
                        v = (v - d) / 256;
                    }
                    digits[n_digits - 1].push(v as i64);
                }
                w.digits = digits;
            } else {
                let folded: Vec<i64> = (0..lanes).map(|x| w.codes[x] * w.scales[x >> lg]).collect();
                w.digits = vec![
                    folded.iter().map(|f| f.rem_euclid(256)).collect(),
                    folded.iter().map(|f| f.div_euclid(256)).collect(),
                ];
            }
        }
        if at(Step::Sums) {
            let operands: Vec<&Vec<i64>> = if grouped {
                w.digits.iter().collect()
            } else {
                vec![&w.codes]
            };
            w.sums = operands
                .iter()
                .map(|operand| {
                    (0..out)
                        .map(|x| {
                            let (row, j) = (x >> lo, x & ((1 << lo) - 1));
                            (0..1usize << ld)
                                .map(|i| operand[(row << ld) | i] * w.weights[j][i])
                                .sum()
                        })
                        .collect()
                })
                .collect();
        }
        let wide = |w: &ProjectionWitness, x: usize| -> i128 {
            w.sums
                .iter()
                .enumerate()
                .map(|(k, s)| i128::from(s[x]) << (8 * k))
                .sum()
        };
        if at(Step::Sign) {
            w.sign = (0..out).map(|x| i64::from(wide(w, x) < 0)).collect();
        }
        if at(Step::Bytes) {
            // sum 256^t C_t = (1 - 2 tau) |V|: the bytes of V / (1 - 2 tau) where that
            // is exact (always, for a Boolean tau).
            let values: Vec<i128> = (0..out)
                .map(|x| {
                    let (odd, v) = (1 - 2 * i128::from(w.sign[x]), wide(w, x));
                    if v % odd == 0 {
                        v / odd
                    } else {
                        odd * v
                    }
                })
                .collect();
            w.bytes = (0..n_bytes)
                .map(|k| {
                    values
                        .iter()
                        .map(|v| {
                            if k + 1 == n_bytes {
                                (v >> (8 * k)) as i64
                            } else {
                                ((v >> (8 * k)) & 255) as i64
                            }
                        })
                        .collect()
                })
                .collect();
        }
        if at(Step::ScaleBytes) {
            w.scale_bytes = (0..n_scale)
                .map(|k| {
                    (0..1usize << t)
                        .map(|row| {
                            let s = w.scales[row << (ld - lg)];
                            if k + 1 == n_scale {
                                s >> (8 * k)
                            } else {
                                (s >> (8 * k)) & 255
                            }
                        })
                        .collect()
                })
                .collect();
        }
        // P = |V| * m_j * u from the byte limbs actually assigned.
        let product = |w: &ProjectionWitness, x: usize| -> i128 {
            let (row, j) = (x >> lo, x & ((1 << lo) - 1));
            let v: i128 = w
                .bytes
                .iter()
                .enumerate()
                .map(|(k, b)| i128::from(b[x]) << (8 * k))
                .sum();
            let u: i128 = if grouped {
                1
            } else {
                w.scale_bytes
                    .iter()
                    .enumerate()
                    .map(|(k, b)| i128::from(b[row]) << (8 * k))
                    .sum()
            };
            v * self.plan.mantissas.get(j).map_or(0, |m| i128::from(*m)) * u
        };
        let shift = self.shift();
        let vanishing = self.vanishing();
        if at(Step::Magnitude) {
            w.magnitude = (0..out)
                .map(|x| {
                    let p = product(w, x);
                    if vanishing {
                        0
                    } else if shift >= 0 {
                        (p << (8 * (shift / 8))) as i64
                    } else {
                        let k = -shift;
                        ((p + (1i128 << (k - 1))) >> k) as i64
                    }
                })
                .collect();
            if wide_output {
                w.magnitude_bytes = (0..3)
                    .map(|k| {
                        w.magnitude
                            .iter()
                            .map(|&m| {
                                if k == 2 {
                                    m.div_euclid(1 << 16)
                                } else {
                                    m.div_euclid(1 << (8 * k)).rem_euclid(256)
                                }
                            })
                            .collect()
                    })
                    .collect();
            }
        }
        if at(Step::Remainder) && n_rem > 0 {
            let k = (-shift).max(1) as u32;
            let rho: Vec<i128> = (0..out)
                .map(|x| product(w, x) + (1i128 << (k - 1)) - (i128::from(w.magnitude[x]) << k))
                .collect();
            w.remainder = (0..n_rem)
                .map(|i| {
                    rho.iter()
                        .map(|v| {
                            if i + 1 == n_rem {
                                (v >> (8 * i)) as i64
                            } else {
                                ((v >> (8 * i)) & 255) as i64
                            }
                        })
                        .collect()
                })
                .collect();
        }
        if at(Step::Output) {
            let (_, factor) = self.left();
            w.output = (0..out)
                .map(|x| {
                    if self.real(x) {
                        factor * (1 - 2 * w.sign[x]) * w.magnitude[x]
                    } else {
                        0
                    }
                })
                .collect();
            if wide_output {
                w.output_bytes = (0..3)
                    .map(|k| {
                        w.output
                            .iter()
                            .map(|&y| {
                                if k == 2 {
                                    y.div_euclid(1 << 16)
                                } else {
                                    y.div_euclid(1 << (8 * k)).rem_euclid(256)
                                }
                            })
                            .collect()
                    })
                    .collect();
            }
        }
    }

    /// Write a (possibly forged) witness. `skip` names one chain position whose
    /// carries are assigned around it (mutation tests).
    pub(crate) fn write(
        &self,
        relation: &Relation,
        w: &ProjectionWitness,
        values: &mut Values,
        skip: Option<(&str, usize)>,
    ) -> Result<(), Violation> {
        let c = self
            .columns
            .as_ref()
            .ok_or(Violation::Missing(self.output_id()))?;
        for (ids, columns) in [
            (&c.fold_scale_bytes, &w.fold_scale_bytes),
            (&c.digits, &w.digits),
            (&c.sums, &w.sums),
            (&c.bytes, &w.bytes),
            (&c.scale_bytes, &w.scale_bytes),
            (&c.magnitude_bytes, &w.magnitude_bytes),
            (&c.remainder, &w.remainder),
            (&c.output_bytes, &w.output_bytes),
        ] {
            for (id, column) in ids.iter().zip(columns) {
                values.set(relation, *id, column.clone())?;
            }
        }
        values.set(relation, c.sign, w.sign.clone())?;
        values.set(relation, c.magnitude, w.magnitude.clone())?;
        values.set(relation, c.output, w.output.clone())?;
        for (name, chain) in &c.chains {
            let around = skip.filter(|(n, _)| n == name).map(|(_, k)| k);
            chain.assign_around(relation, values, around)?;
        }
        Ok(())
    }
}

impl Module for Projection {
    type Capture = ProjectionCapture;

    fn declare(&mut self, relation: &mut Relation) {
        let (t, ld, lg, lo) = self.logs();
        let (lanes, out) = (t + ld, t + lo);
        let grouped = self.grouped();
        let wide_grouped = self.wide_grouped();
        let wide_output = self.wide_output();
        let prefix = self.prefix.clone();
        let plan = &self.plan;
        let mut b = Builder::new(relation, &prefix);

        let weight = self.weight.unwrap_or_else(|| {
            let name = alloc::format!("{prefix}/weight");
            let id = b
                .relation
                .add_column(&name, Kind::Weight, self.weight_width(), lo + ld);
            b.relation.ranges.push(Range {
                name: alloc::format!("{name}/range"),
                column: id,
                width: self.weight_width(),
            });
            id
        });
        let mask = (0..1usize << out)
            .map(|x| i64::from(self.real(x)))
            .collect();
        let mask = b.public("mask", mask, Width::unsigned(1), out);
        let mantissa = |shift: u32| {
            (0..1usize << lo)
                .map(|j| {
                    plan.mantissas
                        .get(j)
                        .map_or(0, |m| i64::from(m >> shift) & 255)
                })
                .collect::<Vec<_>>()
        };
        let m = [
            b.public("mantissa/0", mantissa(0), Width::unsigned(8), lo),
            b.public("mantissa/1", mantissa(8), Width::unsigned(8), lo),
        ];
        let at = |c: ColumnId| r(c, 0..out);

        // Matmul operands: the codes themselves, or the A15 digit rows.
        let mut chains = Vec::new();
        let codes = r(self.input.codes, 0..lanes);
        let (fold_scale_bytes, digits): (Vec<ColumnId>, Vec<ColumnId>) = if wide_grouped {
            let groups = t + ld - lg;
            let bound = u128::from(self.input.scale_bound);
            let n = bytes(bound);
            let top = bit_length(bound) as usize - 8 * (n - 1);
            let s: Vec<ColumnId> = (0..n)
                .map(|c| {
                    let bits = if c + 1 == n { top } else { 8 } as u8;
                    b.witness(
                        &alloc::format!("fold_scale/{c}"),
                        Width::unsigned(bits),
                        groups,
                    )
                })
                .collect();
            let mut terms = vec![term(1, vec![r(self.input.scale, 0..groups)])];
            terms.extend(
                s.iter()
                    .enumerate()
                    .map(|(c, id)| term(-(1 << (8 * c)), vec![r(*id, 0..groups)])),
            );
            b.identity("fold/scale", groups, terms);
            let d: Vec<ColumnId> = self
                .digit_widths()
                .into_iter()
                .enumerate()
                .map(|(k, w)| b.witness(&alloc::format!("digit/{k}"), w, lanes))
                .collect();
            let mut positions = Positions(Vec::new());
            for (c, sc) in s.iter().enumerate() {
                positions.push(c, term(1, vec![codes.clone(), r(*sc, lg..lanes)]));
            }
            for (k, dk) in d.iter().enumerate() {
                positions.push(k, term(-1, vec![r(*dk, 0..lanes)]));
            }
            chains.push((
                alloc::format!("{prefix}/fold"),
                Chain::declare(&mut b, "fold", lanes, 8, positions.0),
            ));
            (s, d)
        } else if grouped {
            let names = ["digit/0", "digit/1"];
            let d: Vec<ColumnId> = names
                .iter()
                .zip(self.digit_widths())
                .map(|(n, w)| b.witness(n, w, lanes))
                .collect();
            // q*s - b0 - 256*b1 = 0 on every lane.
            b.identity(
                "fold",
                lanes,
                vec![
                    term(1, vec![codes.clone(), r(self.input.scale, lg..lanes)]),
                    term(-1, vec![r(d[0], 0..lanes)]),
                    term(-256, vec![r(d[1], 0..lanes)]),
                ],
            );
            (Vec::new(), d)
        } else {
            (Vec::new(), Vec::new())
        };
        let lhs: Vec<ColumnId> = if grouped {
            digits.clone()
        } else {
            vec![self.input.codes]
        };
        let summed = (out..out + ld).collect::<Vec<u8>>();
        let mut sums = Vec::new();
        for (k, (column, width)) in lhs.iter().zip(self.sum_widths()).enumerate() {
            let sum = b.column(&alloc::format!("sum/{k}"), width, out);
            b.relation.add_matmul_within(
                Matmul {
                    name: alloc::format!("{prefix}/sum/{k}"),
                    free: out,
                    summed: ld,
                    out: at(sum),
                    lhs: r(*column, summed.iter().copied().chain(lo..out)),
                    rhs: r(weight, summed.iter().copied().chain(0..lo)),
                },
                self.limit,
            );
            sums.push(sum);
        }

        // Sign chain: sum_t 256^t C_t - (1 - 2 tau) sum_k 256^k v_k = 0.
        let sign = b.witness("sign", Width::unsigned(1), out);
        let v: Vec<ColumnId> = (0..bytes(self.vmax()))
            .map(|k| b.witness(&alloc::format!("byte/{k}"), Width::unsigned(8), out))
            .collect();
        let mut positions = Positions(Vec::new());
        for (k, sum) in sums.iter().enumerate() {
            positions.push(k, term(1, vec![at(*sum)]));
        }
        for (k, byte) in v.iter().enumerate() {
            positions.push(k, term(-1, vec![at(*byte)]));
            positions.push(k, term(2, vec![at(sign), at(*byte)]));
        }
        chains.push((
            alloc::format!("{prefix}/sign"),
            Chain::declare(&mut b, "sign", out, 8, positions.0),
        ));

        // Scale bytes (per-row input): s = sum_c 256^c s_c on the row domain.
        let scale_bytes: Vec<ColumnId> = if grouped {
            Vec::new()
        } else {
            let bound = u128::from(self.input.scale_bound);
            let n = bytes(bound);
            let top = bit_length(bound) as usize - 8 * (n - 1);
            let s: Vec<ColumnId> = (0..n)
                .map(|c| {
                    let bits = if c + 1 == n { top } else { 8 } as u8;
                    b.witness(&alloc::format!("scale/{c}"), Width::unsigned(bits), t)
                })
                .collect();
            let mut terms = vec![term(1, vec![r(self.input.scale, 0..t)])];
            terms.extend(
                s.iter()
                    .enumerate()
                    .map(|(c, id)| term(-(1 << (8 * c)), vec![r(*id, 0..t)])),
            );
            b.identity("scale", t, terms);
            s
        };

        // Rounding chain.
        let (magnitude, magnitude_bytes) = if wide_output {
            let mag = b.column("magnitude", Width::unsigned(24), out);
            let limbs: Vec<ColumnId> = (0..3)
                .map(|k| b.witness(&alloc::format!("magnitude/{k}"), Width::unsigned(8), out))
                .collect();
            b.relation.composes.push(Compose {
                name: alloc::format!("{prefix}/magnitude/compose"),
                column: mag,
                limbs: limbs
                    .iter()
                    .enumerate()
                    .map(|(k, &id)| (id, (8 * k) as u8))
                    .collect(),
            });
            (mag, limbs)
        } else {
            (b.witness("magnitude", Width::unsigned(16), out), Vec::new())
        };
        let shift = self.shift();
        let (offset, factor) = self.left();
        let vanishing = self.vanishing();
        let mut positions = Positions(Vec::new());
        for (a, va) in v.iter().enumerate() {
            for (bi, mb) in m.iter().enumerate() {
                if scale_bytes.is_empty() {
                    positions.push(a + bi + offset, term(1, vec![at(*va), r(*mb, 0..lo)]));
                }
                for (c, sc) in scale_bytes.iter().enumerate() {
                    positions.push(
                        a + bi + c + offset,
                        term(1, vec![at(*va), r(*mb, 0..lo), r(*sc, lo..out)]),
                    );
                }
            }
        }
        let mut remainder = Vec::new();
        if vanishing {
            b.identity("vanishing", out, vec![term(1, vec![at(magnitude)])]);
        } else if shift >= 0 {
            if wide_output {
                for (j, &limb) in magnitude_bytes.iter().enumerate() {
                    positions.push(j, term(-1, vec![at(limb)]));
                }
            } else {
                positions.push(0, term(-1, vec![at(magnitude)]));
            }
        } else {
            let k = (-shift) as usize;
            positions.push((k - 1) / 8, term(1 << ((k - 1) % 8), vec![]));
            if wide_output {
                for (j, &limb) in magnitude_bytes.iter().enumerate() {
                    positions.push(k / 8 + j, term(-(1 << (k % 8)), vec![at(limb)]));
                }
            } else {
                positions.push(k / 8, term(-(1 << (k % 8)), vec![at(magnitude)]));
            }
            let n = k.div_ceil(8);
            for i in 0..n {
                let bits = if i + 1 == n { k - 8 * (n - 1) } else { 8 } as u8;
                let name = alloc::format!("remainder/{i}");
                let limb = b.witness(&name, Width::unsigned(bits), out);
                positions.push(i, term(-1, vec![at(limb)]));
                remainder.push(limb);
            }
        }
        if !vanishing {
            chains.push((
                alloc::format!("{prefix}/round"),
                Chain::declare(&mut b, "round", out, 8, positions.0),
            ));
        }

        // Y = mask*factor*Ymag - 2*mask*factor*tau*Ymag.
        let (output, output_bytes) = if wide_output {
            let y = b.column("output", Width::signed(24), out);
            let limbs = vec![
                b.witness("output/0", Width::unsigned(8), out),
                b.witness("output/1", Width::unsigned(8), out),
                b.witness("output/2", Width::signed(8), out),
            ];
            b.relation.composes.push(Compose {
                name: alloc::format!("{prefix}/output/compose"),
                column: y,
                limbs: limbs
                    .iter()
                    .enumerate()
                    .map(|(k, &id)| (id, (8 * k) as u8))
                    .collect(),
            });
            let mut positions = Positions(Vec::new());
            for (j, (&out_j, &mag_j)) in limbs.iter().zip(&magnitude_bytes).enumerate() {
                positions.push(j, term(1, vec![at(out_j)]));
                positions.push(j, term(-factor, vec![at(mask), at(mag_j)]));
                positions.push(j, term(2 * factor, vec![at(mask), at(sign), at(mag_j)]));
            }
            chains.push((
                alloc::format!("{prefix}/output"),
                Chain::declare(&mut b, "output", out, 8, positions.0),
            ));
            (y, limbs)
        } else {
            let y = b.witness("output", Width::signed(16), out);
            b.identity(
                "output",
                out,
                vec![
                    term(1, vec![at(y)]),
                    term(-factor, vec![at(mask), at(magnitude)]),
                    term(2 * factor, vec![at(mask), at(sign), at(magnitude)]),
                ],
            );
            (y, Vec::new())
        };
        self.columns = Some(Columns {
            weight,
            fold_scale_bytes,
            digits,
            sums,
            bytes: v,
            sign,
            scale_bytes,
            magnitude,
            magnitude_bytes,
            remainder,
            output,
            output_bytes,
            chains,
        });
    }

    fn assign(
        &self,
        relation: &Relation,
        capture: &ProjectionCapture,
        values: &mut Values,
    ) -> Result<(), Violation> {
        let mut w = self.source(relation, capture)?;
        self.complete(&mut w, Step::Digits, None);
        // The executor's outputs must be the ones the relations force.
        let (_, _, _, lo) = self.logs();
        let ok = (0..w.output.len())
            .all(|x| !self.real(x) || w.output[x] == capture.outputs[x >> lo][x & ((1 << lo) - 1)]);
        if !ok {
            return Err(Invalid::Column(self.output_id()).into());
        }
        self.write(relation, &w, values, None)
    }
}

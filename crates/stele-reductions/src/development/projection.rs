//! Affine projection of converted int8 rows (RFC-0026 §5 row 4; RFC-0025 §2.2/2.5,
//! grouped rows RFC-0004 A15, gated scales RFC-0004 A8; `SCALED-LINEAR.md`).
//!
//! Family 1, no bias: `Y_j = R(V_j * m_j * u * 2^l)` with one round-half-away and
//! int16 rejection, where `l = e - f + fo` and
//! - per-row input: `V = A = sum_i q_i*w_ji` (one matmul) and `u = s`;
//! - grouped input: `V = A' = sum_i s_k(i)*q_i*w_ji` and `u = 1`. The folded value
//!   `q_i*s_k(i) = b0_i + 256*b1_i` is split into digit rows, `C_t = sum_i b_t,i*w_ji`
//!   is one matmul per digit and `V = C_0 + 256*C_1` (RFC-0004 A15 digit rows).
//!
//! Wide values never appear in one relation (limb rule, RFC-0026 §3.5):
//! - sign chain: `sum_t 256^t C_t = (1-2*tau) * sum_k 256^k v_k` with byte limbs `v_k`;
//! - scale bytes: `s = sum_c 256^c s_c`;
//! - rounding chain, for `l < 0` with `K = -l`:
//!   `sum v_a*m_b*s_c*256^(a+b+c) + 2^(K-1) = Ymag*2^K + rho`, `rho` in `[0, 2^K)` as
//!   byte limbs; for `l >= 0`: `sum v_a*m_b*s_c*256^(a+b+c+l/8) = Ymag'` and
//!   `Ymag = 2^(l mod 8) * Ymag'`;
//! - output: `Y = mask * (1 - 2*tau) * Ymag`, signed 16, zero on padding.
//!
//! `m_j` is split into two public bytes per channel; padded channels have `m = 0`.
//! Output-uniqueness lemma P: `agents/reviews/e16-05-projections.md`.

use super::{bit_length, log2_ceil, r, signed_for, term, Builder, Chain, RowOutput, Unsupported};
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use stele_ir::relation::{
    ColumnId, Invalid, Kind, Matmul, Module, Range, Relation, Term, Values, Violation, Width,
    MAX_VARS, MAX_WIDTH_BITS,
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
}

/// Executor intermediates of one projection over every real row.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProjectionCapture {
    /// `[row][lane]` input codes and `[row][group]` input scales (the row conversion's).
    pub codes: Vec<Vec<i64>>,
    pub scales: Vec<Vec<u32>>,
    /// `[output][lane]` weight codes; padded weight entries are zero.
    pub weights: Vec<Vec<i64>>,
    /// `[row][output]` int16 projection outputs.
    pub outputs: Vec<Vec<i64>>,
}

#[derive(Clone, Debug)]
struct Columns {
    weight: ColumnId,
    /// Grouped only: digit columns `b0`, `b1`.
    digits: Vec<ColumnId>,
    /// One matmul output per digit row.
    sums: Vec<ColumnId>,
    bytes: Vec<ColumnId>,
    sign: ColumnId,
    /// Per-row only: scale bytes.
    scale_bytes: Vec<ColumnId>,
    magnitude: ColumnId,
    remainder: Vec<ColumnId>,
    output: ColumnId,
    chains: Vec<Chain>,
}

/// One projection reading a converted row (RFC-0026 §5 row 4).
pub struct Projection {
    prefix: String,
    input: RowOutput,
    weight: Option<ColumnId>,
    plan: ProjectionPlan,
    columns: Option<Columns>,
}

/// Bytes needed for `n`.
fn bytes(n: u128) -> usize {
    usize::from(bit_length(n)).div_ceil(8).max(1)
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
        let grouped = input.log_group < input.log_dimension;
        let shape = plan.rows > 0
            && (1..=16384).contains(&plan.inner)
            && plan.outputs > 0
            && plan.mantissas.len() == plan.outputs
            && matches!(plan.weight_bits, 4 | 8)
            && log2_ceil(plan.rows) == input.log_rows
            && log2_ceil(plan.inner) == input.log_dimension;
        if !shape {
            return Err(Unsupported::Shape);
        }
        let bound = if grouped { GROUPED_SCALE } else { GATED_SCALE };
        if input.scale_bound == 0 || input.scale_bound > bound {
            return Err(Unsupported::Policy);
        }
        // shortcut: no row-block split; plans past MAX_VARS need Ref constant bits (E16-01).
        let domain = input.log_rows + log2_ceil(plan.outputs) + input.log_dimension;
        if domain > MAX_VARS {
            return Err(Unsupported::Domain);
        }
        let this = Self {
            prefix: prefix.into(),
            input,
            weight,
            plan,
            columns: None,
        };
        if this.sum_widths().iter().any(|w| w.bits > MAX_WIDTH_BITS) {
            return Err(Unsupported::Domain);
        }
        Ok(this)
    }

    fn grouped(&self) -> bool {
        self.input.log_group < self.input.log_dimension
    }

    fn weight_width(&self) -> Width {
        Width::signed(self.plan.weight_bits)
    }

    /// Digit widths of the matmul left operand.
    fn digit_widths(&self) -> Vec<Width> {
        if self.grouped() {
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

    /// Output column (`T x o`, signed 16); `None` before `declare`.
    pub fn output(&self) -> Option<ColumnId> {
        self.columns.as_ref().map(|c| c.output)
    }

    /// The weight column read (declared here unless one was supplied).
    pub fn weight(&self) -> Option<ColumnId> {
        self.columns.as_ref().map(|c| c.weight)
    }

    fn logs(&self) -> (u8, u8, u8, u8) {
        let i = self.input;
        (
            i.log_rows,
            i.log_dimension,
            i.log_group,
            log2_ceil(self.plan.outputs),
        )
    }
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

impl Module for Projection {
    type Capture = ProjectionCapture;

    fn declare(&mut self, relation: &mut Relation) {
        let (t, ld, lg, lo) = self.logs();
        let (lanes, out) = (t + ld, t + lo);
        let grouped = self.grouped();
        let prefix = self.prefix.clone();
        let plan = &self.plan;
        let mut b = Builder::new(relation, &prefix);

        let weight = self.weight.unwrap_or_else(|| {
            let name = alloc::format!("{prefix}/weight");
            let id = b
                .relation
                .add_column(&name, Kind::Weight, self.weight_width(), lo + ld);
            b.relation.ranges.push(Range {
                name,
                column: id,
                width: self.weight_width(),
            });
            id
        });
        let mask = (0..1usize << out)
            .map(|x| i64::from((x >> lo) < plan.rows && (x & ((1 << lo) - 1)) < plan.outputs))
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
        let codes = r(self.input.codes, 0..lanes);
        let digits: Vec<ColumnId> = if grouped {
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
            d
        } else {
            Vec::new()
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
            b.relation.matmuls.push(Matmul {
                name: alloc::format!("{prefix}/sum/{k}"),
                free: out,
                summed: ld,
                out: at(sum),
                lhs: r(*column, summed.iter().copied().chain(lo..out)),
                rhs: r(weight, summed.iter().copied().chain(0..lo)),
            });
            sums.push(sum);
        }

        // Sign chain: sum_t 256^t C_t - (1 - 2 tau) sum_k 256^k v_k = 0.
        let vmax = self
            .sum_bounds()
            .iter()
            .enumerate()
            .map(|(k, c)| c << (8 * k))
            .sum::<u128>();
        let sign = b.witness("sign", Width::unsigned(1), out);
        let v: Vec<ColumnId> = (0..bytes(vmax))
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
        let sign_chain = Chain::declare(&mut b, "sign", out, positions.0);

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
        let magnitude = b.witness("magnitude", Width::unsigned(16), out);
        let shift = plan.shift;
        let (offset, scale) = if shift >= 0 {
            ((shift / 8) as usize, 1i64 << (shift % 8))
        } else {
            (0, 1)
        };
        // |V*m*u| <= vmax*65535*u_max; past that many bits R(.) is identically 0.
        // The scale bytes bound s below 2^bits(scale_bound).
        let u_max = if grouped {
            1
        } else {
            (1u128 << bit_length(u128::from(self.input.scale_bound))) - 1
        };
        let pmax = vmax * 65535 * u_max;
        let vanishing = shift < 0 && (-shift) as u32 > u32::from(bit_length(pmax)) + 1;
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
        let mut chains = vec![sign_chain];
        if vanishing {
            b.identity("vanishing", out, vec![term(1, vec![at(magnitude)])]);
        } else if shift >= 0 {
            positions.push(0, term(-1, vec![at(magnitude)]));
        } else {
            let k = (-shift) as usize;
            positions.push((k - 1) / 8, term(1 << ((k - 1) % 8), vec![]));
            positions.push(k / 8, term(-(1 << (k % 8)), vec![at(magnitude)]));
            let n = k.div_ceil(8);
            for i in 0..n {
                let bits = if i + 1 == n { k - 8 * (n - 1) } else { 8 } as u8;
                let limb = b.witness(&alloc::format!("remainder/{i}"), Width::unsigned(bits), out);
                positions.push(i, term(-1, vec![at(limb)]));
                remainder.push(limb);
            }
        }
        if !vanishing {
            chains.push(Chain::declare(&mut b, "round", out, positions.0));
        }

        // Y = mask*scale*Ymag - 2*mask*scale*tau*Ymag.
        let output = b.witness("output", Width::signed(16), out);
        b.identity(
            "output",
            out,
            vec![
                term(1, vec![at(output)]),
                term(-scale, vec![at(mask), at(magnitude)]),
                term(2 * scale, vec![at(mask), at(sign), at(magnitude)]),
            ],
        );
        self.columns = Some(Columns {
            weight,
            digits,
            sums,
            bytes: v,
            sign,
            scale_bytes,
            magnitude,
            remainder,
            output,
            chains,
        });
    }

    fn assign(
        &self,
        relation: &Relation,
        capture: &ProjectionCapture,
        values: &mut Values,
    ) -> Result<(), Violation> {
        let c = self
            .columns
            .as_ref()
            .ok_or(Violation::Missing(self.input.codes))?;
        let (t, ld, lg, lo) = self.logs();
        let (lanes, out) = (t + ld, t + lo);
        let plan = &self.plan;
        let real_groups = plan.inner.div_ceil(1 << lg);
        let shape_ok = capture.codes.len() == plan.rows
            && capture.codes.iter().all(|row| row.len() == plan.inner)
            && capture.scales.len() == plan.rows
            && capture.scales.iter().all(|row| row.len() == real_groups)
            && capture.weights.len() == plan.outputs
            && capture.weights.iter().all(|row| row.len() == plan.inner)
            && capture.outputs.len() == plan.rows
            && capture.outputs.iter().all(|row| row.len() == plan.outputs);
        if !shape_ok {
            return Err(Invalid::Column(c.output).into());
        }
        // Scale per (row, group); a public (static) scale column is read as declared.
        let public = match &relation.column(self.input.scale).map(|col| &col.kind) {
            Some(Kind::Public(v)) => Some(v.clone()),
            _ => None,
        };
        let scale = |row: usize, group: usize| -> i64 {
            if let Some(v) = &public {
                v[(row << (ld - lg)) | group]
            } else if row < plan.rows && group < real_groups {
                i64::from(capture.scales[row][group])
            } else {
                0
            }
        };
        let code = |row: usize, i: usize| -> i64 {
            if row < plan.rows && i < plan.inner {
                capture.codes[row][i]
            } else {
                0
            }
        };
        // Matmul left operands per lane: codes, or the A15 digits of q*s.
        let operands: Vec<Vec<i64>> = if c.digits.is_empty() {
            vec![(0..1usize << lanes)
                .map(|x| code(x >> ld, x & ((1 << ld) - 1)))
                .collect()]
        } else {
            let folded: Vec<i64> = (0..1usize << lanes)
                .map(|x| {
                    let (row, i) = (x >> ld, x & ((1 << ld) - 1));
                    code(row, i) * scale(row, i >> lg)
                })
                .collect();
            let low: Vec<i64> = folded.iter().map(|f| f.rem_euclid(256)).collect();
            let high: Vec<i64> = folded.iter().map(|f| f.div_euclid(256)).collect();
            values.set(relation, c.digits[0], low.clone())?;
            values.set(relation, c.digits[1], high.clone())?;
            vec![low, high]
        };
        let size = 1usize << out;
        let mut sums = vec![vec![0i64; size]; c.sums.len()];
        for x in 0..size {
            let (row, j) = (x >> lo, x & ((1 << lo) - 1));
            if j >= plan.outputs {
                continue;
            }
            for (sum, operand) in sums.iter_mut().zip(&operands) {
                sum[x] = (0..plan.inner)
                    .map(|i| operand[(row << ld) | i] * capture.weights[j][i])
                    .sum();
            }
        }
        let mut sign = vec![0; size];
        let mut bytes = vec![vec![0; size]; c.bytes.len()];
        let mut magnitude = vec![0; size];
        let mut remainder = vec![vec![0; size]; c.remainder.len()];
        let mut output = vec![0; size];
        for x in 0..size {
            let (row, j) = (x >> lo, x & ((1 << lo) - 1));
            let wide: i128 = sums
                .iter()
                .enumerate()
                .map(|(k, s)| i128::from(s[x]) << (8 * k))
                .sum();
            sign[x] = i64::from(wide < 0);
            for (k, column) in bytes.iter_mut().enumerate() {
                column[x] = ((wide.unsigned_abs() >> (8 * k)) & 255) as i64;
            }
            let y = if row < plan.rows && j < plan.outputs {
                capture.outputs[row][j]
            } else {
                0
            };
            output[x] = y;
            let m = plan.mantissas.get(j).map_or(0, |m| i128::from(*m));
            let u = if c.scale_bytes.is_empty() {
                1
            } else {
                i128::from(scale(row, 0))
            };
            let product = wide.abs() * m * u;
            magnitude[x] = y.abs();
            if plan.shift >= 0 {
                magnitude[x] = y.abs() >> (plan.shift % 8);
            } else if !c.remainder.is_empty() {
                let k = (-plan.shift) as u32;
                // rho = P + 2^(K-1) - |Y|*2^K; out of [0,2^K) only for a wrong output.
                let rho = product + (1i128 << (k - 1)) - (i128::from(y.abs()) << k);
                let last = remainder.len() - 1;
                for (i, column) in remainder.iter_mut().enumerate() {
                    column[x] = if i == last {
                        (rho >> (8 * i)) as i64
                    } else {
                        ((rho >> (8 * i)) & 255) as i64
                    };
                }
            }
        }
        for (id, column) in c.sums.iter().zip(sums) {
            values.set(relation, *id, column)?;
        }
        for (id, column) in c.bytes.iter().zip(bytes) {
            values.set(relation, *id, column)?;
        }
        for (id, column) in c.remainder.iter().zip(remainder) {
            values.set(relation, *id, column)?;
        }
        values.set(relation, c.sign, sign)?;
        values.set(relation, c.magnitude, magnitude)?;
        values.set(relation, c.output, output)?;
        for (k, id) in c.scale_bytes.iter().enumerate() {
            let column = (0..1usize << t)
                .map(|row| (scale(row, 0) >> (8 * k)) & 255)
                .collect();
            values.set(relation, *id, column)?;
        }
        for chain in &c.chains {
            chain.assign(relation, values)?;
        }
        Ok(())
    }
}

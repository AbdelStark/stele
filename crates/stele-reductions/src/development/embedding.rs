//! RFC-0026 §5 row 1: the family-1 embedding gather of RFC-0025 §2.5,
//! `R0[t,k] = R(e[x_t,k] · m[x_t] · 2^s)` with `s = ee + f0` and one half-away rounding.
//!
//! Columns: the token embedding `E` (weight, V×d), the gathered codes `G = O·E` (one
//! matmul per row block, `O` the public one-hot of the tokens), the sign `σ` of `G`
//! (lookup `(G, σ)`), the output `R0` (T×d) and, when `s < 0`, the rounding remainder
//! `ρ` (one or two range-checked limbs). Public: `O`, `m[t] = m[x_t]`, the real-feature
//! mask `w[k] = [k < d]` and block masks. Shared patterns: sign, round-half-away.
//!
//! **Output uniqueness (RFC-0026 §5.2).** The matmul fixes `G[t,k] = E[x_t,k]`. The sign
//! lookup fixes `σ = [G < 0]`. With `P = G·m·w`:
//! - `s >= 0`: the identity `R0 = P·mm` (public `mm = min(m·2^s, 2^16)`) fixes `R0`; when
//!   `m·2^s >= 2^16` and `G != 0`, `|R0| >= 2^16` contradicts the int16 range, as the
//!   executor rejects the row.
//! - `s < 0`, `h = min(−s, 24)`: `ρ = 2^h·R0 − P + σ + 2^(h−1) − 1 ∈ [0, 2^h)` says
//!   `2^h·R0 − P ∈ (−2^(h−1), 2^(h−1)]` when `P >= 0` and `[−2^(h−1), 2^(h−1))` when
//!   `P < 0`: exactly `R0 = R(P/2^h)`, so `R0` is unique. `|P| < 2^23`, so capping `h`
//!   at 24 leaves every result 0, as at the true shift. At `w = 0`, `P = 0` forces
//!   `R0 = 0` for either `σ`, which pins the padding.

use super::limbs::{at, log2_ceil, sign_table, term, Scope};
use super::Unsupported;
use alloc::format;
use alloc::vec;
use alloc::vec::Vec;
use stele_ir::relation::{
    ColumnId, Kind, Lookup, Matmul, Module, Relation, Values, Violation, Width, MAX_VARS,
};

/// Plan data of the family-1 token embedding (RFC-0025 §2.1, §2.5).
#[derive(Clone, Debug)]
pub struct EmbeddingPlan {
    /// The window's tokens `x_0..x_{T-1}`; `T` is a power of two.
    pub tokens: Vec<u32>,
    /// Vocabulary size `V`.
    pub vocabulary: u32,
    /// Model width `d`.
    pub width: u16,
    /// Code width of the embedding record: 4 or 8.
    pub code_bits: u8,
    /// Row mantissas `m_v` of the token-embedding scale, one per vocabulary row.
    pub mantissas: Vec<u16>,
    /// The token-embedding scale exponent `ee`.
    pub exponent: i16,
    /// The first residual fraction `f0`.
    pub fraction: u8,
}

/// The executor's embedding intermediates for every token row (RFC-0026 §3.8).
#[derive(Clone, Debug)]
pub struct EmbeddingCapture {
    /// Gathered codes `e[x_t, k]`, `T` rows of `d`.
    pub codes: Vec<Vec<i16>>,
    /// The int16 residual `R0`, `T` rows of `d`.
    pub output: Vec<Vec<i16>>,
}

struct Columns {
    weight: ColumnId,
    blocks: Vec<ColumnId>,
    gathered: ColumnId,
    sign: ColumnId,
    output: ColumnId,
    remainder: Vec<ColumnId>,
}

/// RFC-0026 §5 row 1 module.
pub struct Embedding {
    plan: EmbeddingPlan,
    scope: Scope,
    columns: Option<Columns>,
    /// Largest matmul domain; tests lower it to exercise row blocks.
    pub(crate) limit: u8,
}

/// RFC-0026 §3.1 domain cap for the gather matmuls.
pub(crate) const MAX_BLOCK_VARS: u8 = MAX_VARS;

const CAP: i32 = 24;

impl Embedding {
    pub fn new(plan: EmbeddingPlan, scope: &str) -> Result<Self, Unsupported> {
        let ok = plan.tokens.len().is_power_of_two()
            && plan.tokens.iter().all(|&x| x < plan.vocabulary)
            && plan.mantissas.len() == plan.vocabulary as usize
            && plan.mantissas.iter().all(|&m| m >= 1)
            && plan.width >= 1
            && matches!(plan.code_bits, 4 | 8)
            && log2_ceil(plan.width.into()) + log2_ceil(plan.vocabulary as usize) <= MAX_VARS;
        if !ok {
            return Err(Unsupported::Shape);
        }
        Ok(Self {
            plan,
            scope: Scope { name: scope.into() },
            columns: None,
            limit: MAX_BLOCK_VARS,
        })
    }

    /// The weight column `E` (a tied head reuses it, RFC-0026 §2.2).
    pub fn weight(&self) -> Option<ColumnId> {
        self.columns.as_ref().map(|c| c.weight)
    }

    /// The residual `R0` (T×d) consumed by the first norm (RFC-0026 §5.1).
    pub fn output(&self) -> Option<ColumnId> {
        self.columns.as_ref().map(|c| c.output)
    }

    fn shift(&self) -> i32 {
        i32::from(self.plan.exponent) + i32::from(self.plan.fraction)
    }

    fn mantissa(&self, t: usize) -> i64 {
        i64::from(self.plan.mantissas[self.plan.tokens[t] as usize])
    }

    fn logs(&self) -> (u8, u8, u8) {
        let p = &self.plan;
        (
            log2_ceil(p.tokens.len()),
            log2_ceil(p.width.into()),
            log2_ceil(p.vocabulary as usize),
        )
    }
}

impl Module for Embedding {
    type Capture = EmbeddingCapture;

    fn declare(&mut self, relation: &mut Relation) {
        let (lt, ld, lv) = self.logs();
        let (t, d) = (self.plan.tokens.len(), usize::from(self.plan.width));
        let scope = &self.scope;
        let bits = self.plan.code_bits;
        let code = Width::signed(bits);
        let weight = relation.add_column(&format!("{}/E", scope.name), Kind::Weight, code, lv + ld);
        scope.range(relation, weight, code);
        // RFC-0026 §3.6: a matmul domain has at most MAX_VARS bits, so rows are blocked.
        let lb = lt.min(self.limit - ld - lv);
        let size = 1usize << lb;
        let mut blocks = Vec::new();
        for b in 0..t / size {
            let onehot = (0..size << lv)
                .map(|i| {
                    i64::from(
                        self.plan.tokens[b * size + (i >> lv)] as usize == i & ((1 << lv) - 1),
                    )
                })
                .collect();
            let onehot = scope.public(relation, &format!("O{b}"), onehot, lb + lv);
            let out = if lb == lt {
                scope.witness(relation, "G", code, ld + lt)
            } else {
                scope.ranged(relation, &format!("G{b}"), code, ld + lb)
            };
            relation.matmuls.push(Matmul {
                name: format!("{}/gather{b}", scope.name),
                free: ld + lb,
                summed: lv,
                out: at(out, 0..ld + lb),
                lhs: at(onehot, (ld + lb..ld + lb + lv).chain(ld..ld + lb)),
                rhs: at(weight, (0..ld).chain(ld + lb..ld + lb + lv)),
            });
            blocks.push(out);
        }
        let all = || 0..ld + lt;
        let gathered = if lb == lt {
            blocks[0]
        } else {
            let gathered = scope.witness(relation, "G", code, ld + lt);
            let mut terms = vec![term(1, vec![at(gathered, all())])];
            for (b, &block) in blocks.iter().enumerate() {
                let mask = (0..t).map(|i| i64::from(i / size == b)).collect();
                let mask = scope.public(relation, &format!("B{b}"), mask, lt);
                terms.push(term(
                    -1,
                    vec![at(mask, ld..ld + lt), at(block, (0..ld).chain(ld..ld + lb))],
                ));
            }
            scope.identity(relation, "blocks", ld + lt, terms);
            gathered
        };
        let sign = scope.witness(relation, "sigma", Width::unsigned(1), ld + lt);
        let table = sign_table(relation, bits);
        relation.lookups.push(Lookup {
            name: format!("{}/sign", scope.name),
            vars: ld + lt,
            selector: None,
            tuple: vec![at(gathered, all()), at(sign, all())],
            table,
        });
        let mask = (0..1usize << ld).map(|k| i64::from(k < d)).collect();
        let mask = scope.public(relation, "w", mask, ld);
        let shift = self.shift();
        let mut remainder = Vec::new();
        let output;
        if shift >= 0 {
            let scaled = (0..t)
                .map(|i| {
                    if shift >= 17 {
                        1 << 16
                    } else {
                        (self.mantissa(i) << shift).min(1 << 16)
                    }
                })
                .collect();
            let scaled = scope.public(relation, "mm", scaled, lt);
            output = scope.ranged(relation, "R0", Width::signed(16), ld + lt);
            scope.identity(
                relation,
                "exact",
                ld + lt,
                vec![
                    term(1, vec![at(output, all())]),
                    term(
                        -1,
                        vec![
                            at(gathered, all()),
                            at(scaled, ld..ld + lt),
                            at(mask, 0..ld),
                        ],
                    ),
                ],
            );
        } else {
            let h = (-shift).min(CAP) as u8;
            // |P| <= 2^(bits-1)·65535, so |R0| <= (that + 2^(h-1)) >> h: narrow R0 to keep the
            // identity under p (the int16 interface width is an upper bound, RFC-0026 §5.1).
            let largest = ((1u64 << (bits - 1)) * 65535 + (1 << (h - 1))) >> h;
            let width = super::limbs::width_of(-(largest as i128), largest as i128);
            output = scope.ranged(relation, "R0", Width::signed(width.bits.min(16)), ld + lt);
            let m = (0..t).map(|i| self.mantissa(i)).collect();
            let m = scope.public(relation, "m", m, lt);
            let mut terms = vec![
                term(1 << h, vec![at(output, all())]),
                term(
                    -1,
                    vec![at(gathered, all()), at(m, ld..ld + lt), at(mask, 0..ld)],
                ),
                term(1, vec![at(sign, all())]),
            ];
            if h > 1 {
                terms.push(term((1 << (h - 1)) - 1, vec![]));
            }
            let mut left = h;
            for i in 0..2 {
                if left == 0 {
                    break;
                }
                let bits = left.min(16);
                let limb =
                    scope.ranged(relation, &format!("rho{i}"), Width::unsigned(bits), ld + lt);
                terms.push(term(-(1 << (16 * i)), vec![at(limb, all())]));
                remainder.push(limb);
                left -= bits;
            }
            scope.identity(relation, "round", ld + lt, terms);
        }
        self.columns = Some(Columns {
            weight,
            blocks,
            gathered,
            sign,
            output,
            remainder,
        });
    }

    fn assign(
        &self,
        relation: &Relation,
        capture: &EmbeddingCapture,
        values: &mut Values,
    ) -> Result<(), Violation> {
        let c = self
            .columns
            .as_ref()
            .ok_or(Violation::Missing(ColumnId(0)))?;
        let (lt, ld, _) = self.logs();
        let (t, d) = (self.plan.tokens.len(), usize::from(self.plan.width));
        let grid = |rows: &Vec<Vec<i16>>, column: ColumnId| -> Result<Vec<i64>, Violation> {
            if rows.len() != t || rows.iter().any(|r| r.len() != d) {
                return Err(Violation::Missing(column));
            }
            let mut out = vec![0; 1 << (ld + lt)];
            for (i, row) in rows.iter().enumerate() {
                for (k, &v) in row.iter().enumerate() {
                    out[(i << ld) + k] = i64::from(v);
                }
            }
            Ok(out)
        };
        // Padded weight entries are committed as 0 (RFC-0026 §2.1), so G is 0 there too.
        let gathered = grid(&capture.codes, c.gathered)?;
        let output = grid(&capture.output, c.output)?;
        let size = t / c.blocks.len();
        if c.blocks.len() > 1 {
            for (b, &block) in c.blocks.iter().enumerate() {
                let rows = gathered[(b * size) << ld..((b + 1) * size) << ld].to_vec();
                values.set(relation, block, rows)?;
            }
        }
        let sign: Vec<i64> = gathered.iter().map(|&g| i64::from(g < 0)).collect();
        if let [low, rest @ ..] = c.remainder.as_slice() {
            let h = (-self.shift()).min(CAP);
            let rho: Vec<i64> = (0..gathered.len())
                .map(|i| {
                    let (row, k) = (i >> ld, i & ((1 << ld) - 1));
                    let p = gathered[i] * self.mantissa(row) * i64::from(k < d);
                    (output[i] << h) - p + sign[i] + (1 << (h - 1)) - 1
                })
                .collect();
            if let [high] = rest {
                values.set(relation, *low, rho.iter().map(|r| r & 0xffff).collect())?;
                values.set(relation, *high, rho.iter().map(|r| r >> 16).collect())?;
            } else {
                values.set(relation, *low, rho)?;
            }
        }
        values.set(relation, c.gathered, gathered)?;
        values.set(relation, c.sign, sign)?;
        values.set(relation, c.output, output)?;
        Ok(())
    }
}

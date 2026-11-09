//! Gated row conversion of the SiLU product to down-projection codes (RFC-0026 §5
//! row 10 and the §5 gated-scale ceiling; RFC-0025 §2.5, RFC-0004 A8, flow §1).
//!
//! Input: `T = 2^15·high + low` from [`super::GatedProduct`], `|T| < 2^30`, one dynamic
//! scale per row. Every value wider than 16 bits is two radix-`2^15` limbs, and every
//! wide identity is a low and a high limb identity joined by a carry (RFC-0026 §3.5):
//! - sign/abs: `mask·T = (1 − 2σ)·A`, `A = 2^15·Ah + Al`, with the borrow `κ` of the
//!   negation, so `A = |T|` on real lanes and 0 on padding;
//! - attained maximum: `M − A = 2^15·gh + gl >= 0` (borrow `b`), a one-hot `h` per row
//!   (matmul row sum) with `h·gl = h·gh = 0`, so `M = max A`;
//! - gated-scale ceiling: `127·s − M = slack ∈ [0, 126]` (lookup), so `s = ceil(M/127)`,
//!   `s = 2^15·sh + sl <= 8454661`, and `scale` is their Compose (unsigned 24);
//! - zero-row branch: Boolean `z` with `z·(Ml + Mh) = 0` and divisor `D = s + z`;
//! - division: `2A + D − 2q·D = r` with `0 <= r <= 2D − 1` (`r` and `2D − 1 − r` in
//!   limbs), so `q = floor((2A + D)/(2D))`, the executor's code magnitude, and `D >= 1`;
//! - code `c = (1 − 2σ)·q`.
//!
//! The output is E16-05's [`RowOutput`]. Output-uniqueness lemma:
//! `agents/reviews/e16-08-silu.md`, lemma C.

use crate::development::{log2_ceil, r, term, Builder, Policy, RowOutput, Unsupported};
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use stele_ir::relation::{
    ColumnId, Compose, Lookup, Matmul, Module, Relation, Table, Values, Violation, Width,
};

/// Largest gated dynamic scale, `ceil((2^30 − 1)/127)` (RFC-0004 A8).
pub const GATED_SCALE: u32 = 8454661;
const LIMB: i64 = 1 << 15;

/// Lane columns, then row columns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConversionColumns {
    pub sign: ColumnId,
    pub borrow: ColumnId,
    pub magnitude_low: ColumnId,
    pub magnitude_high: ColumnId,
    pub gap_low: ColumnId,
    pub gap_high: ColumnId,
    pub gap_borrow: ColumnId,
    pub hit: ColumnId,
    pub quotient: ColumnId,
    pub codes: ColumnId,
    pub remainder_low: ColumnId,
    pub remainder_high: ColumnId,
    pub remainder_carry: ColumnId,
    pub spare_low: ColumnId,
    pub spare_high: ColumnId,
    pub spare_carry: ColumnId,
    pub maximum_low: ColumnId,
    pub maximum_high: ColumnId,
    pub scale_low: ColumnId,
    pub scale_high: ColumnId,
    pub scale: ColumnId,
    pub slack: ColumnId,
    pub ceiling_carry: ColumnId,
    pub zero: ColumnId,
}

/// The gated row conversion of one layer's `(tokens, hidden)` product.
#[derive(Clone, Debug)]
pub struct GatedConversion {
    prefix: String,
    high: ColumnId,
    low: ColumnId,
    tokens: usize,
    hidden: usize,
    columns: Option<ConversionColumns>,
}

impl GatedConversion {
    /// `high`, `low`: the [`super::GatedColumns`] limbs. Only the dynamic per-row
    /// policy is supported (RFC-0026 §1.3).
    pub fn new(
        layer: usize,
        high: ColumnId,
        low: ColumnId,
        tokens: usize,
        hidden: usize,
        policy: Policy,
    ) -> Result<Self, Unsupported> {
        if tokens == 0 || !(1..=16384).contains(&hidden) {
            return Err(Unsupported::Shape);
        }
        // shortcut: static and grouped gated rows are rejected; add them with a plan
        // that needs them (static: public scale; grouped: per-group scale folds).
        if policy != Policy::Dynamic {
            return Err(Unsupported::Policy);
        }
        if log2_ceil(tokens) + log2_ceil(hidden) > stele_ir::relation::MAX_VARS {
            return Err(Unsupported::Domain);
        }
        Ok(Self {
            prefix: format!("L{layer}/gated/row"),
            high,
            low,
            tokens,
            hidden,
            columns: None,
        })
    }

    pub fn columns(&self) -> Option<ConversionColumns> {
        self.columns
    }

    /// What the down projection reads (E16-05 `Projection::new`).
    pub fn output(&self) -> Option<RowOutput> {
        let (t, d) = (log2_ceil(self.tokens), log2_ceil(self.hidden));
        self.columns.map(|c| RowOutput {
            codes: c.codes,
            scale: c.scale,
            log_rows: t,
            log_dimension: d,
            log_group: d,
            scale_bound: GATED_SCALE,
        })
    }

    fn real(&self, x: usize) -> bool {
        let d = log2_ceil(self.hidden);
        (x >> d) < self.tokens && (x & ((1 << d) - 1)) < self.hidden
    }
}

impl Module for GatedConversion {
    /// The unpadded gated product `T`, row-major `(tokens, hidden)`.
    type Capture = [i64];

    fn declare(&mut self, relation: &mut Relation) {
        let (t, d) = (log2_ceil(self.tokens), log2_ceil(self.hidden));
        let n = t + d;
        let mask = (0..1usize << n).map(|x| i64::from(self.real(x))).collect();
        let prefix = self.prefix.clone();
        let mut b = Builder::new(relation, &prefix);
        let mask = b.public("mask", mask, Width::unsigned(1), n);
        let one = b.public("one", vec![1], Width::unsigned(1), 0);
        let u = Width::unsigned;
        let c = ConversionColumns {
            sign: b.witness("sign", u(1), n),
            borrow: b.witness("borrow", u(1), n),
            magnitude_low: b.witness("magnitude/low", u(15), n),
            magnitude_high: b.witness("magnitude/high", u(15), n),
            gap_low: b.witness("gap/low", u(15), n),
            gap_high: b.witness("gap/high", u(15), n),
            gap_borrow: b.witness("gap/borrow", u(1), n),
            hit: b.witness("hit", u(1), n),
            quotient: b.witness("quotient", u(7), n),
            codes: b.witness("codes", Width::signed(8), n),
            remainder_low: b.witness("remainder/low", u(15), n),
            remainder_high: b.witness("remainder/high", u(10), n),
            remainder_carry: b.witness("remainder/carry", Width::signed(10), n),
            spare_low: b.witness("spare/low", u(15), n),
            spare_high: b.witness("spare/high", u(10), n),
            spare_carry: b.witness("spare/carry", Width::signed(3), n),
            maximum_low: b.witness("maximum/low", u(15), t),
            maximum_high: b.witness("maximum/high", u(15), t),
            scale_low: b.witness("scale/low", u(15), t),
            scale_high: b.witness("scale/high", u(9), t),
            scale: b.column("scale", u(24), t),
            slack: b.column("slack", u(7), t),
            ceiling_carry: b.witness("ceiling/carry", Width::signed(8), t),
            zero: b.witness("zero", u(1), t),
        };
        let lane = |id: ColumnId| r(id, 0..n);
        let row = |id: ColumnId| r(id, d..n);
        let (m, sg, k) = (lane(mask), lane(c.sign), lane(c.borrow));
        let (al, ah) = (lane(c.magnitude_low), lane(c.magnitude_high));
        let (tl, th) = (lane(self.low), lane(self.high));
        let (ml, mh, sl, sh, z) = (
            row(c.maximum_low),
            row(c.maximum_high),
            row(c.scale_low),
            row(c.scale_high),
            row(c.zero),
        );
        let (q, rl, rh) = (
            lane(c.quotient),
            lane(c.remainder_low),
            lane(c.remainder_high),
        );

        // Sign/abs, low limb: mask·Tl − 2σ·mask·Tl − Al + 2^15·κ = 0.
        b.identity(
            "sign/low",
            n,
            vec![
                term(1, vec![m.clone(), tl.clone()]),
                term(-2, vec![sg.clone(), m.clone(), tl]),
                term(-1, vec![al.clone()]),
                term(LIMB, vec![k.clone()]),
            ],
        );
        // High limb: mask·Th − 2σ·mask·Th − κ − Ah = 0.
        b.identity(
            "sign/high",
            n,
            vec![
                term(1, vec![m.clone(), th.clone()]),
                term(-2, vec![sg.clone(), m, th]),
                term(-1, vec![k]),
                term(-1, vec![ah.clone()]),
            ],
        );
        // Gap M − A = 2^15·gh + gl, borrow gb.
        let (gl, gh, gb) = (lane(c.gap_low), lane(c.gap_high), lane(c.gap_borrow));
        b.identity(
            "gap/low",
            n,
            vec![
                term(1, vec![ml.clone()]),
                term(-1, vec![al.clone()]),
                term(-1, vec![gl.clone()]),
                term(LIMB, vec![gb.clone()]),
            ],
        );
        b.identity(
            "gap/high",
            n,
            vec![
                term(1, vec![mh.clone()]),
                term(-1, vec![ah.clone()]),
                term(-1, vec![gb]),
                term(-1, vec![gh.clone()]),
            ],
        );
        let hit = lane(c.hit);
        b.identity(
            "attained",
            n,
            vec![term(1, vec![hit.clone(), gl]), term(1, vec![hit, gh])],
        );
        b.relation.matmuls.push(Matmul {
            name: format!("{prefix}/attained/one-hot"),
            free: t,
            summed: d,
            out: r(one, []),
            lhs: r(c.hit, (t..t + d).chain(0..t)),
            rhs: r(one, []),
        });
        // Ceiling 127·s − M = slack: low 127·sl − Ml − slack = 2^15·e, high 127·sh − Mh + e = 0.
        let rows = |id: ColumnId| r(id, 0..t);
        b.identity(
            "ceiling/low",
            t,
            vec![
                term(127, vec![rows(c.scale_low)]),
                term(-1, vec![rows(c.maximum_low)]),
                term(-1, vec![rows(c.slack)]),
                term(-LIMB, vec![rows(c.ceiling_carry)]),
            ],
        );
        b.identity(
            "ceiling/high",
            t,
            vec![
                term(127, vec![rows(c.scale_high)]),
                term(-1, vec![rows(c.maximum_high)]),
                term(1, vec![rows(c.ceiling_carry)]),
            ],
        );
        let table = b.relation.add_table(Table {
            name: "range/0..=126".into(),
            widths: vec![u(7)],
            rows: (0..=126).map(|v| vec![v]).collect(),
        });
        b.relation.lookups.push(Lookup {
            name: format!("{prefix}/ceiling"),
            vars: t,
            selector: None,
            tuple: vec![rows(c.slack)],
            table,
        });
        b.relation.composes.push(Compose {
            name: format!("{prefix}/scale"),
            column: c.scale,
            limbs: vec![(c.scale_low, 0), (c.scale_high, 15)],
        });
        // Zero-row branch: z·(Ml + Mh) = 0.
        b.identity(
            "zero",
            t,
            vec![
                term(1, vec![rows(c.zero), rows(c.maximum_low)]),
                term(1, vec![rows(c.zero), rows(c.maximum_high)]),
            ],
        );
        // Division 2A + D − 2qD = r, D = sl + 2^15·sh + z:
        // low 2Al + sl + z − 2q·sl − 2q·z − rl = 2^15·f; high 2Ah + sh − 2q·sh − rh + f = 0.
        let f = lane(c.remainder_carry);
        b.identity(
            "division/low",
            n,
            vec![
                term(2, vec![al]),
                term(1, vec![sl.clone()]),
                term(1, vec![z.clone()]),
                term(-2, vec![q.clone(), sl.clone()]),
                term(-2, vec![q.clone(), z.clone()]),
                term(-1, vec![rl.clone()]),
                term(-LIMB, vec![f.clone()]),
            ],
        );
        b.identity(
            "division/high",
            n,
            vec![
                term(2, vec![ah]),
                term(1, vec![sh.clone()]),
                term(-2, vec![q.clone(), sh.clone()]),
                term(-1, vec![rh.clone()]),
                term(1, vec![f]),
            ],
        );
        // Spare 2D − 1 − r = 2^15·ph + pl: low 2sl + 2z − 1 − rl − pl = 2^15·g; high 2sh − rh − ph + g = 0.
        let g = lane(c.spare_carry);
        b.identity(
            "spare/low",
            n,
            vec![
                term(2, vec![sl]),
                term(2, vec![z]),
                term(-1, vec![]),
                term(-1, vec![rl]),
                term(-1, vec![lane(c.spare_low)]),
                term(-LIMB, vec![g.clone()]),
            ],
        );
        b.identity(
            "spare/high",
            n,
            vec![
                term(2, vec![sh]),
                term(-1, vec![rh]),
                term(-1, vec![lane(c.spare_high)]),
                term(1, vec![g]),
            ],
        );
        // Code c = q − 2σq.
        b.identity(
            "code",
            n,
            vec![
                term(1, vec![lane(c.codes)]),
                term(-1, vec![q.clone()]),
                term(2, vec![sg, q]),
            ],
        );
        self.columns = Some(c);
    }

    fn assign(
        &self,
        relation: &Relation,
        capture: &[i64],
        values: &mut Values,
    ) -> Result<(), Violation> {
        if capture.len() != self.tokens * self.hidden {
            return Err(Violation::Missing(self.high));
        }
        for (id, column) in self.fill(&self.plan(capture)) {
            values.set(relation, id, column)?;
        }
        Ok(())
    }
}

/// The free choices of a witness, per padded lane or row. The honest plan derives
/// them from `T`; tests change them to build attackers, and [`GatedConversion::fill`]
/// derives every other column from them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Plan {
    /// [lane] `T` (0 on padding).
    pub(crate) product: Vec<i64>,
    /// [lane] `σ` and `A`.
    pub(crate) sign: Vec<i64>,
    pub(crate) magnitude: Vec<i64>,
    /// [row] `M`, and the `M` each gap is measured from.
    pub(crate) maximum: Vec<i64>,
    pub(crate) gap_maximum: Vec<i64>,
    /// [lane] one-hot `h`.
    pub(crate) hit: Vec<i64>,
    /// [row] `s`, `slack` and `z`.
    pub(crate) scale: Vec<i64>,
    pub(crate) slack: Vec<i64>,
    pub(crate) zero: Vec<i64>,
    /// [lane] `q`; honest is `floor((2A + D)/(2D))`.
    pub(crate) quotient: Vec<i64>,
}

impl GatedConversion {
    fn bits(&self) -> (u8, u8) {
        (log2_ceil(self.tokens), log2_ceil(self.hidden))
    }

    pub(crate) fn plan(&self, capture: &[i64]) -> Plan {
        let (t, d) = self.bits();
        let product: Vec<i64> = (0..1usize << (t + d))
            .map(|x| {
                if self.real(x) {
                    capture[(x >> d) * self.hidden + (x & ((1 << d) - 1))]
                } else {
                    0
                }
            })
            .collect();
        let magnitude: Vec<i64> = product.iter().map(|v| v.abs()).collect();
        let width = 1usize << d;
        let maximum: Vec<i64> = magnitude
            .chunks(width)
            .map(|m| m.iter().copied().max().unwrap_or(0))
            .collect();
        let scale: Vec<i64> = maximum.iter().map(|m| (m + 126) / 127).collect();
        let zero: Vec<i64> = maximum.iter().map(|&m| i64::from(m == 0)).collect();
        // The first attained lane, as the executor reports it.
        let mut hit = vec![0; product.len()];
        for (row, m) in magnitude.chunks(width).enumerate() {
            let first = m.iter().position(|v| *v == maximum[row]).unwrap_or(0);
            hit[row * width + first] = 1;
        }
        let quotient = (0..product.len())
            .map(|x| {
                let divisor = scale[x >> d] + zero[x >> d];
                (2 * magnitude[x] + divisor) / (2 * divisor)
            })
            .collect();
        Plan {
            sign: product.iter().map(|&v| i64::from(v < 0)).collect(),
            slack: maximum
                .iter()
                .zip(&scale)
                .map(|(m, s)| 127 * s - m)
                .collect(),
            gap_maximum: maximum.clone(),
            product,
            magnitude,
            maximum,
            hit,
            scale,
            zero,
            quotient,
        }
    }

    /// Every witness column from `plan`: limbs are Euclidean splits and carries are
    /// floors, so a consistent plan satisfies every relation exactly.
    pub(crate) fn fill(&self, plan: &Plan) -> Vec<(ColumnId, Vec<i64>)> {
        let c = self.columns.expect("GatedConversion::fill before declare");
        let (_, d) = self.bits();
        let split = |v: i64| (v.rem_euclid(LIMB), v.div_euclid(LIMB));
        let mut lanes = [(); 16].map(|_| Vec::with_capacity(plan.product.len()));
        for x in 0..plan.product.len() {
            let row = x >> d;
            let (sign, a, q) = (plan.sign[x], plan.magnitude[x], plan.quotient[x]);
            let (sl, _) = split(plan.scale[row]);
            let z = plan.zero[row];
            let divisor = plan.scale[row] + z;
            let (al, ah) = split(a);
            let (gl, gh) = split(plan.gap_maximum[row] - a);
            let (ml, _) = split(plan.gap_maximum[row]);
            let remainder = 2 * a + divisor - 2 * q * divisor;
            let (rl, rh) = split(remainder);
            let (pl, ph) = split(2 * divisor - 1 - remainder);
            let row_values = [
                sign,
                i64::from(sign == 1 && plan.product[x].rem_euclid(LIMB) != 0),
                al,
                ah,
                gl,
                gh,
                i64::from(ml < al),
                plan.hit[x],
                q,
                (1 - 2 * sign) * q,
                rl,
                rh,
                (2 * al + sl + z - 2 * q * (sl + z) - rl).div_euclid(LIMB),
                pl,
                ph,
                (2 * sl + 2 * z - 1 - rl - pl).div_euclid(LIMB),
            ];
            for (column, v) in lanes.iter_mut().zip(row_values) {
                column.push(v);
            }
        }
        let ids = [
            c.sign,
            c.borrow,
            c.magnitude_low,
            c.magnitude_high,
            c.gap_low,
            c.gap_high,
            c.gap_borrow,
            c.hit,
            c.quotient,
            c.codes,
            c.remainder_low,
            c.remainder_high,
            c.remainder_carry,
            c.spare_low,
            c.spare_high,
            c.spare_carry,
        ];
        let mut all: Vec<(ColumnId, Vec<i64>)> = ids.into_iter().zip(lanes).collect();
        let rows = |f: &dyn Fn(usize) -> i64| (0..plan.scale.len()).map(f).collect::<Vec<_>>();
        all.extend([
            (c.maximum_low, rows(&|k| split(plan.maximum[k]).0)),
            (c.maximum_high, rows(&|k| split(plan.maximum[k]).1)),
            (c.scale_low, rows(&|k| split(plan.scale[k]).0)),
            (c.scale_high, rows(&|k| split(plan.scale[k]).1)),
            (c.scale, plan.scale.clone()),
            (c.slack, plan.slack.clone()),
            (
                c.ceiling_carry,
                rows(&|k| {
                    let low = 127 * split(plan.scale[k]).0 - split(plan.maximum[k]).0;
                    (low - plan.slack[k]).div_euclid(LIMB)
                }),
            ),
            (c.zero, plan.zero.clone()),
        ]);
        all
    }
}

#[cfg(test)]
mod tests;

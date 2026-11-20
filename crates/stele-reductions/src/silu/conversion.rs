//! Gated row conversion of the SiLU product to down-projection codes (RFC-0026 §5
//! row 10 and the §5 gated-scale ceiling; RFC-0025 §2.5, RFC-0004 A8 and A15, flow §1).
//!
//! Input: `T = 2^14·high + low` from [`super::GatedProduct`], one dynamic scale per row
//! (`Policy::Dynamic`) or per group of `g` features (`Policy::Grouped(g)`, RFC-0004 A15).
//! `|T| < 2^30` follows from the `silu_q` table restriction (no output `−2^15`,
//! `GatedProduct::new`); the executor's gated envelope is `[−2^30, 2^30]`. Every value wider than 16 bits is two radix-`2^14` limbs, and every
//! wide identity is a low and a high limb identity joined by a carry (RFC-0026 §3.5):
//! - sign/abs: `mask·T = (1 − 2σ)·A`, `A = 2^14·Ah + Al` (`Al: u14, Ah: u16`), with the
//!   borrow `κ` of the negation, so `A = |T|` on real lanes and 0 on padding;
//! - attained maximum: `M − A = 2^14·gh + gl >= 0` (borrow `b`), a one-hot `h` per row
//!   (matmul row sum) with `h·gl = 0` and `h·gh = 0`, so `M = max A`;
//! - gated-scale ceiling: `127·s − M = slack ∈ [0, 126]` (lookup), so `s = ceil(M/127)`,
//!   `s = 2^14·sh + sl <= 8454661` (`sl: u14, sh: u10`), and `scale` is virtual `Def::Linear`;
//! - zero-row branch: Boolean `z` with `z·(Ml + Mh) = 0` and divisor `D = s + z`;
//! - division: `2A + D − 2q·D = r` with `0 <= r <= 2D − 1` (`r` and `2D − 1 − r` in
//!   radix-`2^14` limbs `u14` / `u11`), so `q = floor((2A + D)/(2D))`, the executor's code
//!   magnitude, and `D >= 1`;
//! - code `c = (1 − 2σ)·q`.
//!
//! Committed advice columns (RFC-0028 §1.2):
//! - Lane (`7` cols): `sign (u1)`, `borrow (u1)`, `gap/borrow (u1)`, `hit (u1)`,
//!   `quotient (u7)`, `remainder/carry (s10)`, `spare/carry (s3)`.
//! - Group (`6` cols): `maximum/low (u14)`, `maximum/high (u16)`, `scale/low (u14)`,
//!   `scale/high (u10)`, `ceiling/carry (s8)`, `zero (u1)`.
//!
//! The output is E16-05's [`RowOutput`]. Output-uniqueness lemma:
//! `agents/reviews/e16-08-silu.md`, lemma C.

use crate::development::{log2_ceil, r, term, Builder, Policy, RowOutput, Unsupported};
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use stele_ir::relation::{
    ColumnId, Def, Kind, Lookup, Matmul, Module, Relation, Table, Values, Violation, Width,
};

/// Largest gated dynamic scale, `ceil((2^30 − 1)/127)` (RFC-0004 A8).
pub const GATED_SCALE: u32 = 8454661;
const LIMB_BITS: u8 = super::LOW_BITS;
const LIMB: i64 = 1 << LIMB_BITS;

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
    policy: Policy,
    columns: Option<ConversionColumns>,
}

impl GatedConversion {
    /// `high`, `low`: the [`super::GatedColumns`] limbs. Supports dynamic per-row
    /// (`Policy::Dynamic`) and grouped dynamic (`Policy::Grouped(g)`, RFC-0004 A15)
    /// policies; static gated policies are rejected.
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
        let policy_ok = match policy {
            Policy::Dynamic => true,
            Policy::Grouped(g) => {
                g.is_power_of_two() && (g as usize) < hidden && hidden.is_multiple_of(g as usize)
            }
            Policy::Static(_) => false,
        };
        if !policy_ok {
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
            policy,
            columns: None,
        })
    }

    pub fn columns(&self) -> Option<ConversionColumns> {
        self.columns
    }

    /// What the down projection reads (E16-05 `Projection::new`).
    pub fn output(&self) -> Option<RowOutput> {
        let (t, d, lg) = self.logs();
        self.columns.map(|c| RowOutput {
            codes: c.codes,
            scale: c.scale,
            log_rows: t,
            log_dimension: d,
            log_group: lg,
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
        let (t, d, lg) = self.logs();
        let n = t + d;
        let groups = n - lg;
        let mask = (0..1usize << n).map(|x| i64::from(self.real(x))).collect();
        let prefix = self.prefix.clone();
        let mut b = Builder::new(relation, &prefix);
        let mask = b.public("mask", mask, Width::unsigned(1), n);
        let one = b.public("one", vec![1], Width::unsigned(1), 0);
        let u = Width::unsigned;
        let lane = |id: ColumnId| r(id, 0..n);
        let row = |id: ColumnId| r(id, lg..n);
        let rows = |id: ColumnId| r(id, 0..groups);

        // Committed lane advice (7 cols, RFC-0028 §1.2): sign, borrow, gap_borrow, hit,
        // quotient, remainder_carry, spare_carry.
        let sign = b.witness("sign", u(1), n);
        let borrow = b.witness("borrow", u(1), n);
        let gap_borrow = b.witness("gap/borrow", u(1), n);
        let hit = b.witness("hit", u(1), n);
        let quotient = b.witness("quotient", u(7), n);
        let remainder_carry = b.witness("remainder/carry", Width::signed(10), n);
        let spare_carry = b.witness("spare/carry", Width::signed(3), n);

        // Committed group advice (6 cols): maximum_{low,high}, scale_{low,high}, ceiling_carry, zero.
        let maximum_low = b.witness("maximum/low", u(LIMB_BITS), groups);
        let maximum_high = b.witness("maximum/high", u(30 - LIMB_BITS), groups);
        let scale_low = b.witness("scale/low", u(LIMB_BITS), groups);
        let scale_high = b.witness("scale/high", u(24 - LIMB_BITS), groups);
        let ceiling_carry = b.witness("ceiling/carry", Width::signed(8), groups);
        let zero = b.witness("zero", u(1), groups);

        // Virtual group columns (RFC-0028 §1.2): scale, slack.
        let scale = b.virtual_col(
            "scale",
            Def::Linear {
                constant: 0,
                terms: vec![(1, rows(scale_low)), (LIMB, rows(scale_high))],
            },
            groups,
        );
        let slack = b.virtual_col(
            "slack",
            Def::Linear {
                constant: 0,
                terms: vec![
                    (127, rows(scale_low)),
                    (-1, rows(maximum_low)),
                    (-LIMB, rows(ceiling_carry)),
                ],
            },
            groups,
        );

        let (m, sg, k) = (lane(mask), lane(sign), lane(borrow));
        let (tl, th) = (lane(self.low), lane(self.high));
        let (ml, mh, sl, sh, z) = (
            row(maximum_low),
            row(maximum_high),
            row(scale_low),
            row(scale_high),
            row(zero),
        );
        let q = lane(quotient);

        // Virtual sign/abs limbs: Al = mask*Tl - 2*sigma*mask*Tl + 2^14*borrow ∈ [0, 2^14).
        let magnitude_low = b.virtual_ranged(
            "magnitude/low",
            Def::Pointwise {
                terms: vec![
                    term(1, vec![m.clone(), tl.clone()]),
                    term(-2, vec![sg.clone(), m.clone(), tl]),
                    term(LIMB, vec![k.clone()]),
                ],
            },
            u(LIMB_BITS),
            n,
        );
        // Ah = mask*Th - 2*sigma*mask*Th - borrow ∈ [0, 2^16).
        let magnitude_high = b.virtual_ranged(
            "magnitude/high",
            Def::Pointwise {
                terms: vec![
                    term(1, vec![m.clone(), th.clone()]),
                    term(-2, vec![sg.clone(), m, th]),
                    term(-1, vec![k]),
                ],
            },
            u(30 - LIMB_BITS),
            n,
        );
        let (al, ah) = (lane(magnitude_low), lane(magnitude_high));

        // Virtual gap limbs: gl = Ml - Al + 2^14*gb, gh = Mh - Ah - gb ∈ [0, 2^14) / [0, 2^16).
        let gb = lane(gap_borrow);
        let gap_low = b.virtual_ranged(
            "gap/low",
            Def::Linear {
                constant: 0,
                terms: vec![(1, ml), (-1, al.clone()), (LIMB, gb.clone())],
            },
            u(LIMB_BITS),
            n,
        );
        let gap_high = b.virtual_ranged(
            "gap/high",
            Def::Linear {
                constant: 0,
                terms: vec![(1, mh), (-1, ah.clone()), (-1, gb)],
            },
            u(30 - LIMB_BITS),
            n,
        );
        let (gl, gh) = (lane(gap_low), lane(gap_high));
        let hit_ref = lane(hit);
        b.identity("attained/low", n, vec![term(1, vec![hit_ref.clone(), gl])]);
        b.identity("attained/high", n, vec![term(1, vec![hit_ref, gh])]);
        b.relation.matmuls.push(Matmul {
            name: format!("{prefix}/attained/one-hot"),
            free: groups,
            summed: lg,
            out: r(one, []),
            lhs: r(hit, (groups..n).chain(0..groups)),
            rhs: r(one, []),
        });

        // High ceiling identity + slack lookup in [0, 126].
        b.identity(
            "ceiling/high",
            groups,
            vec![
                term(127, vec![rows(scale_high)]),
                term(-1, vec![rows(maximum_high)]),
                term(1, vec![rows(ceiling_carry)]),
            ],
        );
        let table = b.relation.add_table(Table {
            name: "range/0..=126".into(),
            widths: vec![u(7)],
            rows: (0..=126).map(|v| vec![v]).collect(),
        });
        b.relation.lookups.push(Lookup {
            name: format!("{prefix}/ceiling"),
            vars: groups,
            selector: None,
            tuple: vec![rows(slack)],
            table,
        });
        // Zero-row branch: z*(Ml + Mh) = 0.
        b.identity(
            "zero",
            groups,
            vec![
                term(1, vec![rows(zero), rows(maximum_low)]),
                term(1, vec![rows(zero), rows(maximum_high)]),
            ],
        );

        // Virtual division remainder limbs (RFC-0028 §1.2, A1).
        let f = lane(remainder_carry);
        let remainder_low = b.virtual_ranged(
            "remainder/low",
            Def::Pointwise {
                terms: vec![
                    term(2, vec![al]),
                    term(1, vec![sl.clone()]),
                    term(1, vec![z.clone()]),
                    term(-2, vec![q.clone(), sl.clone()]),
                    term(-2, vec![q.clone(), z.clone()]),
                    term(-LIMB, vec![f.clone()]),
                ],
            },
            u(LIMB_BITS),
            n,
        );
        let remainder_high = b.virtual_ranged(
            "remainder/high",
            Def::Pointwise {
                terms: vec![
                    term(2, vec![ah]),
                    term(1, vec![sh.clone()]),
                    term(-2, vec![q.clone(), sh.clone()]),
                    term(1, vec![f]),
                ],
            },
            u(25 - LIMB_BITS),
            n,
        );
        let (rl, rh) = (lane(remainder_low), lane(remainder_high));

        // Virtual spare limbs: pl = 2*sl + 2*z - 1 - rl - 2^14*g, ph = 2*sh - rh + g.
        let g = lane(spare_carry);
        let spare_low = b.virtual_ranged(
            "spare/low",
            Def::Linear {
                constant: -1,
                terms: vec![(2, sl), (2, z), (-1, rl), (-LIMB, g.clone())],
            },
            u(LIMB_BITS),
            n,
        );
        let spare_high = b.virtual_ranged(
            "spare/high",
            Def::Linear {
                constant: 0,
                terms: vec![(2, sh), (-1, rh), (1, g)],
            },
            u(25 - LIMB_BITS),
            n,
        );

        // Virtual codes c = (1 - 2*sigma)*q ∈ [-128, 128) (range tightens magnitude to 128).
        let codes = b.virtual_ranged(
            "codes",
            Def::Pointwise {
                terms: vec![term(1, vec![q.clone()]), term(-2, vec![sg, q])],
            },
            Width::signed(8),
            n,
        );

        self.columns = Some(ConversionColumns {
            sign,
            borrow,
            magnitude_low,
            magnitude_high,
            gap_low,
            gap_high,
            gap_borrow,
            hit,
            quotient,
            codes,
            remainder_low,
            remainder_high,
            remainder_carry,
            spare_low,
            spare_high,
            spare_carry,
            maximum_low,
            maximum_high,
            scale_low,
            scale_high,
            scale,
            slack,
            ceiling_carry,
            zero,
        });
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
            if !matches!(relation.columns[id.0 as usize].kind, Kind::Virtual(_)) {
                values.set(relation, id, column)?;
            }
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
    fn logs(&self) -> (u8, u8, u8) {
        let (t, d) = (log2_ceil(self.tokens), log2_ceil(self.hidden));
        let lg = match self.policy {
            Policy::Grouped(g) => g.trailing_zeros() as u8,
            _ => d,
        };
        (t, d, lg)
    }

    pub(crate) fn plan(&self, capture: &[i64]) -> Plan {
        let (t, d, lg) = self.logs();
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
        let width = 1usize << lg;
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
                let divisor = scale[x >> lg] + zero[x >> lg];
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
        let (_, _, lg) = self.logs();
        let split = |v: i64| (v.rem_euclid(LIMB), v.div_euclid(LIMB));
        let mut lanes = [(); 16].map(|_| Vec::with_capacity(plan.product.len()));
        for x in 0..plan.product.len() {
            let row = x >> lg;
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

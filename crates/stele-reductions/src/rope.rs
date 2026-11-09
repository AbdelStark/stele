//! RoPE module of the development-profile relation (RFC-0026 §5 row 5, task E16-06).
//!
//! Integer definition (RFC-0025 §2.4, RFC-0004 A7): for rotary pair `j` of head `h` at
//! position `t`, with `(c, s) = Rotation::coefficient(t, j)` and inputs `(x, y)`,
//! `x' = R((x·c − y·s)/2^14)` and `y' = R((x·s + y·c)/2^14)`, where `R` rounds half away
//! from zero. Layout 0 pairs channels `(2j, 2j+1)`, layout 1 pairs `(j, j + r/2)`.
//! Channels `r..dh` pass through unchanged.
//!
//! Columns, all on the output layout `(t, head, i)` with each dimension padded to a
//! power of two (row index in the high bits):
//! - `partner`: `P = x·Perm`, the paired input channel (0 on unrotated channels), by a
//!   matmul with a public permutation, so any layout and rotary width is expressible.
//! - the numerator `N = x·a + P·b`, with public coefficients `a`, `b`, is never committed.
//!   `N = H·2^14 + L` with `L` in `[0, 2^14)` and `H = out − β`; `ν = [H < 0]` by the
//!   two's-complement column `tc = H + 2^16·ν` in `[0, 2^16)`; `β = [L ≥ 2^13 + ν]` by
//!   the RFC-0026 §5 division pattern `tie = (2β−1)(L − 2^13 − ν) − (1−β) ≥ 0`.
//!   Then `out = H + β = R(N/2^14)` (ties away from zero: `ν` moves the tie at `L = 2^13`).
//! - Coefficients are split as `hi + one` with `hi` in signed 15 and `one` in `{0,1}`,
//!   because `16384` does not fit signed 15 and a signed 16 coefficient would break the
//!   §3.6 bound: `3·2^29 + 2^16 + 2^15 < p`.
//!
//! Padding entries have zero coefficients, so `N = 0` pins `out = 0` (RFC-0026 §2.1).
//! The output-uniqueness lemma is in `agents/reviews/e16-06-rope.md`.

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use stele_cqis::model::{Error as ModelError, Rotation};
use stele_ir::relation::{
    ColumnId, Identity, Kind, Matmul, Module, Range, Ref, Relation, Term, Values, Violation, Width,
};

/// Q14 rotary divisor `2^14` (RFC-0004 A7).
const DIVISOR: i64 = 1 << 14;
const HALF: i64 = DIVISOR / 2;
/// Largest coefficient part held in signed 15.
const HI_MAX: i64 = (1 << 14) - 1;

fn log2_ceil(n: usize) -> u8 {
    n.next_power_of_two().trailing_zeros() as u8
}

/// Column ids allocated by [`Rope::declare`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RopeColumns {
    /// Rotated output `Q'` or `K'` (int16), consumed by E16-07.
    pub output: ColumnId,
    pub partner: ColumnId,
    pub low: ColumnId,
    pub half: ColumnId,
    pub negative: ColumnId,
    pub twos: ColumnId,
    pub tie: ColumnId,
}

/// RoPE of one projection output (Q with `heads`, or K with `groups`) of one layer.
#[derive(Clone, Debug)]
pub struct Rope {
    layer: usize,
    name: String,
    input: ColumnId,
    tokens: usize,
    heads: usize,
    head_width: usize,
    /// Per output entry `(self coefficient, partner channel and coefficient)`; `None` is
    /// passthrough. Indexed `[t][i]` for `i < head_width`, shared by heads.
    coefficients: Vec<(i64, Option<(usize, i64)>)>,
    columns: Option<RopeColumns>,
}

impl Rope {
    /// Plan data for one tensor: `role` is `"q"` or `"k"`, `input` the E16-05 projection
    /// output column of shape `(tokens, heads, head_width)` (int16), positions `0..tokens`.
    /// `rotation` is the block's rotation; `None` is complete passthrough.
    pub fn new(
        layer: usize,
        role: &str,
        input: ColumnId,
        tokens: usize,
        heads: u16,
        head_width: u16,
        rotation: Option<&Rotation>,
    ) -> Result<Self, ModelError> {
        let head_width = usize::from(head_width);
        let mut coefficients = vec![(DIVISOR, None); tokens * head_width];
        if let Some(r) = rotation {
            let half = usize::from(r.width() / 2);
            if usize::from(r.width()) > head_width {
                return Err(ModelError::Rotation);
            }
            for t in 0..tokens {
                let position = u32::try_from(t).map_err(|_| ModelError::Rotation)?;
                for j in 0..half {
                    let (c, s) = r.coefficient(position, j as u16)?;
                    let (c, s) = (i64::from(c), i64::from(s));
                    let (left, right) = if r.layout() == 0 {
                        (2 * j, 2 * j + 1)
                    } else {
                        (j, j + half)
                    };
                    coefficients[t * head_width + left] = (c, Some((right, -s)));
                    coefficients[t * head_width + right] = (c, Some((left, s)));
                }
            }
        }
        Ok(Self {
            layer,
            name: format!("L{layer}/rope/{role}"),
            input,
            tokens,
            heads: usize::from(heads),
            head_width,
            coefficients,
            columns: None,
        })
    }

    /// Column ids, once declared.
    pub fn columns(&self) -> Option<RopeColumns> {
        self.columns
    }

    /// Bits of `(channel, head, row)`.
    fn bits(&self) -> (u8, u8, u8) {
        (
            log2_ceil(self.head_width),
            log2_ceil(self.heads),
            log2_ceil(self.tokens),
        )
    }

    fn log_len(&self) -> u8 {
        let (d, h, t) = self.bits();
        d + h + t
    }

    /// `(t, head, i)` of a padded index, `None` on padding.
    fn entry(&self, index: usize) -> Option<(usize, usize, usize)> {
        let (d, h, _) = self.bits();
        let (i, head, t) = (
            index & ((1 << d) - 1),
            (index >> d) & ((1 << h) - 1),
            index >> (d + h),
        );
        (i < self.head_width && head < self.heads && t < self.tokens).then_some((t, head, i))
    }

    /// Unpadded input offset of `(t, head, i)` in the executor's row-major layout.
    fn offset(&self, t: usize, head: usize, i: usize) -> usize {
        (t * self.heads + head) * self.head_width + i
    }
}

/// Split `v` in `[-2^14, 2^14]` into signed-15 and `{0,1}` parts.
fn split(v: i64) -> (i64, i64) {
    let hi = v.min(HI_MAX);
    (hi, v - hi)
}

/// `[out, L, β, ν, tc, tie]` of numerator `N`: `out = R(N/2^14)` (no range check).
pub(crate) fn solve(numerator: i64) -> [i64; 6] {
    let high = numerator.div_euclid(DIVISOR);
    let low = numerator.rem_euclid(DIVISOR);
    let negative = i64::from(high < 0);
    let half = i64::from(low >= HALF + negative);
    [
        high + half,
        low,
        half,
        negative,
        high + (negative << 16),
        (2 * half - 1) * (low - HALF - negative) - (1 - half),
    ]
}

fn term(coeff: i64, factors: &[&Ref]) -> Term {
    Term {
        coeff,
        factors: factors.iter().map(|&f| f.clone()).collect(),
    }
}

impl Module for Rope {
    /// The unpadded projection output, row-major `(tokens, heads, head_width)`.
    type Capture = [i16];

    fn declare(&mut self, relation: &mut Relation) {
        let n = self.log_len();
        let (d, _, _) = self.bits();
        // Q and K of one layer share the group when their lengths agree (RFC-0026 §2.3).
        let group_name = format!("L{}/rope/{n}", self.layer);
        let group = match relation.groups.iter().position(|g| g.name == group_name) {
            Some(g) => stele_ir::relation::GroupId(g as u32),
            None => relation.add_group(&group_name, n),
        };
        let name = self.name.clone();
        let witness = |relation: &mut Relation, label: &str, width: Width| {
            let id =
                relation.add_column(&format!("{name}/{label}"), Kind::Witness(group), width, n);
            relation.ranges.push(Range {
                name: format!("{name}/{label}"),
                column: id,
                width,
            });
            id
        };
        let columns = RopeColumns {
            output: witness(relation, "out", Width::signed(16)),
            partner: witness(relation, "partner", Width::signed(16)),
            low: witness(relation, "low", Width::unsigned(14)),
            half: witness(relation, "half", Width::unsigned(1)),
            negative: witness(relation, "negative", Width::unsigned(1)),
            twos: witness(relation, "twos", Width::unsigned(16)),
            tie: witness(relation, "tie", Width::unsigned(14)),
        };

        // Public permutation over (i, i'): Perm[i][i'] = 1 iff i' is i's rotary partner.
        let mut perm = vec![0; 1 << (2 * d)];
        for (i, (_, partner)) in self.coefficients[..self.head_width].iter().enumerate() {
            if let Some((p, _)) = partner {
                perm[(i << d) | p] = 1;
            }
        }
        let perm = relation.add_column(
            &format!("{name}/perm"),
            Kind::Public(perm),
            Width::unsigned(1),
            2 * d,
        );
        let mut public = [(); 4].map(|_| vec![0; 1 << n]);
        for (index, (t, _, i)) in (0..1usize << n).filter_map(|x| self.entry(x).map(|e| (x, e))) {
            let (own, partner) = self.coefficients[t * self.head_width + i];
            let (own_hi, own_one) = split(own);
            let (partner_hi, partner_one) = split(partner.map_or(0, |p| p.1));
            for (column, v) in public
                .iter_mut()
                .zip([own_hi, own_one, partner_hi, partner_one])
            {
                column[index] = v;
            }
        }
        let [own_hi, own_one, partner_hi, partner_one] = public;
        let mut add = |label: &str, values: Vec<i64>, width: Width| {
            relation.add_column(&format!("{name}/{label}"), Kind::Public(values), width, n)
        };
        let own_hi = add("own_hi", own_hi, Width::signed(15));
        let own_one = add("own_one", own_one, Width::unsigned(1));
        let partner_hi = add("partner_hi", partner_hi, Width::signed(15));
        let partner_one = add("partner_one", partner_one, Width::unsigned(1));

        let at = |c: ColumnId| Ref::identity(c, n);
        // P(t, head, i) = Σ_{i'} x(t, head, i')·Perm(i, i'); i' on domain bits n..n+d.
        let input_vars: Vec<u8> = (n..n + d).chain(d..n).collect();
        let perm_vars: Vec<u8> = (n..n + d).chain(0..d).collect();
        relation.matmuls.push(Matmul {
            name: format!("{name}/gather"),
            free: n,
            summed: d,
            out: at(columns.partner),
            lhs: Ref {
                column: self.input,
                vars: input_vars,
            },
            rhs: Ref {
                column: perm,
                vars: perm_vars,
            },
        });
        let (x, p, out, low, half, neg, twos, tie) = (
            at(self.input),
            at(columns.partner),
            at(columns.output),
            at(columns.low),
            at(columns.half),
            at(columns.negative),
            at(columns.twos),
            at(columns.tie),
        );
        // N = (out − β)·2^14 + L.
        relation.identities.push(Identity {
            name: format!("{name}/numerator"),
            vars: n,
            terms: vec![
                term(1, &[&x, &at(own_hi)]),
                term(1, &[&x, &at(own_one)]),
                term(1, &[&p, &at(partner_hi)]),
                term(1, &[&p, &at(partner_one)]),
                term(-DIVISOR, &[&out]),
                term(DIVISOR, &[&half]),
                term(-1, &[&low]),
            ],
        });
        // tie = (2β−1)(L − 2^13 − ν) − (1−β), expanded.
        relation.identities.push(Identity {
            name: format!("{name}/rounding"),
            vars: n,
            terms: vec![
                term(1, &[&tie]),
                term(-2, &[&half, &low]),
                term(2 * HALF - 1, &[&half]),
                term(2, &[&half, &neg]),
                term(1, &[&low]),
                term(-1, &[&neg]),
                term(1 - HALF, &[]),
            ],
        });
        // tc = (out − β) + 2^16·ν.
        relation.identities.push(Identity {
            name: format!("{name}/sign"),
            vars: n,
            terms: vec![
                term(1, &[&twos]),
                term(-1, &[&out]),
                term(1, &[&half]),
                term(-(1 << 16), &[&neg]),
            ],
        });
        self.columns = Some(columns);
    }

    fn assign(
        &self,
        relation: &Relation,
        capture: &[i16],
        values: &mut Values,
    ) -> Result<(), Violation> {
        let columns = self.columns.expect("Rope::assign before declare");
        if capture.len() != self.tokens * self.heads * self.head_width {
            return Err(Violation::Missing(self.input));
        }
        let len = 1usize << self.log_len();
        let mut cols = [(); 7].map(|_| vec![0i64; len]);
        for index in 0..len {
            let (own, partner, x) = match self.entry(index) {
                Some((t, head, i)) => {
                    let (own, partner) = self.coefficients[t * self.head_width + i];
                    let x = i64::from(capture[self.offset(t, head, i)]);
                    let partner = partner.map(|(channel, coeff)| {
                        (i64::from(capture[self.offset(t, head, channel)]), coeff)
                    });
                    (own, partner, x)
                }
                // Padding: zero coefficients pin the output; the upstream pins x to 0.
                None => (0, None, 0),
            };
            let (partner_value, partner_coeff) = partner.unwrap_or((0, 0));
            let [out, low, half, negative, twos, tie] =
                solve(x * own + partner_value * partner_coeff);
            if !Width::signed(16).contains(out) {
                return Err(Violation::Range {
                    relation: format!("{}/out", self.name),
                    index,
                });
            }
            let row = [out, partner_value, low, half, negative, twos, tie];
            for (column, v) in cols.iter_mut().zip(row) {
                column[index] = v;
            }
        }
        let ids = [
            columns.output,
            columns.partner,
            columns.low,
            columns.half,
            columns.negative,
            columns.twos,
            columns.tie,
        ];
        for (id, column) in ids.into_iter().zip(cols) {
            values.set(relation, id, column)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;

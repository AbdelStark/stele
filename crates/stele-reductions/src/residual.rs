//! Residual add of the development-profile relation (RFC-0026 §5 row 11, task E16-09).
//!
//! Integer definition (RFC-0025 §2.2): for int16 inputs `X`, `Y` in units `2^-fx`,
//! `2^-fy` and output units `2^-fo` (all fractions in `[0, 30]`), with
//! `c = max(fx, fy, fo)`, `out = R((X·2^(c−fx) + Y·2^(c−fy))/2^(c−fo))`, rounded half
//! away from zero, int16 (version-1 stream; RFC-0004 A14 wide streams are outside
//! RFC-0026 §1.3).
//!
//! Since one of the three shifts is 0, the numerator is `N = F + G·2^e`, where `F`
//! (`first`) is the input with the smaller shift and `G` (`second`) the other one, and
//! `out = 2^m·R(N/2^k)` with `k = c − fo` and `m` the common shift (`m > 0` only when
//! `k = 0`). `N` reaches 46 bits, so it is never held whole (RFC-0026 §3.5a limb rule):
//!
//! - `k = 0`: `S = F + G·2^e` and `out = 2^m·S` (`S` is `out` when `m = 0`).
//! - `k > 0`: with `s = max(0, k − 14)` and `k2 = k − s`, stage 1 takes
//!   `T = floor(N/2^s)` and the sticky bit `st = [N mod 2^s ≠ 0]` from Euclidean splits
//!   of `F` (at `2^s`) and, when `e < s`, of `G` (at `2^(s−e)`), with a carry `κ`. Stage
//!   2 is the RFC-0026 §5 division pattern with divisor `D2 = 2^k2`:
//!   `T = (out − β)·D2 + L`, `L ∈ [0, D2)`; `ν = [out − β < 0]` by
//!   `tc = out − β + 2^16·ν ∈ [0, 2^16)`; `β = [2L + st ≥ D2 + ν]` by
//!   `tie = (2β−1)(2L + st − D2 − ν) − (1−β) ≥ 0`. This is `R(N/2^k)` because
//!   `N mod 2^k = L·2^s + (N mod 2^s)` (lemma in the review notes).
//! - A shifted input that would break the §3.6 bound is read through a **narrow copy**:
//!   a witness equal to it with a smaller declared width, which every non-overflowing
//!   execution satisfies (`|G·2^e'| < 2^30`, or `< 2^16` when `k = 0`).
//!
//! Padded lanes and token rows of the output are pinned to 0 by a public mask (RFC-0026 §2.1). The
//! output-uniqueness lemma is in `agents/reviews/e16-09-residual-argmax.md`.

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use stele_ir::relation::{
    ColumnId, GroupId, Identity, Invalid, Kind, Module, Range, Ref, Relation, Term, Values,
    Violation, Width,
};

fn log2_ceil(n: usize) -> u8 {
    n.next_power_of_two().trailing_zeros() as u8
}

fn term(coeff: i64, factors: &[&Ref]) -> Term {
    Term {
        coeff,
        factors: factors.iter().map(|&f| f.clone()).collect(),
    }
}

/// Stage-2 rounding columns (`k > 0`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RoundingColumns {
    pub low: ColumnId,
    pub half: ColumnId,
    pub negative: ColumnId,
    pub twos: ColumnId,
    pub tie: ColumnId,
}

/// Column ids allocated by [`Residual::declare`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResidualColumns {
    /// `R_mid` or `R_{ℓ+1}` (int16), consumed by E16-04 and the next residual.
    pub output: ColumnId,
    pub rounding: Option<RoundingColumns>,
    /// Every other witness column, by label (`scaled`, `narrow`, `first_high`, …).
    pub auxiliary: Vec<(&'static str, ColumnId)>,
}

impl ResidualColumns {
    pub fn auxiliary(&self, label: &str) -> Option<ColumnId> {
        self.auxiliary
            .iter()
            .find_map(|&(l, id)| (l == label).then_some(id))
    }
}

/// One residual add of the executor (E16-03 `Block::mid` or `Block::residual`):
/// the two inputs and the int16 quotient, row-major `(t, lane)` and unpadded.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ResidualCapture {
    pub left: Vec<i64>,
    pub right: Vec<i64>,
    pub output: Vec<i64>,
}

/// Static shape of one add, from the three fractions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Shape {
    /// `F` is the right input (`fy` carries the smaller shift).
    swap: bool,
    e: u8,
    m: u8,
    k: u8,
    s: u8,
}

impl Shape {
    fn new(fx: u8, fy: u8, fo: u8) -> Self {
        let c = fx.max(fy).max(fo);
        let (a, b, k) = (c - fx, c - fy, c - fo);
        Self {
            swap: b < a,
            e: a.abs_diff(b),
            m: a.min(b),
            k,
            s: k.saturating_sub(14),
        }
    }

    fn k2(self) -> u8 {
        self.k - self.s
    }

    /// Shift of `G` in the stage-2 (or `k = 0`) identity when it is not split.
    fn coarse(self) -> Option<u8> {
        (self.e >= self.s).then(|| self.e - self.s)
    }

    /// Declared width of `G` in that identity: `|G·2^e'| < 2^30` (`2^16` when `k = 0`).
    fn narrow(self) -> Option<u8> {
        let shift = self.coarse()?;
        let limit: u8 = if self.k == 0 { 17 } else { 31 };
        let bits = limit.saturating_sub(shift).clamp(1, 16);
        (bits < 16).then_some(bits)
    }
}

/// One residual add `out = R((X·2^(c−fx) + Y·2^(c−fy))/2^(c−fo))` of one layer.
#[derive(Clone, Debug)]
pub struct Residual {
    layer: usize,
    name: String,
    inputs: [ColumnId; 2],
    tokens: usize,
    width: usize,
    shape: Shape,
    columns: Option<ResidualColumns>,
}

impl Residual {
    /// Plan data for one add: `role` is `"mid"` (incoming cut + O) or `"out"`
    /// (`R_mid` + down). `left`/`right` are int16 columns of shape `(tokens, width)`
    /// in fractions `fx`/`fy`; the output fraction is `fo`. Fractions above 30
    /// (RFC-0025 §2.2) or an empty shape are rejected.
    pub fn new(
        layer: usize,
        role: &str,
        (left, fx): (ColumnId, u8),
        (right, fy): (ColumnId, u8),
        fo: u8,
        tokens: usize,
        width: usize,
    ) -> Result<Self, Invalid> {
        let name = format!("L{layer}/residual/{role}");
        if fx.max(fy).max(fo) > 30 || tokens == 0 || width == 0 {
            return Err(Invalid::Shape { relation: name });
        }
        Ok(Self {
            layer,
            name,
            inputs: [left, right],
            tokens,
            width,
            shape: Shape::new(fx, fy, fo),
            columns: None,
        })
    }

    /// Column ids, once declared.
    pub fn columns(&self) -> Option<&ResidualColumns> {
        self.columns.as_ref()
    }

    fn lane_bits(&self) -> u8 {
        log2_ceil(self.width)
    }

    fn log_len(&self) -> u8 {
        self.lane_bits() + log2_ceil(self.tokens)
    }

    /// `(t, lane)` of a padded index, `None` on padding.
    fn entry(&self, index: usize) -> Option<(usize, usize)> {
        let bits = self.lane_bits();
        let (lane, t) = (index & ((1 << bits) - 1), index >> bits);
        (lane < self.width && t < self.tokens).then_some((t, lane))
    }

    /// `(F, G)` input columns.
    fn ordered(&self) -> (ColumnId, ColumnId) {
        let [x, y] = self.inputs;
        if self.shape.swap {
            (y, x)
        } else {
            (x, y)
        }
    }

    fn group(&self, relation: &mut Relation) -> GroupId {
        // Both adds of one layer share a group (RFC-0026 §2.3).
        let n = self.log_len();
        let name = format!("L{}/residual/{n}", self.layer);
        match relation.groups.iter().position(|g| g.name == name) {
            Some(g) => GroupId(g as u32),
            None => relation.add_group(&name, n),
        }
    }

    /// Every witness value of one entry, in [`Self::labels`] order, from `F`, `G` and
    /// the claimed output. Out-of-width values are left for the checker to reject.
    fn solve(&self, f: i128, g: i128, out: i128) -> Vec<i128> {
        let Shape { e, m, k, s, .. } = self.shape;
        let mut row = vec![out];
        if k == 0 {
            if m > 0 {
                row.push(f + (g << e));
            }
            if self.shape.narrow().is_some() {
                row.push(g);
            }
            return row;
        }
        let (mut t, mut st) = (f + (g << e), 0);
        if s > 0 {
            let (high, low) = (f.div_euclid(1 << s), f.rem_euclid(1 << s));
            row.extend([high, low]);
            let rest = if e < s {
                let j = s - e;
                let (gh, gl) = (g.div_euclid(1 << j), g.rem_euclid(1 << j));
                let sum = low + (gl << e);
                let (carry, rest) = (sum >> s, sum & ((1 << s) - 1));
                row.extend([gh, gl, carry, rest]);
                t = high + gh + carry;
                rest
            } else {
                t = high + (g << (e - s));
                low
            };
            st = i128::from(rest != 0);
            row.extend([st, st * (rest - 1)]);
        }
        if self.shape.narrow().is_some() {
            row.push(g);
        }
        let d2 = 1i128 << self.shape.k2();
        let (high, low) = (t.div_euclid(d2), t.rem_euclid(d2));
        let negative = i128::from(high < 0);
        let half = out - high;
        let tie = (2 * half - 1) * (2 * low + st - d2 - negative) - (1 - half);
        row.extend([low, half, negative, high + (negative << 16), tie]);
        row
    }

    /// Witness labels and widths in [`Self::solve`] order (`out` first).
    fn labels(&self) -> Vec<(&'static str, Width)> {
        let Shape { e, m, k, s, .. } = self.shape;
        let mut labels = vec![("out", Width::signed(16))];
        let narrow = self
            .shape
            .narrow()
            .map(|bits| ("narrow", Width::signed(bits)));
        if k == 0 {
            if m > 0 {
                labels.push(("scaled", Width::signed(16u8.saturating_sub(m).max(1))));
            }
            labels.extend(narrow);
            return labels;
        }
        if s > 0 {
            labels.extend([
                ("first_high", Width::signed(16u8.saturating_sub(s).max(1))),
                ("first_low", Width::unsigned(s)),
            ]);
            if e < s {
                let j = s - e;
                labels.extend([
                    ("second_high", Width::signed(16u8.saturating_sub(j).max(1))),
                    ("second_low", Width::unsigned(j)),
                    ("carry", Width::unsigned(1)),
                    ("rest", Width::unsigned(s)),
                ]);
            }
            labels.extend([("sticky", Width::unsigned(1)), ("gap", Width::unsigned(s))]);
        }
        labels.extend(narrow);
        let k2 = self.shape.k2();
        labels.extend([
            ("low", Width::unsigned(k2)),
            ("half", Width::unsigned(1)),
            ("negative", Width::unsigned(1)),
            ("twos", Width::unsigned(16)),
            ("tie", Width::unsigned(k2 + 1)),
        ]);
        labels
    }
}

impl Module for Residual {
    type Capture = ResidualCapture;

    fn declare(&mut self, relation: &mut Relation) {
        let n = self.log_len();
        let group = self.group(relation);
        let name = self.name.clone();
        let mut ids = Vec::new();
        for (label, width) in self.labels() {
            let column = format!("{name}/{label}");
            let id = relation.add_column(&column, Kind::Witness(group), width, n);
            relation.ranges.push(Range {
                name: column,
                column: id,
                width,
            });
            ids.push((label, id));
        }
        let col = |label: &str| ids.iter().find_map(|&(l, id)| (l == label).then_some(id));
        let at = |c: ColumnId| Ref::identity(c, n);
        let get = |label: &str| col(label).map(at);
        let mut identity = |label: &str, terms: Vec<Term>| {
            relation.identities.push(Identity {
                name: format!("{name}/{label}"),
                vars: n,
                terms,
            })
        };
        let Shape { e, m, k, s, .. } = self.shape;
        let (first, second) = self.ordered();
        let (first, out) = (at(first), at(ids[0].1));
        // G in the unsplit identity: its narrow copy (= G) when one is declared.
        let coarse = match get("narrow") {
            Some(narrow) => {
                identity("copy", vec![term(1, &[&narrow]), term(-1, &[&at(second)])]);
                narrow
            }
            None => at(second),
        };
        let second = at(second);
        if k == 0 {
            // S = F + G·2^e, and out = 2^m·S.
            let scaled = get("scaled").unwrap_or_else(|| out.clone());
            identity(
                "numerator",
                vec![
                    term(1, &[&scaled]),
                    term(-1, &[&first]),
                    term(-(1 << e), &[&coarse]),
                ],
            );
            if m > 0 {
                identity("scale", vec![term(1, &[&out]), term(-(1 << m), &[&scaled])]);
            }
        } else {
            // Stage 1: T = high(F) + (G·2^(e−s) or high(G) + κ), st = [N mod 2^s ≠ 0].
            let mut stage2 = Vec::new();
            let mut sticky = None;
            if s > 0 {
                let (fh, fl) = (
                    get("first_high").expect("split"),
                    get("first_low").expect("split"),
                );
                identity(
                    "first",
                    vec![
                        term(1, &[&first]),
                        term(-(1 << s), &[&fh]),
                        term(-1, &[&fl]),
                    ],
                );
                stage2.push(term(1, &[&fh]));
                let rest = match (get("second_high"), get("second_low")) {
                    (Some(gh), Some(gl)) => {
                        let (carry, rest) =
                            (get("carry").expect("carry"), get("rest").expect("rest"));
                        identity(
                            "second",
                            vec![
                                term(1, &[&second]),
                                term(-(1 << (s - e)), &[&gh]),
                                term(-1, &[&gl]),
                            ],
                        );
                        identity(
                            "carry_sum",
                            vec![
                                term(1, &[&fl]),
                                term(1 << e, &[&gl]),
                                term(-(1 << s), &[&carry]),
                                term(-1, &[&rest]),
                            ],
                        );
                        stage2.extend([term(1, &[&gh]), term(1, &[&carry])]);
                        rest
                    }
                    _ => {
                        stage2.push(term(1 << (e - s), &[&coarse]));
                        fl
                    }
                };
                let (st, gap) = (get("sticky").expect("sticky"), get("gap").expect("gap"));
                // st = [rest ≠ 0]: (1 − st)·rest = 0 and gap = st·(rest − 1) ≥ 0.
                identity(
                    "sticky_zero",
                    vec![term(1, &[&rest]), term(-1, &[&st, &rest])],
                );
                identity(
                    "sticky_gap",
                    vec![term(1, &[&gap]), term(-1, &[&st, &rest]), term(1, &[&st])],
                );
                sticky = Some(st);
            } else {
                stage2.extend([term(1, &[&first]), term(1 << e, &[&coarse])]);
            }
            // Stage 2: T − D2·(out − β) − L = 0.
            let d2 = 1i64 << self.shape.k2();
            let (low, half, neg) = (
                get("low").expect("low"),
                get("half").expect("half"),
                get("negative").expect("negative"),
            );
            stage2.extend([term(-d2, &[&out]), term(d2, &[&half]), term(-1, &[&low])]);
            identity("numerator", stage2);
            // tie = (2β−1)(2L + st − D2 − ν) − (1−β), expanded.
            let mut tie = vec![
                term(1, &[&get("tie").expect("tie")]),
                term(-4, &[&half, &low]),
                term(2 * d2 - 1, &[&half]),
                term(2, &[&half, &neg]),
                term(2, &[&low]),
                term(-1, &[&neg]),
                term(1 - d2, &[]),
            ];
            if let Some(st) = &sticky {
                tie.extend([term(-2, &[&half, st]), term(1, &[st])]);
            }
            identity("round", tie);
            // tc = (out − β) + 2^16·ν.
            identity(
                "sign",
                vec![
                    term(1, &[&get("twos").expect("twos")]),
                    term(-1, &[&out]),
                    term(1, &[&half]),
                    term(-(1 << 16), &[&neg]),
                ],
            );
        }
        // RFC-0026 §2.1: padded lanes and padded token rows of the output are 0.
        if self.tokens * self.width != 1 << self.log_len() {
            let mask = (0..1usize << n)
                .map(|i| i64::from(self.entry(i).is_none()))
                .collect();
            let mask = relation.add_column(
                &format!("{name}/pad"),
                Kind::Public(mask),
                Width::unsigned(1),
                n,
            );
            relation.identities.push(Identity {
                name: format!("{name}/pad"),
                vars: n,
                terms: vec![term(1, &[&at(mask), &out])],
            });
        }
        let rounding = (k > 0).then(|| RoundingColumns {
            low: col("low").expect("low"),
            half: col("half").expect("half"),
            negative: col("negative").expect("negative"),
            twos: col("twos").expect("twos"),
            tie: col("tie").expect("tie"),
        });
        self.columns = Some(ResidualColumns {
            output: ids[0].1,
            rounding,
            auxiliary: ids[1..]
                .iter()
                .copied()
                .filter(|(l, _)| !["low", "half", "negative", "twos", "tie"].contains(l))
                .collect(),
        });
    }

    fn assign(
        &self,
        relation: &Relation,
        capture: &ResidualCapture,
        values: &mut Values,
    ) -> Result<(), Violation> {
        let columns = self
            .columns
            .as_ref()
            .expect("Residual::assign before declare");
        let count = self.tokens * self.width;
        let ResidualCapture {
            left,
            right,
            output,
        } = capture;
        if [left.len(), right.len(), output.len()] != [count; 3] {
            return Err(Violation::Missing(columns.output));
        }
        let (first, second) = if self.shape.swap {
            (right, left)
        } else {
            (left, right)
        };
        let labels = self.labels();
        let len = 1usize << self.log_len();
        let mut cols = vec![vec![0i64; len]; labels.len()];
        for index in 0..len {
            let (f, g, out) = self.entry(index).map_or((0, 0, 0), |(t, lane)| {
                let o = t * self.width + lane;
                (first[o], second[o], output[o])
            });
            let row = self.solve(f.into(), g.into(), out.into());
            for (column, v) in cols.iter_mut().zip(row) {
                column[index] = i64::try_from(v).unwrap_or(i64::MAX);
            }
        }
        let ids = core::iter::once(columns.output).chain(columns.auxiliary.iter().map(|a| a.1));
        let rounding = columns
            .rounding
            .map(|r| [r.low, r.half, r.negative, r.twos, r.tie]);
        for (id, column) in ids.chain(rounding.into_iter().flatten()).zip(cols) {
            values.set(relation, id, column)?;
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests;

//! Row conversion of int16 rows to int8 codes (RFC-0026 §5 row 3 and its shared
//! patterns; RFC-0025 §2.2, flow §1; grouped rows RFC-0004 A15). The gated
//! conversion (RFC-0004 A8) is E16-08's; it produces the same [`RowOutput`].
//!
//! Per group of `g` lanes (`g = d` for a per-row policy) with scale `s`:
//! - sign/abs: `mask*x = a - 2*sigma*a`, so `a = |x|` on real lanes and `a = 0` on
//!   padding, which pins every padded code to 0;
//! - attained maximum (dynamic): `gap = M - a >= 0`, one-hot `h` with `sum h = 1`
//!   over the group (matmul row sum) and `h*gap = 0`, so `M = max a`;
//! - row-scale ceiling (dynamic): `slack = 127*s - M` in `[0,126]` (lookup);
//! - zero-row branch (dynamic): Boolean `z` with `z*M = 0` and divisor `D = s + z`,
//!   `D >= 1` by the range on `spare`. The pattern's `z*q = 0` is implied by the
//!   division and the half bit (lemma R, step 6), so it is not declared;
//! - round-half-away division: `a = q0*D + rho`, `spare = D - 1 - rho >= 0`,
//!   `half_gap = (2beta-1)(2rho-D) - (1-beta) >= 0`, `q = q0 + beta <= 127`;
//! - code `c = q - 2*sigma*q`.
//!
//! A static policy makes `s` a public column and `z = 0`. Output-uniqueness lemma R
//! and the mutation survey: `agents/reviews/e16-05-projections.md`.

use super::{bit_length, log2_ceil, r, term, Builder, Unsupported};
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use stele_ir::relation::{
    ColumnId, Invalid, Lookup, Matmul, Module, Relation, Table, Values, Violation, Width, MAX_VARS,
};

/// RFC-0025 §2.2 row policy for an int16 source row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Policy {
    /// One dynamic scale `ceil(max|x|/127)` per row.
    Dynamic,
    /// One configured scale in `1..=65535` for every row.
    Static(u32),
    /// RFC-0004 A15: one dynamic scale per group of `g` lanes.
    Grouped(u32),
}

/// Largest dynamic int16 scale, `ceil(32768/127)`.
const DYNAMIC_SCALE: u32 = 259;

/// What a projection reads from a converted row (RFC-0026 §5.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RowOutput {
    /// Codes, `T x d` row-major, signed 8.
    pub codes: ColumnId,
    /// Scales, `T x (d/g)` row-major (public for a static policy).
    pub scale: ColumnId,
    pub log_rows: u8,
    pub log_dimension: u8,
    /// Index bits of one scale group (`log_dimension` for a per-row policy).
    pub log_group: u8,
    /// Largest scale the policy admits.
    pub scale_bound: u32,
}

/// Executor intermediates of one row conversion over every real row
/// (`stele_cqis::row::Quantiser::convert_wide`, or the capture's `Quantised`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ConversionCapture {
    /// `[row][lane]` int16 source values.
    pub inputs: Vec<Vec<i64>>,
    /// `[row][lane]` int8 codes.
    pub codes: Vec<Vec<i64>>,
    /// `[row][group]` scales (one per row for policies 0/1).
    pub scales: Vec<Vec<u32>>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Columns {
    pub(crate) magnitude: ColumnId,
    pub(crate) sign: ColumnId,
    pub(crate) floor: ColumnId,
    pub(crate) remainder: ColumnId,
    pub(crate) spare: ColumnId,
    pub(crate) half: ColumnId,
    pub(crate) half_gap: ColumnId,
    pub(crate) quotient: ColumnId,
    pub(crate) codes: ColumnId,
    pub(crate) scale: ColumnId,
    /// Dynamic only: (zero, maximum, slack, gap, hit).
    pub(crate) dynamic: Option<(ColumnId, ColumnId, ColumnId, ColumnId, ColumnId)>,
}

/// Steps of the witness dataflow, in order. Each step solves its own defining
/// relation from earlier values. A mutation test lies at one step and recomputes
/// the later ones: the attacker's strongest completion of that lie.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Step {
    Sign,
    Magnitude,
    Maximum,
    Gap,
    Hit,
    Scale,
    Slack,
    Zero,
    Floor,
    Remainder,
    Spare,
    Half,
    HalfGap,
    Quotient,
    Code,
}

impl Step {
    pub(crate) const ALL: [Step; 15] = [
        Step::Sign,
        Step::Magnitude,
        Step::Maximum,
        Step::Gap,
        Step::Hit,
        Step::Scale,
        Step::Slack,
        Step::Zero,
        Step::Floor,
        Step::Remainder,
        Step::Spare,
        Step::Half,
        Step::HalfGap,
        Step::Quotient,
        Step::Code,
    ];
}

/// Values of every witness column; `input` is the read-only source.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct RowWitness {
    pub(crate) input: Vec<i64>,
    pub(crate) sign: Vec<i64>,
    pub(crate) magnitude: Vec<i64>,
    pub(crate) maximum: Vec<i64>,
    pub(crate) hit: Vec<i64>,
    pub(crate) gap: Vec<i64>,
    pub(crate) scale: Vec<i64>,
    pub(crate) slack: Vec<i64>,
    pub(crate) zero: Vec<i64>,
    pub(crate) floor: Vec<i64>,
    pub(crate) remainder: Vec<i64>,
    pub(crate) spare: Vec<i64>,
    pub(crate) half: Vec<i64>,
    pub(crate) half_gap: Vec<i64>,
    pub(crate) quotient: Vec<i64>,
    pub(crate) codes: Vec<i64>,
}

impl RowWitness {
    /// The column a step defines.
    pub(crate) fn column(&mut self, step: Step) -> &mut Vec<i64> {
        match step {
            Step::Sign => &mut self.sign,
            Step::Magnitude => &mut self.magnitude,
            Step::Maximum => &mut self.maximum,
            Step::Hit => &mut self.hit,
            Step::Gap => &mut self.gap,
            Step::Scale => &mut self.scale,
            Step::Slack => &mut self.slack,
            Step::Zero => &mut self.zero,
            Step::Floor => &mut self.floor,
            Step::Remainder => &mut self.remainder,
            Step::Spare => &mut self.spare,
            Step::Half => &mut self.half,
            Step::HalfGap => &mut self.half_gap,
            Step::Quotient => &mut self.quotient,
            Step::Code => &mut self.codes,
        }
    }
}

/// One row conversion of a `rows x dimension` int16 column (RFC-0026 §5 row 3).
#[derive(Clone, Debug)]
pub struct RowConversion {
    prefix: String,
    input: ColumnId,
    rows: usize,
    dimension: usize,
    policy: Policy,
    pub(crate) columns: Option<Columns>,
}

impl RowConversion {
    /// `input` is a signed-16 column of `2^(log rows + log dimension)` entries,
    /// row-major with padded rows and lanes. Rejects shapes and policies outside
    /// RFC-0025 §2.2 / RFC-0004 A15.
    pub fn new(
        prefix: &str,
        input: ColumnId,
        rows: usize,
        dimension: usize,
        policy: Policy,
    ) -> Result<Self, Unsupported> {
        if rows == 0 || !(1..=16384).contains(&dimension) {
            return Err(Unsupported::Shape);
        }
        let ok = match policy {
            Policy::Dynamic => true,
            Policy::Static(s) => (1..=65535).contains(&s),
            Policy::Grouped(g) => {
                g.is_power_of_two()
                    && (g as usize) < dimension
                    && dimension.is_multiple_of(g as usize)
            }
        };
        if !ok {
            return Err(Unsupported::Policy);
        }
        if log2_ceil(rows) + log2_ceil(dimension) > MAX_VARS {
            return Err(Unsupported::Domain);
        }
        Ok(Self {
            prefix: prefix.into(),
            input,
            rows,
            dimension,
            policy,
            columns: None,
        })
    }

    pub(crate) fn dynamic(&self) -> bool {
        !matches!(self.policy, Policy::Static(_))
    }

    pub(crate) fn logs(&self) -> (u8, u8, u8) {
        let (t, ld) = (log2_ceil(self.rows), log2_ceil(self.dimension));
        let lg = match self.policy {
            Policy::Grouped(g) => g.trailing_zeros() as u8,
            _ => ld,
        };
        (t, ld, lg)
    }

    fn scale_bound(&self) -> u32 {
        match self.policy {
            Policy::Static(s) => s,
            _ => DYNAMIC_SCALE,
        }
    }

    /// Output column ids; `None` before `declare`.
    pub fn output(&self) -> Option<RowOutput> {
        let (log_rows, log_dimension, log_group) = self.logs();
        self.columns.map(|c| RowOutput {
            codes: c.codes,
            scale: c.scale,
            log_rows,
            log_dimension,
            log_group,
            scale_bound: self.scale_bound(),
        })
    }

    pub(crate) fn real(&self, x: usize) -> bool {
        let (_, ld, _) = self.logs();
        (x >> ld) < self.rows && (x & ((1 << ld) - 1)) < self.dimension
    }

    fn codes_id(&self) -> ColumnId {
        self.columns.map_or(self.input, |c| c.codes)
    }

    /// The capture's source values over the padded lanes.
    pub(crate) fn source(&self, capture: &ConversionCapture) -> Result<RowWitness, Violation> {
        let (t, ld, lg) = self.logs();
        let groups = self.dimension.div_ceil(1 << lg);
        let ok = capture.inputs.len() == self.rows
            && capture.codes.len() == self.rows
            && capture.scales.len() == self.rows
            && capture.inputs.iter().all(|row| row.len() == self.dimension)
            && capture.codes.iter().all(|row| row.len() == self.dimension)
            && capture.scales.iter().all(|row| row.len() == groups);
        if !ok {
            return Err(Invalid::Column(self.codes_id()).into());
        }
        let input = (0..1usize << (t + ld))
            .map(|x| {
                if self.real(x) {
                    capture.inputs[x >> ld][x & ((1 << ld) - 1)]
                } else {
                    0
                }
            })
            .collect();
        Ok(RowWitness {
            input,
            ..RowWitness::default()
        })
    }

    /// Recompute every step from `from` on, each solving its own defining relation
    /// from the values before it; a `frozen` step keeps its value (the attacker's
    /// completion when that step's relation is deleted).
    pub(crate) fn complete(&self, w: &mut RowWitness, from: Step, frozen: Option<Step>) {
        let (t, ld, lg) = self.logs();
        let lanes = 1usize << (t + ld);
        let groups = 1usize << (t + ld - lg);
        let width = 1usize << lg;
        let at = |step: Step| from <= step && frozen != Some(step);
        for step in Step::ALL {
            let n = if matches!(step, Step::Maximum | Step::Scale | Step::Slack | Step::Zero) {
                groups
            } else {
                lanes
            };
            w.column(step).resize(n, 0);
        }
        let dynamic = self.dynamic();
        for x in 0..lanes {
            let source = if self.real(x) { w.input[x] } else { 0 };
            if at(Step::Sign) {
                w.sign[x] = i64::from(source < 0);
            }
            if at(Step::Magnitude) {
                // a = mask*x / (1 - 2*sigma) where that is exact, else |x|.
                let odd = 1 - 2 * w.sign[x];
                w.magnitude[x] = if source % odd == 0 {
                    source / odd
                } else {
                    source.abs()
                };
            }
        }
        for k in 0..groups {
            let span = k * width..(k + 1) * width;
            if at(Step::Maximum) && dynamic {
                w.maximum[k] = w.magnitude[span.clone()].iter().copied().max().unwrap_or(0);
            }
            if at(Step::Gap) && dynamic {
                for x in span.clone() {
                    w.gap[x] = w.maximum[k] - w.magnitude[x];
                }
            }
            if at(Step::Hit) && dynamic {
                // The first lane with gap 0 (h*gap = 0); none (h = 0) if M is not attained.
                let first = span.clone().find(|&x| w.gap[x] == 0);
                for x in span.clone() {
                    w.hit[x] = i64::from(Some(x) == first);
                }
            }
            if at(Step::Scale) {
                w.scale[k] = match self.policy {
                    Policy::Static(s) => i64::from(s),
                    _ => (w.maximum[k] + 126).div_euclid(127),
                };
            }
            if at(Step::Slack) && dynamic {
                w.slack[k] = 127 * w.scale[k] - w.maximum[k];
            }
            if at(Step::Zero) && dynamic {
                w.zero[k] = i64::from(w.maximum[k] == 0);
            }
        }
        for x in 0..lanes {
            let divisor = w.scale[x >> lg] + w.zero[x >> lg];
            if at(Step::Floor) {
                w.floor[x] = w.magnitude[x].checked_div(divisor).unwrap_or(0);
            }
            if at(Step::Remainder) {
                w.remainder[x] = w.magnitude[x] - w.floor[x] * divisor;
            }
            if at(Step::Spare) {
                w.spare[x] = divisor - 1 - w.remainder[x];
            }
            let rho = w.remainder[x];
            if at(Step::Half) {
                w.half[x] = i64::from(2 * rho >= divisor);
            }
            if at(Step::HalfGap) {
                let beta = w.half[x];
                w.half_gap[x] = (2 * beta - 1) * (2 * rho - divisor) - (1 - beta);
            }
            if at(Step::Quotient) {
                w.quotient[x] = w.floor[x] + w.half[x];
            }
            if at(Step::Code) {
                w.codes[x] = w.quotient[x] - 2 * w.sign[x] * w.quotient[x];
            }
        }
    }

    /// Write a (possibly forged) witness into this module's columns.
    pub(crate) fn write(
        &self,
        relation: &Relation,
        w: &RowWitness,
        values: &mut Values,
    ) -> Result<(), Violation> {
        let c = self.columns.ok_or(Violation::Missing(self.input))?;
        let mut columns = vec![
            (c.magnitude, &w.magnitude),
            (c.sign, &w.sign),
            (c.floor, &w.floor),
            (c.remainder, &w.remainder),
            (c.spare, &w.spare),
            (c.half, &w.half),
            (c.half_gap, &w.half_gap),
            (c.quotient, &w.quotient),
            (c.codes, &w.codes),
        ];
        if let Some((zero, maximum, slack, gap, hit)) = c.dynamic {
            columns.extend([
                (c.scale, &w.scale),
                (zero, &w.zero),
                (maximum, &w.maximum),
                (slack, &w.slack),
                (gap, &w.gap),
                (hit, &w.hit),
            ]);
        }
        for (id, column) in columns {
            values.set(relation, id, column.clone())?;
        }
        Ok(())
    }
}

impl Module for RowConversion {
    type Capture = ConversionCapture;

    fn declare(&mut self, relation: &mut Relation) {
        assert_eq!(
            relation.column(self.input).map(|c| c.width),
            Some(Width::signed(16)),
            "row conversion input must be a signed-16 column (RFC-0026 §5.1)"
        );
        let (t, ld, lg) = self.logs();
        let lanes = t + ld;
        let groups = lanes - lg;
        let mask = (0..1usize << lanes)
            .map(|x| i64::from(self.real(x)))
            .collect();
        let prefix = self.prefix.clone();
        let mut b = Builder::new(relation, &prefix);
        let mask = b.public("mask", mask, Width::unsigned(1), lanes);
        let one = b.public("one", vec![1], Width::unsigned(1), 0);
        let lane = |c: ColumnId| r(c, 0..lanes);
        let group = |c: ColumnId| r(c, lg..lanes);

        let magnitude = b.witness("magnitude", Width::unsigned(16), lanes);
        let sign = b.witness("sign", Width::unsigned(1), lanes);
        let floor = b.witness("floor", Width::unsigned(7), lanes);
        let remainder = b.witness("remainder", Width::unsigned(16), lanes);
        let spare = b.witness("spare", Width::unsigned(16), lanes);
        let half = b.witness("half", Width::unsigned(1), lanes);
        let half_gap = b.witness("half_gap", Width::unsigned(16), lanes);
        let quotient = b.witness("quotient", Width::unsigned(7), lanes);
        let codes = b.witness("codes", Width::signed(8), lanes);
        let (scale, zero, dynamic) = match self.policy {
            Policy::Static(s) => (
                b.public(
                    "scale",
                    vec![i64::from(s); 1 << groups],
                    Width::unsigned(16),
                    groups,
                ),
                b.public("zero", vec![0; 1 << groups], Width::unsigned(1), groups),
                None,
            ),
            _ => {
                let scale_width = Width::unsigned(bit_length(u128::from(DYNAMIC_SCALE)));
                let scale = b.witness("scale", scale_width, groups);
                let zero = b.witness("zero", Width::unsigned(1), groups);
                let maximum = b.witness("maximum", Width::unsigned(16), groups);
                let slack = b.column("slack", Width::unsigned(7), groups);
                let gap = b.witness("gap", Width::unsigned(16), lanes);
                let hit = b.witness("hit", Width::unsigned(1), lanes);
                (scale, zero, Some((zero, maximum, slack, gap, hit)))
            }
        };
        let (x, s, z) = (r(self.input, 0..lanes), group(scale), group(zero));

        // mask*x - a + 2*sigma*a = 0.
        b.identity(
            "sign",
            lanes,
            vec![
                term(1, vec![lane(mask), x]),
                term(-1, vec![lane(magnitude)]),
                term(2, vec![lane(sign), lane(magnitude)]),
            ],
        );
        // a = q0*(s+z) + rho.
        b.identity(
            "division",
            lanes,
            vec![
                term(1, vec![lane(magnitude)]),
                term(-1, vec![lane(floor), s.clone()]),
                term(-1, vec![lane(floor), z.clone()]),
                term(-1, vec![lane(remainder)]),
            ],
        );
        // spare = s + z - 1 - rho >= 0: rho < D, and D >= 1.
        b.identity(
            "spare",
            lanes,
            vec![
                term(1, vec![lane(spare)]),
                term(-1, vec![s.clone()]),
                term(-1, vec![z.clone()]),
                term(1, vec![]),
                term(1, vec![lane(remainder)]),
            ],
        );
        // half_gap = (2beta-1)(2rho-D) - (1-beta) >= 0, D = s+z.
        b.identity(
            "half",
            lanes,
            vec![
                term(1, vec![lane(half_gap)]),
                term(-4, vec![lane(half), lane(remainder)]),
                term(2, vec![lane(half), s.clone()]),
                term(2, vec![lane(half), z.clone()]),
                term(2, vec![lane(remainder)]),
                term(-1, vec![s.clone()]),
                term(-1, vec![z.clone()]),
                term(1, vec![]),
                term(-1, vec![lane(half)]),
            ],
        );
        // q = q0 + beta.
        b.identity(
            "quotient",
            lanes,
            vec![
                term(1, vec![lane(quotient)]),
                term(-1, vec![lane(floor)]),
                term(-1, vec![lane(half)]),
            ],
        );
        // c = q - 2*sigma*q.
        b.identity(
            "code",
            lanes,
            vec![
                term(1, vec![lane(codes)]),
                term(-1, vec![lane(quotient)]),
                term(2, vec![lane(sign), lane(quotient)]),
            ],
        );
        if let Some((_, maximum, slack, gap, hit)) = dynamic {
            b.identity(
                "gap",
                lanes,
                vec![
                    term(1, vec![lane(gap)]),
                    term(-1, vec![group(maximum)]),
                    term(1, vec![lane(magnitude)]),
                ],
            );
            b.identity("attained", lanes, vec![term(1, vec![lane(hit), lane(gap)])]);
            let at = |c: ColumnId| r(c, 0..groups);
            // slack = 127*s - M, in [0,126] by the lookup below.
            b.identity(
                "ceiling",
                groups,
                vec![
                    term(1, vec![at(slack)]),
                    term(-127, vec![at(scale)]),
                    term(1, vec![at(maximum)]),
                ],
            );
            b.identity("zero", groups, vec![term(1, vec![at(zero), at(maximum)])]);
            let table = b.relation.add_table(Table {
                name: "range/0..=126".into(),
                widths: vec![Width::unsigned(7)],
                rows: (0..=126).map(|v| vec![v]).collect(),
            });
            b.relation.lookups.push(Lookup {
                name: alloc::format!("{prefix}/slack/range"),
                vars: groups,
                selector: None,
                tuple: vec![at(slack)],
                table,
            });
            // sum over the group of h = 1: summed bits are the lanes of one group.
            b.relation.matmuls.push(Matmul {
                name: alloc::format!("{prefix}/attained/one-hot"),
                free: groups,
                summed: lg,
                out: r(one, []),
                lhs: r(hit, (groups..groups + lg).chain(0..groups)),
                rhs: r(one, []),
            });
        }
        self.columns = Some(Columns {
            magnitude,
            sign,
            floor,
            remainder,
            spare,
            half,
            half_gap,
            quotient,
            codes,
            scale,
            dynamic,
        });
    }

    fn assign(
        &self,
        relation: &Relation,
        capture: &ConversionCapture,
        values: &mut Values,
    ) -> Result<(), Violation> {
        let mut w = self.source(capture)?;
        self.complete(&mut w, Step::Sign, None);
        // The executor's codes and scales must be the ones the relations force.
        let (_, ld, lg) = self.logs();
        let codes_ok = (0..w.codes.len())
            .all(|x| !self.real(x) || w.codes[x] == capture.codes[x >> ld][x & ((1 << ld) - 1)]);
        let per_row = 1usize << (ld - lg);
        let scales_ok = capture.scales.iter().enumerate().all(|(row, scales)| {
            scales
                .iter()
                .enumerate()
                .all(|(k, s)| w.scale[row * per_row + k] == i64::from(*s))
        });
        if !codes_ok || !scales_ok {
            return Err(Invalid::Column(self.codes_id()).into());
        }
        self.write(relation, &w, values)
    }
}

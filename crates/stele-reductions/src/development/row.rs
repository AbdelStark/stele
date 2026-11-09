//! Row conversion of int16 rows to int8 codes (RFC-0026 §5 row 3; RFC-0025 §2.2,
//! flow §1; grouped rows RFC-0004 A15).
//!
//! Per group of `g` lanes (`g = d` for a per-row policy) with scale `s`:
//! - sign/abs: `mask*x = a - 2*sigma*a`, so `a = |x|` on real lanes and `a = 0` on
//!   padding, which pins every padded code to 0;
//! - attained maximum (dynamic): `gap = M - a >= 0`, one-hot `h` with `sum h = 1`
//!   over the group (matmul row sum) and `h*gap = 0`, so `M = max a`;
//! - ceiling (dynamic): `127*s - M` in `[0,126]` (lookup), so `s = ceil(M/127)`;
//! - zero-row branch (dynamic): Boolean `z` with `z*M = 0`, `z*q = 0`, and divisor
//!   `D = s + z >= 1` (from the range on `D-1-rho`), so `z = [M = 0]`;
//! - round-half-away division `R(a/D)`: `a = q0*D + rho`, `0 <= rho <= D-1`,
//!   `beta = [2*rho >= D]` by a range on `(2beta-1)(2rho-D) - (1-beta)`,
//!   `q = q0 + beta <= 127`;
//! - code `c = (1-2*sigma)*q`.
//!
//! A static policy makes `s` a public column and `z = 0`. Output-uniqueness lemma:
//! lemma R in `agents/reviews/e16-05-projections.md`.

use super::{bit_length, log2_ceil, r, term, Builder, Unsupported};
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use stele_ir::relation::{
    ColumnId, Invalid, Lookup, Matmul, Module, Relation, Table, Values, Violation, Width,
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

/// Executor intermediates of one row conversion over every real row:
/// `stele_cqis::row::Quantiser::convert_wide`'s input, codes and scales.
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
struct Columns {
    magnitude: ColumnId,
    sign: ColumnId,
    floor: ColumnId,
    remainder: ColumnId,
    spare: ColumnId,
    half: ColumnId,
    half_gap: ColumnId,
    quotient: ColumnId,
    codes: ColumnId,
    scale: ColumnId,
    /// Dynamic only: (zero, maximum, slack, gap, hit).
    dynamic: Option<(ColumnId, ColumnId, ColumnId, ColumnId, ColumnId)>,
}

/// One row conversion of a `rows x dimension` int16 column (RFC-0026 §5 row 3).
#[derive(Clone, Debug)]
pub struct RowConversion {
    prefix: String,
    input: ColumnId,
    rows: usize,
    dimension: usize,
    policy: Policy,
    columns: Option<Columns>,
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
        if log2_ceil(rows) + log2_ceil(dimension) > stele_ir::relation::MAX_VARS {
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

    fn logs(&self) -> (u8, u8, u8) {
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

    /// Zero-branch column `z` of a dynamic policy (near-miss tests).
    #[cfg(test)]
    pub(crate) fn zero(&self) -> Option<ColumnId> {
        self.columns.and_then(|c| c.dynamic).map(|d| d.0)
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
}

impl Module for RowConversion {
    type Capture = ConversionCapture;

    fn declare(&mut self, relation: &mut Relation) {
        let (t, ld, lg) = self.logs();
        let lanes = t + ld;
        let groups = lanes - lg;
        let (rows, d) = (self.rows, self.dimension);
        let mask = (0..1usize << lanes)
            .map(|x| i64::from((x >> ld) < rows && (x & ((1 << ld) - 1)) < d))
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
            let m = group(maximum);
            b.identity(
                "zero/codes",
                lanes,
                vec![term(1, vec![z.clone(), lane(quotient)])],
            );
            b.identity(
                "gap",
                lanes,
                vec![
                    term(1, vec![lane(gap)]),
                    term(-1, vec![m]),
                    term(1, vec![lane(magnitude)]),
                ],
            );
            b.identity("attained", lanes, vec![term(1, vec![lane(hit), lane(gap)])]);
            // slack = 127*s - M, in [0,126] by the lookup below.
            b.identity(
                "ceiling",
                groups,
                vec![
                    term(1, vec![r(slack, 0..groups)]),
                    term(-127, vec![r(scale, 0..groups)]),
                    term(1, vec![r(maximum, 0..groups)]),
                ],
            );
            b.identity(
                "zero/maximum",
                groups,
                vec![term(1, vec![r(zero, 0..groups), r(maximum, 0..groups)])],
            );
            let table = b.relation.add_table(Table {
                name: "range/0..=126".into(),
                widths: vec![Width::unsigned(7)],
                rows: (0..=126).map(|v| vec![v]).collect(),
            });
            b.relation.lookups.push(Lookup {
                name: alloc::format!("{prefix}/ceiling"),
                vars: groups,
                selector: None,
                tuple: vec![r(slack, 0..groups)],
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
        let c = self.columns.ok_or(Violation::Missing(self.input))?;
        let (t, ld, lg) = self.logs();
        let (lanes, groups) = (t + ld, t + ld - lg);
        let real_groups = self.dimension.div_ceil(1 << lg);
        let shape_ok = capture.inputs.len() == self.rows
            && capture.codes.len() == self.rows
            && capture.scales.len() == self.rows
            && capture.inputs.iter().all(|row| row.len() == self.dimension)
            && capture.codes.iter().all(|row| row.len() == self.dimension)
            && capture.scales.iter().all(|row| row.len() == real_groups);
        if !shape_ok {
            return Err(Invalid::Column(self.input).into());
        }
        let dynamic = c.dynamic.is_some();
        let real = |x: usize| (x >> ld) < self.rows && (x & ((1 << ld) - 1)) < self.dimension;
        let at = |rows: &Vec<Vec<i64>>, x: usize| {
            if real(x) {
                rows[x >> ld][x & ((1 << ld) - 1)]
            } else {
                0
            }
        };
        let scale_of = |k: usize| -> i64 {
            let (row, group) = (k >> (ld - lg), k & ((1 << (ld - lg)) - 1));
            match self.policy {
                Policy::Static(s) => i64::from(s),
                _ if row < self.rows && group < real_groups => {
                    i64::from(capture.scales[row][group])
                }
                _ => 0,
            }
        };
        let scales: Vec<i64> = (0..1usize << groups).map(scale_of).collect();
        let zeros: Vec<i64> = scales
            .iter()
            .map(|&s| i64::from(dynamic && s == 0))
            .collect();
        let lane_count = 1usize << lanes;
        let a: Vec<i64> = (0..lane_count)
            .map(|x| at(&capture.inputs, x).abs())
            .collect();
        let mut columns: [Vec<i64>; 9] = Default::default();
        for x in 0..lane_count {
            let input = at(&capture.inputs, x);
            let code = at(&capture.codes, x);
            let divisor = scales[x >> lg] + zeros[x >> lg];
            let (floor, remainder) = (a[x] / divisor, a[x] % divisor);
            // beta follows the captured code, so a wrong code fails only its ranges.
            let half = code.abs() - floor;
            let row = [
                a[x],
                i64::from(input < 0),
                floor,
                remainder,
                divisor - 1 - remainder,
                half,
                (2 * half - 1) * (2 * remainder - divisor) - (1 - half),
                code.abs(),
                code,
            ];
            for (column, value) in columns.iter_mut().zip(row) {
                column.push(value);
            }
        }
        let ids = [
            c.magnitude,
            c.sign,
            c.floor,
            c.remainder,
            c.spare,
            c.half,
            c.half_gap,
            c.quotient,
            c.codes,
        ];
        for (id, column) in ids.into_iter().zip(columns) {
            values.set(relation, id, column)?;
        }
        if let Some((zero, maximum, slack, gap, hit)) = c.dynamic {
            let width = 1usize << lg;
            let maxima: Vec<i64> = a
                .chunks(width)
                .map(|group| group.iter().copied().max().unwrap_or(0))
                .collect();
            let first: Vec<usize> = a
                .chunks(width)
                .zip(&maxima)
                .map(|(group, m)| group.iter().position(|v| v == m).unwrap_or(0))
                .collect();
            values.set(relation, c.scale, scales.clone())?;
            values.set(relation, zero, zeros)?;
            values.set(relation, maximum, maxima.clone())?;
            let slacks = scales
                .iter()
                .zip(&maxima)
                .map(|(s, m)| 127 * s - m)
                .collect();
            values.set(relation, slack, slacks)?;
            values.set(
                relation,
                gap,
                (0..lane_count).map(|x| maxima[x >> lg] - a[x]).collect(),
            )?;
            values.set(
                relation,
                hit,
                (0..lane_count)
                    .map(|x| i64::from(x & (width - 1) == first[x >> lg]))
                    .collect(),
            )?;
        }
        Ok(())
    }
}

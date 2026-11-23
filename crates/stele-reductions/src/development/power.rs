//! Power-of-two rows, their projections and the gated product that feeds one
//! (RFC-0026 A32 over the numerics of RFC-0004 A16).
//!
//! A row has `b`-bit codes `q = R+(x / 2^a)` with `|q| <= c = 2^(b-1) - 1`, where
//! `R+(x / 2^a) = floor((x + floor(2^a / 2)) / 2^a)` and `a` is the least exponent in
//! `amin..=amax` that keeps every code of the row within `[-c, c]`.
//!
//! Row relations, per row `t` and lane `i`:
//! - `(a_t, P_t)` and `(a_t, H_t)` are rows of public tables, so `P = 2^a` and
//!   `H = floor(P / 2)`;
//! - `(q, h)` is a row of the code table: `|q| <= c` and a flag `h` in `0..=3`;
//! - `rho = mask*x + H - q*P` and `(4a + h, rho)` is a row of the remainder table, so
//!   `0 <= rho < P`, which makes `q` the one code of `x` at exponent `a`;
//! - `sum_i h_i` is 0 at `a = amin` and in `1..=3` above it.
//!
//! A flag marks a lane whose code at exponent `a - 1`, `2q + tau`, leaves `[-c, c]`
//! (`tau` is -1, 0 or 1 by the quarter of `P` that holds `rho`): `h = 1` for
//! `|q| > w = 2^(b-2)`, `h = 2` for `q = w` with `4*rho >= P`, `h = 3` for `q = -w`
//! with `4*rho < 3P`. Codes shrink as `a` grows, so one marked lane makes `a` the least
//! admissible exponent. Padding has `x = 0`, hence `q = 0`, no flag and `a = amin`.
//!
//! Projection relations, per row `t` and channel `j` with the public shift
//! `lambda_j >= 1` (the channel mantissa is `2^k_j` and `lambda_j = L - k_j`):
//! - `cap = min(amax, lambda_min - 1)`, `a' = min(a, cap)`; half the divisor is
//!   `D/2 = 2^(lambda_j - a' - 1) = 2^(lambda_j - cap - 1) * 2^(cap - a')`, a public
//!   channel factor times a row factor read from `a_t` by a table;
//! - `A = sum_i q_i * w_ji` is a virtual contraction, `Z` is committed signed 16, and
//!   `rho = A + D/2 - Z*D` with `(lambda_j - a', rho)` a row of the shift table
//!   (`0 <= rho < D`), so `Z = R+(A / D)`;
//! - the output is `Z`, or `Z * 2^(a - a')` range-checked signed 16 when `amax > cap`.
//!
//! Gated product relations, per row and lane, for the gate `G` and the up value `U`:
//! - `(G, s)` is a row of the `silu_q` table;
//! - `mask*s*U + H - q*P - rho0 - W*rho1 = 0` with the split `W_t = 2^w(a)`,
//!   `w(a) = min(max(a - 2, 0), 12)`, `(a, rho0)` a row of the low table
//!   (`rho0 < 2^w`) and `(4a + h, rho1)` a row of the high table (`rho1 < 2^(a - w)`),
//!   so `0 <= rho0 + W*rho1 < P`. The quarter tests read `rho1` alone because `W`
//!   divides `P/4` from `a = 2` on.
//!
//! Committed cells per element: a row 2 (`q`, `h`); a projection output 1 (`Z`); a
//! gated lane 5 (`s`, `q`, `h`, `rho0`, `rho1`). Row-domain columns are extra.

use super::{
    log2_ceil, r, term, Builder, ConversionCapture, Policy, Projection, ProjectionCapture,
    ProjectionPlan, RowConversion, RowOutput, Unsupported,
};
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use stele_cqis::tables::{Error as TableError, Table as CqisTable};
use stele_ir::relation::{
    ColumnId, Def, Invalid, Kind, Lookup, Module, Range, Relation, Table, Values, Violation, Width,
    HALF_MODULUS, MAX_VARS,
};

/// Widest shift a projection divides by: its table has `2^(SHIFT + 1) - 2` rows.
const SHIFT: u8 = 15;
/// Low remainder limb of a gated row holds at most this many bits.
const SPLIT: u8 = 12;

/// What a projection reads from a power-of-two row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PowerOutput {
    /// Codes, `T x d` row-major, signed `bits`.
    pub codes: ColumnId,
    /// Row exponents `a`, one per row.
    pub exponent: ColumnId,
    pub log_rows: u8,
    pub log_dimension: u8,
    /// Code width `b`, and the least and largest row exponent.
    pub bits: u8,
    pub least: u8,
    pub most: u8,
}

/// `(c, w)`: the largest code magnitude and the magnitude a flag starts at.
fn code_bounds(bits: u8) -> (i64, i64) {
    ((1 << (bits - 1)) - 1, 1 << (bits - 2))
}

fn supported(bits: u8, least: u8, most: u8) -> bool {
    (4..=12).contains(&bits) && least <= most && most <= 26
}

/// `R+(x / 2^a)`.
fn round(x: i64, a: u8) -> i64 {
    (x + ((1i64 << a) >> 1)) >> a
}

/// The least exponent in `least..=most` that keeps every code of `row` within `[-c, c]`.
fn exponent_of(row: &[i64], bits: u8, least: u8, most: u8) -> Option<u8> {
    let c = code_bounds(bits).0;
    let low = row.iter().copied().min().unwrap_or(0).min(0);
    let high = row.iter().copied().max().unwrap_or(0).max(0);
    (least..=most).find(|&a| round(high, a) <= c && round(low, a) >= -c)
}

/// The flag of a lane whose code at exponent `a - 1` leaves `[-c, c]`, else 0.
fn flag(q: i64, rho: i64, a: u8, bits: u8) -> i64 {
    let w = code_bounds(bits).1;
    let p = 1i64 << a;
    if a == 0 {
        0
    } else if q.abs() > w {
        1
    } else if q == w && 4 * rho >= p {
        2
    } else if q == -w && 4 * rho < 3 * p {
        3
    } else {
        0
    }
}

/// `(q, h)`: every code with flag 0, a code past `w` with flag 1, `w` with 2, `-w` with 3.
fn code_table(bits: u8) -> Table {
    let (c, w) = code_bounds(bits);
    let mut rows = Vec::new();
    for q in -c..=c {
        rows.push(vec![q, 0]);
        if q.abs() > w {
            rows.push(vec![q, 1]);
        }
    }
    rows.push(vec![w, 2]);
    rows.push(vec![-w, 3]);
    Table {
        name: format!("power/code/{bits}"),
        widths: vec![Width::signed(bits), Width::unsigned(2)],
        rows,
    }
}

/// `(a, f(a))` over `least..=most`.
fn exponent_table(name: &str, least: u8, most: u8, width: Width, f: impl Fn(u8) -> i64) -> Table {
    Table {
        name: format!("power/{name}/{least}..{most}"),
        widths: vec![Width::unsigned(5), width],
        rows: (least..=most).map(|a| vec![i64::from(a), f(a)]).collect(),
    }
}

/// `(a, s)`: no flag at the least exponent, one to three flag units above it.
fn count_table(least: u8, most: u8) -> Table {
    let mut rows = vec![vec![i64::from(least), 0]];
    for a in least + 1..=most {
        rows.extend((1..=3).map(|s| vec![i64::from(a), s]));
    }
    Table {
        name: format!("power/count/{least}..{most}"),
        widths: vec![Width::unsigned(5), Width::unsigned(2)],
        rows,
    }
}

/// `(4a + h, r)`: `r < 2^(a - w(a))`, and for `h = 2` and `h = 3` the quarter of `P`
/// that the flag needs, read from the limb of weight `2^w(a)`.
fn remainder_table(name: &str, least: u8, most: u8, split: impl Fn(u8) -> u8) -> Table {
    let mut rows = Vec::new();
    let mut top = 1;
    for a in least..=most {
        let w = split(a);
        top = top.max(a - w);
        for r in 0..1i64 << (a - w) {
            let scaled = (4 * r) << w;
            rows.push(vec![4 * i64::from(a), r]);
            rows.push(vec![4 * i64::from(a) + 1, r]);
            if scaled >= 1 << a {
                rows.push(vec![4 * i64::from(a) + 2, r]);
            }
            if scaled < 3 << a {
                rows.push(vec![4 * i64::from(a) + 3, r]);
            }
        }
    }
    Table {
        name: format!("power/{name}/{least}..{most}"),
        widths: vec![Width::unsigned(7), Width::unsigned(top)],
        rows,
    }
}

/// Weight exponent of the high remainder limb of a gated row.
fn split(a: u8) -> u8 {
    a.saturating_sub(2).min(SPLIT)
}

/// Row-domain columns every power-of-two row declares.
#[derive(Clone, Copy, Debug)]
struct RowColumns {
    exponent: ColumnId,
    power: ColumnId,
    half: ColumnId,
}

/// Declare `a`, `P = 2^a` and `H = floor(P/2)` on the row domain, bound by tables.
fn row_columns(b: &mut Builder<'_>, rows: u8, least: u8, most: u8) -> RowColumns {
    let exponent = b.column("exponent", Width::unsigned(5), rows);
    let power = b.column("power", Width::unsigned(most + 1), rows);
    let half = b.column("half", Width::unsigned(most.max(1)), rows);
    let at = |c: ColumnId| r(c, 0..rows);
    for (name, column, width, f) in [
        (
            "power",
            power,
            Width::unsigned(most + 1),
            (|a| 1i64 << a) as fn(u8) -> i64,
        ),
        ("half", half, Width::unsigned(most.max(1)), |a| {
            (1i64 << a) >> 1
        }),
    ] {
        let table = b
            .relation
            .add_table(exponent_table(name, least, most, width, f));
        let lookup = Lookup {
            name: format!("{}/{name}/table", b.prefix()),
            vars: rows,
            selector: None,
            tuple: vec![at(exponent), at(column)],
            table,
        };
        b.relation.lookups.push(lookup);
    }
    RowColumns {
        exponent,
        power,
        half,
    }
}

/// Declare the code table lookup and the flag count of a row, with its table.
fn flags(
    b: &mut Builder<'_>,
    codes: ColumnId,
    hit: ColumnId,
    exponent: ColumnId,
    (rows, lanes): (u8, u8),
    (bits, least, most): (u8, u8, u8),
) {
    let domain = rows + lanes;
    let table = b.relation.add_table(code_table(bits));
    let lookup = Lookup {
        name: format!("{}/codes/table", b.prefix()),
        vars: domain,
        selector: None,
        tuple: vec![r(codes, 0..domain), r(hit, 0..domain)],
        table,
    };
    b.relation.lookups.push(lookup);
    let one = b.public("one", vec![1], Width::unsigned(1), 0);
    let count = b.virtual_col(
        "count",
        Def::Contraction {
            free: rows,
            summed: lanes,
            lhs: r(hit, (rows..domain).chain(0..rows)),
            rhs: r(one, []),
        },
        rows,
    );
    let table = b.relation.add_table(count_table(least, most));
    let lookup = Lookup {
        name: format!("{}/count/table", b.prefix()),
        vars: rows,
        selector: None,
        tuple: vec![r(exponent, 0..rows), r(count, 0..rows)],
        table,
    };
    b.relation.lookups.push(lookup);
}

/// Bits of the halved channel divisor `2^(lambda - cap - 1)` at the largest shift.
fn halved_bits(high: i32, cap: i32) -> u8 {
    (high - cap).max(1) as u8
}

/// Bits of the row factor `2^(cap - min(a, cap))` at the least exponent.
fn scale_bits(least: u8, cap: i32) -> u8 {
    (cap - i32::from(least).min(cap) + 1) as u8
}

/// One power-of-two conversion of a `rows x dimension` int16 column.
#[derive(Clone, Debug)]
pub struct PowerRow {
    prefix: String,
    input: ColumnId,
    rows: usize,
    dimension: usize,
    bits: u8,
    least: u8,
    most: u8,
    columns: Option<(RowColumns, ColumnId, ColumnId)>,
}

impl PowerRow {
    /// `input` is a signed-16 column of `2^(log rows + log dimension)` entries,
    /// row-major. `scale` is the policy's `b + 256*amin` (RFC-0004 A16).
    pub fn new(
        prefix: &str,
        input: ColumnId,
        rows: usize,
        dimension: usize,
        scale: u32,
    ) -> Result<Self, Unsupported> {
        if rows == 0 || !(1..=16384).contains(&dimension) {
            return Err(Unsupported::Shape);
        }
        let (bits, least) = ((scale & 255) as u8, scale >> 8);
        if scale > 0xffff || !(4..=12).contains(&bits) || least > u32::from(17 - bits) {
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
            bits,
            least: least as u8,
            most: 17 - bits,
            columns: None,
        })
    }

    fn logs(&self) -> (u8, u8) {
        (log2_ceil(self.rows), log2_ceil(self.dimension))
    }

    /// Output column ids; `None` before `declare`.
    pub fn output(&self) -> Option<PowerOutput> {
        let (log_rows, log_dimension) = self.logs();
        self.columns.map(|(row, codes, _)| PowerOutput {
            codes,
            exponent: row.exponent,
            log_rows,
            log_dimension,
            bits: self.bits,
            least: self.least,
            most: self.most,
        })
    }
}

impl Module for PowerRow {
    type Capture = ConversionCapture;

    fn declare(&mut self, relation: &mut Relation) {
        assert!(
            relation
                .column_magnitude(self.input)
                .is_some_and(|m| m <= Width::signed(16).magnitude()),
            "a power-of-two row converts a signed-16 column (RFC-0026 A32)"
        );
        let (t, ld) = self.logs();
        let lanes = t + ld;
        let (rows, dimension) = (self.rows, self.dimension);
        let mask = (0..1usize << lanes)
            .map(|x| i64::from((x >> ld) < rows && (x & ((1 << ld) - 1)) < dimension))
            .collect();
        let prefix = self.prefix.clone();
        let mut b = Builder::new(relation, &prefix);
        let mask = b.public("mask", mask, Width::unsigned(1), lanes);
        let row = row_columns(&mut b, t, self.least, self.most);
        let codes = b.column("codes", Width::signed(self.bits), lanes);
        let hit = b.column("hit", Width::unsigned(2), lanes);
        let lane = |c: ColumnId| r(c, 0..lanes);
        let of_row = |c: ColumnId| r(c, ld..lanes);
        let remainder = b.virtual_col(
            "remainder",
            Def::Pointwise {
                terms: vec![
                    term(1, vec![lane(mask), lane(self.input)]),
                    term(1, vec![of_row(row.half)]),
                    term(-1, vec![lane(codes), of_row(row.power)]),
                ],
            },
            lanes,
        );
        let key = b.virtual_col(
            "key",
            Def::Linear {
                constant: 0,
                terms: vec![(4, of_row(row.exponent)), (1, lane(hit))],
            },
            lanes,
        );
        let table =
            b.relation
                .add_table(remainder_table("remainder", self.least, self.most, |_| 0));
        let lookup = Lookup {
            name: format!("{prefix}/remainder/table"),
            vars: lanes,
            selector: None,
            tuple: vec![lane(key), lane(remainder)],
            table,
        };
        b.relation.lookups.push(lookup);
        flags(
            &mut b,
            codes,
            hit,
            row.exponent,
            (t, ld),
            (self.bits, self.least, self.most),
        );
        self.columns = Some((row, codes, hit));
    }

    fn assign(
        &self,
        relation: &Relation,
        capture: &ConversionCapture,
        values: &mut Values,
    ) -> Result<(), Violation> {
        let (row, codes, hit) = self.columns.ok_or(Violation::Missing(self.input))?;
        let bad = || Violation::from(Invalid::Column(codes));
        let (t, ld) = self.logs();
        if capture.inputs.len() != self.rows
            || capture.inputs.iter().any(|x| x.len() != self.dimension)
        {
            return Err(bad());
        }
        let mut exponents = vec![i64::from(self.least); 1 << t];
        let mut q = vec![0i64; 1 << (t + ld)];
        let mut h = vec![0i64; 1 << (t + ld)];
        for (i, x) in capture.inputs.iter().enumerate() {
            let a = exponent_of(x, self.bits, self.least, self.most).ok_or_else(bad)?;
            exponents[i] = i64::from(a);
            let mut flagged = a == self.least;
            for (j, &x) in x.iter().enumerate() {
                let code = round(x, a);
                q[(i << ld) + j] = code;
                let rho = x + ((1i64 << a) >> 1) - (code << a);
                let f = flag(code, rho, a, self.bits);
                if !flagged && f != 0 {
                    h[(i << ld) + j] = f;
                    flagged = true;
                }
            }
            // The executor's codes and scale must be the ones the relations force.
            let same = capture
                .codes
                .get(i)
                .is_some_and(|c| c[..] == q[i << ld..][..x.len()])
                && capture.scales.get(i).is_some_and(|s| s[..] == [1u32 << a]);
            if !flagged || !same {
                return Err(bad());
            }
        }
        let power = exponents.iter().map(|a| 1i64 << a).collect();
        let half = exponents.iter().map(|a| (1i64 << a) >> 1).collect();
        for (id, column) in [
            (row.exponent, exponents),
            (row.power, power),
            (row.half, half),
            (codes, q),
            (hit, h),
        ] {
            values.set(relation, id, column)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
struct ProjectionColumns {
    weight: ColumnId,
    mantissa: ColumnId,
    output: ColumnId,
    /// Row columns `a' = min(a, cap)` (when `amax > cap`), `2^(cap - a')` and
    /// `2^(a - a')` (when `amax > cap`).
    kept: Option<ColumnId>,
    scale: ColumnId,
    grow: Option<ColumnId>,
}

/// The projection of a power-of-two row into signed int16 outputs.
#[derive(Clone, Debug)]
pub struct PowerProjection {
    prefix: String,
    input: PowerOutput,
    weight: Option<ColumnId>,
    plan: ProjectionPlan,
    /// Channel shifts `lambda_j`, and `cap = min(amax, lambda_min - 1)`.
    shifts: Vec<u8>,
    cap: u8,
    columns: Option<ProjectionColumns>,
}

impl PowerProjection {
    /// `plan` is the projection's plan data; its mantissas are powers of two and its
    /// `shift` is `e - f + fo`, so the channel shift is `lambda_j = -shift - k_j`.
    pub fn new(
        prefix: &str,
        input: PowerOutput,
        weight: Option<ColumnId>,
        plan: ProjectionPlan,
    ) -> Result<Self, Unsupported> {
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
        if !supported(input.bits, input.least, input.most)
            || plan.mantissas.iter().any(|m| !m.is_power_of_two())
        {
            return Err(Unsupported::Policy);
        }
        let shift = |m: u16| -plan.shift - m.trailing_zeros() as i32;
        let low = plan.mantissas.iter().map(|m| shift(*m)).min().unwrap_or(0);
        let high = plan.mantissas.iter().map(|m| shift(*m)).max().unwrap_or(0);
        if low < 1 || high > 63 {
            return Err(Unsupported::Policy);
        }
        let cap = i32::from(input.most).min(low - 1);
        // The widest divisor is at the smallest kept exponent.
        let widest = high - i32::from(input.least).min(cap);
        let accumulator = (1u128 << log2_ceil(plan.inner))
            * Width::signed(input.bits).magnitude()
            * Width::signed(plan.weight_bits).magnitude();
        // The remainder's static bound, from the widths `declare` gives the halved
        // channel divisor and the row factor (RFC-0026 §3.6).
        let divisor = Width::unsigned(halved_bits(high, cap)).magnitude()
            * Width::unsigned(scale_bits(input.least, cap)).magnitude();
        let wrap_free = widest <= i32::from(SHIFT)
            && accumulator + divisor + 2 * Width::signed(16).magnitude() * divisor <= HALF_MODULUS;
        if plan.output_bits != 16
            || !wrap_free
            || input.log_rows + log2_ceil(plan.outputs) > MAX_VARS
        {
            return Err(Unsupported::Domain);
        }
        Ok(Self {
            prefix: prefix.into(),
            shifts: plan.mantissas.iter().map(|m| shift(*m) as u8).collect(),
            cap: cap as u8,
            input,
            weight,
            plan,
            columns: None,
        })
    }

    /// The output column; `None` before `declare`.
    pub fn output(&self) -> Option<ColumnId> {
        self.columns.map(|c| c.output)
    }

    /// The weight column read (declared here unless one was supplied).
    pub fn weight(&self) -> Option<ColumnId> {
        self.columns.map(|c| c.weight)
    }

    fn weight_width(&self) -> Width {
        Width::signed(self.plan.weight_bits)
    }
}

impl Module for PowerProjection {
    type Capture = ProjectionCapture;

    fn declare(&mut self, relation: &mut Relation) {
        let (t, ld, lo) = (
            self.input.log_rows,
            self.input.log_dimension,
            log2_ceil(self.plan.outputs),
        );
        let out = t + lo;
        let (cap, least, most) = (self.cap, self.input.least, self.input.most);
        let prefix = self.prefix.clone();
        let mut b = Builder::new(relation, &prefix);
        let weight = self.weight.unwrap_or_else(|| {
            let name = format!("{prefix}/weight");
            let id = b
                .relation
                .add_column(&name, Kind::Weight, self.weight_width(), lo + ld);
            b.relation.ranges.push(Range {
                name: format!("{name}/range"),
                column: id,
                width: self.weight_width(),
            });
            id
        });
        // A padded channel has zero weights; any admissible shift pins its output to 0.
        let shifts: Vec<i64> = (0..1usize << lo)
            .map(|j| i64::from(self.shifts.get(j).copied().unwrap_or(cap + 1)))
            .collect();
        let high = shifts.iter().copied().max().unwrap_or(1);
        let widest = high - i64::from(least.min(cap));
        // Half the channel divisor, `2^(lambda_j - cap - 1)`: one bit tighter than the
        // divisor under the bound rule.
        let halved = shifts
            .iter()
            .map(|s| 1i64 << (s - i64::from(cap) - 1))
            .collect();
        let bits = Width::unsigned(halved_bits(high as i32, i32::from(cap)));
        let shift = b.public("shift", shifts, Width::unsigned(6), lo);
        let halved = b.public("halved", halved, bits, lo);

        let rows = |c: ColumnId| r(c, 0..t);
        let row_column = |b: &mut Builder<'_>, name: &str, width: Width, f: fn(u8, u8) -> i64| {
            let column = b.column(name, width, t);
            let table = b.relation.add_table(exponent_table(
                &format!("{name}/{cap}"),
                least,
                most,
                width,
                |a| f(a, cap),
            ));
            let lookup = Lookup {
                name: format!("{prefix}/{name}/table"),
                vars: t,
                selector: None,
                tuple: vec![rows(self.input.exponent), rows(column)],
                table,
            };
            b.relation.lookups.push(lookup);
            column
        };
        let scale = row_column(
            &mut b,
            "scale",
            Width::unsigned(scale_bits(least, i32::from(cap))),
            |a, cap| 1 << (cap - a.min(cap)),
        );
        let (kept, grow) = if most > cap {
            (
                Some(row_column(&mut b, "kept", Width::unsigned(5), |a, cap| {
                    i64::from(a.min(cap))
                })),
                Some(row_column(
                    &mut b,
                    "grow",
                    Width::unsigned(most - cap + 1),
                    |a, cap| 1 << (a - a.min(cap)),
                )),
            )
        } else {
            (None, None)
        };

        let at = |c: ColumnId| r(c, 0..out);
        let channel = |c: ColumnId| r(c, 0..lo);
        let of_row = |c: ColumnId| r(c, lo..out);
        let summed = (out..out + ld).collect::<Vec<u8>>();
        let sum = b.virtual_col(
            "sum",
            Def::Contraction {
                free: out,
                summed: ld,
                lhs: r(self.input.codes, summed.iter().copied().chain(lo..out)),
                rhs: r(weight, summed.iter().copied().chain(0..lo)),
            },
            out,
        );
        let mantissa = b.witness("mantissa", Width::signed(16), out);
        let remainder = b.virtual_col(
            "remainder",
            Def::Pointwise {
                terms: vec![
                    term(1, vec![at(sum)]),
                    term(1, vec![channel(halved), of_row(scale)]),
                    term(-2, vec![at(mantissa), channel(halved), of_row(scale)]),
                ],
            },
            out,
        );
        let key = b.virtual_col(
            "key",
            Def::Linear {
                constant: 0,
                terms: vec![
                    (1, channel(shift)),
                    (-1, of_row(kept.unwrap_or(self.input.exponent))),
                ],
            },
            out,
        );
        let table = b.relation.add_table(Table {
            name: format!("power/shift/{widest}"),
            widths: vec![Width::unsigned(5), Width::unsigned(widest as u8)],
            rows: (1..=widest)
                .flat_map(|k| (0..1i64 << k).map(move |v| vec![k, v]))
                .collect(),
        });
        let lookup = Lookup {
            name: format!("{prefix}/remainder/table"),
            vars: out,
            selector: None,
            tuple: vec![at(key), at(remainder)],
            table,
        };
        b.relation.lookups.push(lookup);
        let output = match grow {
            Some(grow) => b.virtual_ranged(
                "output",
                Def::Pointwise {
                    terms: vec![term(1, vec![at(mantissa), of_row(grow)])],
                },
                Width::signed(16),
                out,
            ),
            None => mantissa,
        };
        self.columns = Some(ProjectionColumns {
            weight,
            mantissa,
            output,
            kept,
            scale,
            grow,
        });
    }

    fn assign(
        &self,
        relation: &Relation,
        capture: &ProjectionCapture,
        values: &mut Values,
    ) -> Result<(), Violation> {
        let c = self.columns.ok_or(Violation::Missing(self.input.codes))?;
        let bad = || Violation::from(Invalid::Column(c.mantissa));
        let (t, lo) = (self.input.log_rows, log2_ceil(self.plan.outputs));
        let ok = capture.scales.len() == self.plan.rows
            && capture.outputs.len() == self.plan.rows
            && capture.outputs.iter().all(|y| y.len() == self.plan.outputs);
        if !ok {
            return Err(bad());
        }
        let least = i64::from(self.input.least);
        let cap = i64::from(self.cap);
        let mut kept = vec![least.min(cap); 1 << t];
        let mut scale = vec![1i64 << (cap - least.min(cap)); 1 << t];
        let mut grow = vec![1i64 << (least - least.min(cap)); 1 << t];
        let mut z = vec![0i64; 1 << (t + lo)];
        for (i, (s, y)) in capture.scales.iter().zip(&capture.outputs).enumerate() {
            let a = match s[..] {
                [s] if s.is_power_of_two() => i64::from(s.trailing_zeros()),
                _ => return Err(bad()),
            };
            kept[i] = a.min(cap);
            scale[i] = 1 << (cap - kept[i]);
            grow[i] = 1 << (a - kept[i]);
            for (j, y) in y.iter().enumerate() {
                z[(i << lo) + j] = y >> (a - kept[i]);
            }
        }
        values.set(relation, c.mantissa, z)?;
        values.set(relation, c.scale, scale)?;
        if let (Some(k), Some(g)) = (c.kept, c.grow) {
            values.set(relation, k, kept)?;
            values.set(relation, g, grow)?;
        }
        Ok(())
    }
}

/// Executor values of one gated product: the unpadded `(tokens, hidden)` gate and up
/// projection outputs, row-major.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PowerGatedCapture {
    pub gate: Vec<i16>,
    pub up: Vec<i16>,
}

#[derive(Clone, Copy, Debug)]
struct GatedColumns {
    row: RowColumns,
    weight: ColumnId,
    silu: ColumnId,
    codes: ColumnId,
    hit: ColumnId,
    low: ColumnId,
    high: ColumnId,
}

/// The SiLU gated product `T = U * silu_q[G]` of one layer and its power-of-two row.
#[derive(Clone, Debug)]
pub struct PowerGated {
    prefix: String,
    gate: ColumnId,
    up: ColumnId,
    tokens: usize,
    hidden: usize,
    /// `silu_q[g]` at index `g + 32768`.
    silu: Vec<i64>,
    bits: u8,
    least: u8,
    most: u8,
    columns: Option<GatedColumns>,
}

impl PowerGated {
    /// `gate` and `up` are signed-16 columns of shape `(tokens, hidden)`; `table` is the
    /// block's `silu_q` component; `scale` is the policy's `b + 256*amin`.
    pub fn new(
        layer: usize,
        gate: ColumnId,
        up: ColumnId,
        tokens: usize,
        hidden: usize,
        table: &CqisTable,
        scale: u32,
    ) -> Result<Self, TableError> {
        let (bits, least) = ((scale & 255) as u8, scale >> 8);
        let entries = table.entries();
        if table.descriptor().name() != "silu_q"
            || entries.len() != 2 << 16
            || tokens == 0
            || !(1..=16384).contains(&hidden)
            || scale > 0xffff
            || !(4..=12).contains(&bits)
            || least > u32::from(29 - bits)
            || log2_ceil(tokens) + log2_ceil(hidden) > MAX_VARS
        {
            return Err(TableError::Parameters);
        }
        // Outputs within (-2^15, 2^15) keep |U * a| below 2^30.
        let silu = entries
            .chunks_exact(2)
            .enumerate()
            .map(|(i, row)| {
                let ok =
                    i64::from(row[0]) == i as i64 - 32768 && (-32767..=32767).contains(&row[1]);
                ok.then_some(i64::from(row[1])).ok_or(TableError::Shape)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            prefix: format!("L{layer}/gated"),
            gate,
            up,
            tokens,
            hidden,
            silu,
            bits,
            least: least as u8,
            most: 29 - bits,
            columns: None,
        })
    }

    fn logs(&self) -> (u8, u8) {
        (log2_ceil(self.tokens), log2_ceil(self.hidden))
    }

    /// The row the down projection reads; `None` before `declare`.
    pub fn output(&self) -> Option<PowerOutput> {
        let (log_rows, log_dimension) = self.logs();
        self.columns.map(|c| PowerOutput {
            codes: c.codes,
            exponent: c.row.exponent,
            log_rows,
            log_dimension,
            bits: self.bits,
            least: self.least,
            most: self.most,
        })
    }
}

impl Module for PowerGated {
    type Capture = PowerGatedCapture;

    fn declare(&mut self, relation: &mut Relation) {
        let (t, lh) = self.logs();
        let lanes = t + lh;
        let (tokens, hidden) = (self.tokens, self.hidden);
        let mask = (0..1usize << lanes)
            .map(|x| i64::from((x >> lh) < tokens && (x & ((1 << lh) - 1)) < hidden))
            .collect();
        let prefix = self.prefix.clone();
        let (least, most) = (self.least, self.most);
        let mut b = Builder::new(relation, &prefix);
        let mask = b.public("mask", mask, Width::unsigned(1), lanes);
        let row = row_columns(&mut b, t, least, most);
        let weight = b.column("split", Width::unsigned(SPLIT + 1), t);
        let table = b.relation.add_table(exponent_table(
            "split",
            least,
            most,
            Width::unsigned(SPLIT + 1),
            |a| 1 << split(a),
        ));
        let lookup = Lookup {
            name: format!("{prefix}/split/table"),
            vars: t,
            selector: None,
            tuple: vec![r(row.exponent, 0..t), r(weight, 0..t)],
            table,
        };
        b.relation.lookups.push(lookup);

        let lane = |c: ColumnId| r(c, 0..lanes);
        let of_row = |c: ColumnId| r(c, lh..lanes);
        let silu = b.column("silu", Width::signed(16), lanes);
        let table = b.relation.add_table(Table {
            name: "silu_q".into(),
            widths: vec![Width::signed(16), Width::signed(16)],
            rows: (0..1 << 16)
                .map(|i| vec![i as i64 - 32768, self.silu[i]])
                .collect(),
        });
        let lookup = Lookup {
            name: format!("{prefix}/silu"),
            vars: lanes,
            selector: None,
            tuple: vec![lane(self.gate), lane(silu)],
            table,
        };
        b.relation.lookups.push(lookup);
        let codes = b.column("codes", Width::signed(self.bits), lanes);
        let hit = b.column("hit", Width::unsigned(2), lanes);
        let low = b.column("low", Width::unsigned(SPLIT), lanes);
        let top = (least..=most).map(|a| a - split(a)).max().unwrap_or(1);
        let high = b.column("high", Width::unsigned(top.max(1)), lanes);
        // T + H = q*P + rho0 + W*rho1; every side stays below p (RFC-0026 §3.6).
        b.identity(
            "division",
            lanes,
            vec![
                term(1, vec![lane(mask), lane(silu), lane(self.up)]),
                term(1, vec![of_row(row.half)]),
                term(-1, vec![lane(codes), of_row(row.power)]),
                term(-1, vec![lane(low)]),
                term(-1, vec![of_row(weight), lane(high)]),
            ],
        );
        let table = b.relation.add_table(Table {
            name: format!("power/low/{least}..{most}"),
            widths: vec![Width::unsigned(5), Width::unsigned(SPLIT)],
            rows: (least..=most)
                .flat_map(|a| (0..1i64 << split(a)).map(move |v| vec![i64::from(a), v]))
                .collect(),
        });
        let lookup = Lookup {
            name: format!("{prefix}/low/table"),
            vars: lanes,
            selector: None,
            tuple: vec![of_row(row.exponent), lane(low)],
            table,
        };
        b.relation.lookups.push(lookup);
        let key = b.virtual_col(
            "key",
            Def::Linear {
                constant: 0,
                terms: vec![(4, of_row(row.exponent)), (1, lane(hit))],
            },
            lanes,
        );
        let table = b
            .relation
            .add_table(remainder_table("high", least, most, split));
        let lookup = Lookup {
            name: format!("{prefix}/high/table"),
            vars: lanes,
            selector: None,
            tuple: vec![lane(key), lane(high)],
            table,
        };
        b.relation.lookups.push(lookup);
        flags(
            &mut b,
            codes,
            hit,
            row.exponent,
            (t, lh),
            (self.bits, least, most),
        );
        self.columns = Some(GatedColumns {
            row,
            weight,
            silu,
            codes,
            hit,
            low,
            high,
        });
    }

    fn assign(
        &self,
        relation: &Relation,
        capture: &PowerGatedCapture,
        values: &mut Values,
    ) -> Result<(), Violation> {
        let c = self.columns.ok_or(Violation::Missing(self.gate))?;
        let bad = || Violation::from(Invalid::Column(c.codes));
        let (t, lh) = self.logs();
        let n = self.tokens * self.hidden;
        if capture.gate.len() != n || capture.up.len() != n {
            return Err(bad());
        }
        let size = 1usize << (t + lh);
        // Padding: the producer pins G = 0, so a = silu_q[0]; the mask pins T = 0.
        let mut silu = vec![self.silu[32768]; size];
        let (mut q, mut h) = (vec![0i64; size], vec![0i64; size]);
        let (mut low, mut high) = (vec![0i64; size], vec![0i64; size]);
        let mut exponents = vec![i64::from(self.least); 1 << t];
        let mut products = vec![0i64; self.hidden];
        for i in 0..self.tokens {
            for (j, product) in products.iter_mut().enumerate() {
                let k = i * self.hidden + j;
                let a = self.silu[(i64::from(capture.gate[k]) + 32768) as usize];
                silu[(i << lh) + j] = a;
                *product = i64::from(capture.up[k]) * a;
            }
            let a = exponent_of(&products, self.bits, self.least, self.most).ok_or_else(bad)?;
            exponents[i] = i64::from(a);
            let mut flagged = a == self.least;
            for (j, &x) in products.iter().enumerate() {
                let at = (i << lh) + j;
                q[at] = round(x, a);
                let rho = x + ((1i64 << a) >> 1) - (q[at] << a);
                low[at] = rho & ((1 << split(a)) - 1);
                high[at] = rho >> split(a);
                let f = flag(q[at], rho, a, self.bits);
                if !flagged && f != 0 {
                    h[at] = f;
                    flagged = true;
                }
            }
            if !flagged {
                return Err(bad());
            }
        }
        // Padded lanes and rows: T = 0, so q = 0 and the remainder is H.
        for at in 0..size {
            let (i, j) = (at >> lh, at & ((1 << lh) - 1));
            if i >= self.tokens || j >= self.hidden {
                let a = exponents[i] as u8;
                let rho = (1i64 << a) >> 1;
                low[at] = rho & ((1 << split(a)) - 1);
                high[at] = rho >> split(a);
            }
        }
        let power = exponents.iter().map(|a| 1i64 << a).collect();
        let half = exponents.iter().map(|a| (1i64 << a) >> 1).collect();
        let weight = exponents.iter().map(|a| 1i64 << split(*a as u8)).collect();
        for (id, column) in [
            (c.row.exponent, exponents),
            (c.row.power, power),
            (c.row.half, half),
            (c.weight, weight),
            (c.silu, silu),
            (c.codes, q),
            (c.hit, h),
            (c.low, low),
            (c.high, high),
        ] {
            values.set(relation, id, column)?;
        }
        Ok(())
    }
}

/// A row policy of either kind: scaled int8 codes, or a power-of-two row with the
/// policy scale `b + 256*amin`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RowPolicy {
    Scaled(Policy),
    Power(u32),
}

/// What a projection reads from a row of either kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RowRead {
    Scaled(RowOutput),
    Power(PowerOutput),
}

impl RowRead {
    /// The codes column.
    pub fn codes(self) -> ColumnId {
        match self {
            RowRead::Scaled(o) => o.codes,
            RowRead::Power(o) => o.codes,
        }
    }
}

/// A row conversion of either kind.
#[derive(Clone, Debug)]
pub enum AnyRow {
    Scaled(RowConversion),
    Power(PowerRow),
}

impl AnyRow {
    pub fn new(
        prefix: &str,
        input: ColumnId,
        rows: usize,
        dimension: usize,
        policy: RowPolicy,
    ) -> Result<Self, Unsupported> {
        Ok(match policy {
            RowPolicy::Scaled(p) => {
                AnyRow::Scaled(RowConversion::new(prefix, input, rows, dimension, p)?)
            }
            RowPolicy::Power(scale) => {
                AnyRow::Power(PowerRow::new(prefix, input, rows, dimension, scale)?)
            }
        })
    }

    /// What a projection reads; `None` before `declare`.
    pub fn output(&self) -> Option<RowRead> {
        match self {
            AnyRow::Scaled(m) => m.output().map(RowRead::Scaled),
            AnyRow::Power(m) => m.output().map(RowRead::Power),
        }
    }
}

impl Module for AnyRow {
    type Capture = ConversionCapture;

    fn declare(&mut self, relation: &mut Relation) {
        match self {
            AnyRow::Scaled(m) => m.declare(relation),
            AnyRow::Power(m) => m.declare(relation),
        }
    }

    fn assign(
        &self,
        relation: &Relation,
        capture: &ConversionCapture,
        values: &mut Values,
    ) -> Result<(), Violation> {
        match self {
            AnyRow::Scaled(m) => m.assign(relation, capture, values),
            AnyRow::Power(m) => m.assign(relation, capture, values),
        }
    }
}

/// A projection of a row of either kind.
pub enum AnyProjection {
    Scaled(Projection),
    Power(PowerProjection),
}

impl AnyProjection {
    pub fn new(
        prefix: &str,
        input: RowRead,
        weight: Option<ColumnId>,
        plan: ProjectionPlan,
    ) -> Result<Self, Unsupported> {
        Ok(match input {
            RowRead::Scaled(row) => {
                AnyProjection::Scaled(Projection::new(prefix, row, weight, plan)?)
            }
            RowRead::Power(row) => {
                AnyProjection::Power(PowerProjection::new(prefix, row, weight, plan)?)
            }
        })
    }

    /// The output column; `None` before `declare`.
    pub fn output(&self) -> Option<ColumnId> {
        match self {
            AnyProjection::Scaled(m) => m.output(),
            AnyProjection::Power(m) => m.output(),
        }
    }

    /// The weight column read (declared here unless one was supplied).
    pub fn weight(&self) -> Option<ColumnId> {
        match self {
            AnyProjection::Scaled(m) => m.weight(),
            AnyProjection::Power(m) => m.weight(),
        }
    }
}

impl Module for AnyProjection {
    type Capture = ProjectionCapture;

    fn declare(&mut self, relation: &mut Relation) {
        match self {
            AnyProjection::Scaled(m) => m.declare(relation),
            AnyProjection::Power(m) => m.declare(relation),
        }
    }

    fn assign(
        &self,
        relation: &Relation,
        capture: &ProjectionCapture,
        values: &mut Values,
    ) -> Result<(), Violation> {
        match self {
            AnyProjection::Scaled(m) => m.assign(relation, capture, values),
            AnyProjection::Power(m) => m.assign(relation, capture, values),
        }
    }
}

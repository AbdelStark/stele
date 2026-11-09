//! Residual add tests: executor-equivalent honest values, near misses, static shapes.

use super::*;
use stele_ir::relation::{check, check_except};

/// The executor's `residual` (stele-cqis execution/forward.rs: `numerics::scaled_sum`
/// with divisor 1) restated, before its int16 check (the executor returns
/// `Error::Range` outside int16).
fn reference(x: i64, y: i64, (fx, fy, fo): (u8, u8, u8)) -> i64 {
    let c = fx.max(fy).max(fo);
    let n = (i128::from(x) << (c - fx)) + (i128::from(y) << (c - fy));
    let d = 1u128 << (c - fo);
    let (q, r) = (n.unsigned_abs() / d, n.unsigned_abs() % d);
    let v = (q + u128::from(r >= d - r)) as i64;
    if n < 0 {
        -v
    } else {
        v
    }
}

fn int16(v: i64) -> bool {
    Width::signed(16).contains(v)
}

struct Case {
    relation: Relation,
    values: Values,
    module: Residual,
    inputs: [ColumnId; 2],
}

impl Case {
    fn column(&self, id: ColumnId) -> &[i64] {
        self.values.get(&self.relation, id).expect("column")
    }

    fn columns(&self) -> &ResidualColumns {
        self.module.columns().expect("declared")
    }

    fn with(&self, changes: &[(ColumnId, usize, i64)]) -> Values {
        let mut values = self.values.clone();
        for &(id, index, v) in changes {
            let mut column = values.get(&self.relation, id).expect("column").to_vec();
            column[index] = v;
            values.set(&self.relation, id, column).expect("set");
        }
        values
    }
}

/// Declare int16 inputs (padding 0, as their producers pin it) and the module, and
/// assign the executor's values, including an out-of-int16 quotient where the
/// executor overflows.
fn case(x: &[i64], y: &[i64], fractions: (u8, u8, u8), tokens: usize, width: usize) -> Case {
    let mut relation = Relation::default();
    let n = log2_ceil(tokens) + log2_ceil(width);
    let group = relation.add_group("L0/projection/test", n);
    let mut inputs = [ColumnId(0); 2];
    for (slot, name) in inputs.iter_mut().zip(["x", "y"]) {
        *slot = relation.add_column(name, Kind::Witness(group), Width::signed(16), n);
        relation.ranges.push(Range {
            name: name.into(),
            column: *slot,
            width: Width::signed(16),
        });
    }
    let (fx, fy, fo) = fractions;
    let mut module = Residual::new(
        0,
        "mid",
        (inputs[0], fx),
        (inputs[1], fy),
        fo,
        tokens,
        width,
    )
    .expect("plan");
    module.declare(&mut relation);
    let mut values = Values::new(&relation);
    let capture = ResidualCapture {
        left: x.to_vec(),
        right: y.to_vec(),
        output: x
            .iter()
            .zip(y)
            .map(|(a, b)| reference(*a, *b, fractions))
            .collect(),
    };
    for (id, input) in inputs.into_iter().zip([x, y]) {
        let mut padded = vec![0; 1 << n];
        for (index, v) in padded.iter_mut().enumerate() {
            if let Some((t, lane)) = module.entry(index) {
                *v = input[t * width + lane];
            }
        }
        values.set(&relation, id, padded).expect("input");
    }
    module
        .assign(&relation, &capture, &mut values)
        .expect("assign");
    Case {
        relation,
        values,
        module,
        inputs,
    }
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn fraction(&mut self) -> u8 {
        (self.next() % 31) as u8
    }
    fn input(&mut self, len: usize, extreme: bool) -> Vec<i64> {
        (0..len)
            .map(|_| {
                let v = match (extreme, self.next() % 4) {
                    (true, 0) => i16::MIN,
                    (true, 1) => i16::MAX,
                    (true, 2) => -1 - (self.next() % 4) as i16,
                    (_, 3) => (self.next() as i16) >> 12,
                    _ => (self.next() as i16) >> 3,
                };
                i64::from(v)
            })
            .collect()
    }
}

/// Every shape branch: exact (`m = 0`, `m > 0`, narrow), one-stage rounding (with and
/// without narrow copy, either input finest), two-stage rounding with `G` unsplit and
/// split, and the Llama fixture's `(23, 0, 5)`.
const FRACTIONS: [(u8, u8, u8); 14] = [
    (8, 8, 8),
    (8, 8, 12),
    (0, 16, 30),
    (12, 8, 9),
    (8, 12, 9),
    (0, 14, 1),
    (14, 0, 0),
    (10, 10, 4),
    (0, 30, 14),
    (30, 30, 16),
    (16, 0, 0),
    (23, 0, 5),
    (30, 28, 0),
    (20, 30, 0),
];

/// The plain checker accepts exactly the executor's non-overflowing outputs.
fn accepts(extreme: bool) {
    let mut rng = Rng(0x0e16_0009 + u64::from(extreme));
    let (mut accepted, mut overflowed) = (0, 0);
    let random: Vec<_> = (0..64)
        .map(|_| (rng.fraction(), rng.fraction(), rng.fraction()))
        .collect();
    for &fractions in FRACTIONS.iter().chain(&random) {
        for (tokens, width) in [(4, 8), (3, 6)] {
            let (x, y) = (
                rng.input(tokens * width, extreme),
                rng.input(tokens * width, extreme),
            );
            let case = case(&x, &y, fractions, tokens, width);
            let expected: Vec<_> = x
                .iter()
                .zip(&y)
                .map(|(a, b)| reference(*a, *b, fractions))
                .collect();
            if !expected.iter().all(|v| int16(*v)) {
                assert!(
                    check(&case.relation, &case.values).is_err(),
                    "overflow {fractions:?}"
                );
                overflowed += 1;
                continue;
            }
            assert_eq!(
                check(&case.relation, &case.values),
                Ok(()),
                "honest {fractions:?}"
            );
            let out = case.column(case.columns().output);
            for (index, v) in out.iter().enumerate() {
                let want = case
                    .module
                    .entry(index)
                    .map_or(0, |(t, lane)| expected[t * width + lane]);
                assert_eq!(*v, want, "output {index} {fractions:?}");
            }
            accepted += 1;
        }
    }
    assert!(accepted > FRACTIONS.len() && overflowed > 0);
}

#[test]
fn matches_reference_random_rows() {
    accepts(false);
}

#[test]
fn matches_reference_extreme_rows() {
    accepts(true);
}

/// Replace output entry `index` by `out` with the strongest assignment: stage-1 columns
/// stay (they do not depend on the output), and every stage-2 column is re-solved for
/// each `(β, ν)`; with `k = 0`, `S` is re-solved too. The checker must reject all.
fn rejects_output(case: &Case, index: usize, out: i64) {
    let c = case.columns();
    let Some(r) = c.rounding else {
        let mut changes = vec![(c.output, index, out)];
        if let Some(scaled) = c.auxiliary("scaled") {
            changes.push((scaled, index, out >> case.module.shape.m));
        }
        assert!(
            check(&case.relation, &case.with(&changes)).is_err(),
            "exact output {out}"
        );
        return;
    };
    let d = 1i64 << case.module.shape.k2();
    let get = |id| case.column(id)[index];
    let sticky = c.auxiliary("sticky").map_or(0, get);
    let t = (get(c.output) - get(r.half)) * d + get(r.low);
    for half in 0..2 {
        for negative in 0..2 {
            let low = t - (out - half) * d;
            let values = case.with(&[
                (c.output, index, out),
                (r.half, index, half),
                (r.negative, index, negative),
                (r.low, index, low),
                (r.twos, index, out - half + (negative << 16)),
                (
                    r.tie,
                    index,
                    (2 * half - 1) * (2 * low + sticky - d - negative) - (1 - half),
                ),
            ]);
            assert!(
                matches!(check(&case.relation, &values), Err(Violation::Range { .. })),
                "accepted output {out} at {index} with β={half} ν={negative}"
            );
        }
    }
}

#[test]
fn rejects_output_off_by_one() {
    let mut rng = Rng(77);
    for fractions in FRACTIONS {
        let (x, y) = (rng.input(32, false), rng.input(32, false));
        let mut case = case(&x, &y, fractions, 4, 8);
        if check(&case.relation, &case.values).is_err() {
            // Small inputs keep every shape in range.
            let small: Vec<_> = y.iter().map(|v| v >> 14).collect();
            case = self::case(&vec![0; 32], &small, fractions, 4, 8);
            check(&case.relation, &case.values).expect("honest");
        }
        let output = case.columns().output;
        for index in [0, 5, 17, 31] {
            let out = case.column(output)[index];
            rejects_output(&case, index, out + 1);
            rejects_output(&case, index, out - 1);
        }
    }
}

/// Exact ties: honest rounds away from zero, toward zero is rejected.
#[test]
fn rejects_other_rounding_direction_at_ties() {
    // (fractions, x, y): N = X + 4Y over 2; N = X + Y·2^16 over 2^16 (two-stage, the
    // tie needs the sticky bit 0).
    for (fractions, x, y) in [
        ((10, 8, 9), 1, 0),
        ((10, 8, 9), -1, 0),
        ((10, 8, 9), 5, 3),
        ((10, 8, 9), -5, -3),
        ((16, 0, 0), -(1 << 15), 0),
        ((16, 0, 0), -(1 << 15), 3),
        ((16, 0, 0), -(1 << 15), -3),
    ] {
        let case = case(&[x], &[y], fractions, 1, 1);
        check(&case.relation, &case.values).expect("honest tie");
        let out = case.column(case.columns().output)[0];
        let c = fractions.0;
        let n = (i128::from(x) << (c - fractions.0)) + (i128::from(y) << (c - fractions.1));
        let d = 1i128 << (c - fractions.2);
        assert_eq!(2 * n.rem_euclid(d), d, "the fixture is a tie");
        assert_eq!(
            2 * i128::from(out) * d,
            2 * n + n.signum() * d,
            "away from zero"
        );
        rejects_output(&case, 0, out - out.signum());
    }
}

/// Just past a negative tie the sticky bit decides: `N = −2^16 − 2^15 + 1` over `2^16`
/// rounds to −1. Claiming `st = 0` (which would give −2) is rejected.
#[test]
fn rejects_sticky_bit_lie() {
    let case = case(&[-(1 << 15) + 1], &[-1], (16, 0, 0), 1, 1);
    check(&case.relation, &case.values).expect("honest");
    let c = case.columns();
    assert_eq!(case.column(c.output)[0], -1);
    let (sticky, gap) = (
        c.auxiliary("sticky").expect("sticky"),
        c.auxiliary("gap").expect("gap"),
    );
    assert_eq!(case.column(sticky)[0], 1);
    let lie = case.with(&[(sticky, 0, 0), (gap, 0, 0)]);
    assert!(matches!(
        check(&case.relation, &lie),
        Err(Violation::Identity { .. })
    ));
}

fn read(case: &Case, values: &Values, id: ColumnId, index: usize) -> i64 {
    values.get(&case.relation, id).expect("column")[index]
}

fn write(case: &Case, values: &mut Values, id: ColumnId, index: usize, v: i64) {
    let mut column = values.get(&case.relation, id).expect("column").to_vec();
    column[index] = v;
    values.set(&case.relation, id, column).expect("set");
}

/// The attacker's completion: read `T` and `st` from the stage-1 columns as they stand
/// in `values` (not from the honest formulas), then set every later column so that
/// its own identities hold. `lie` takes `ν` against the sign identity while keeping
/// `tc` in range.
fn respond(case: &Case, values: &mut Values, index: usize, lie: bool) {
    let (shape, c) = (case.module.shape, case.columns());
    let at =
        |values: &Values, label: &str| c.auxiliary(label).map(|id| read(case, values, id, index));
    let (first, second) = case.module.ordered();
    let coarse = at(values, "narrow").unwrap_or_else(|| read(case, values, second, index));
    let f = read(case, values, first, index);
    let Some(r) = c.rounding else {
        let scaled = f + (coarse << shape.e);
        if let Some(id) = c.auxiliary("scaled") {
            write(case, values, id, index, scaled);
        }
        write(case, values, c.output, index, scaled << shape.m);
        return;
    };
    let (t, st) = match at(values, "first_high") {
        None => (f + (coarse << shape.e), 0),
        Some(fh) => {
            let rest = match (at(values, "second_high"), at(values, "carry")) {
                (Some(gh), Some(carry)) => gh + carry,
                _ => coarse << (shape.e - shape.s),
            };
            (fh + rest, at(values, "sticky").expect("sticky"))
        }
    };
    let d = 1i64 << shape.k2();
    let (high, low) = (t.div_euclid(d), t.rem_euclid(d));
    let truth = i64::from(high < 0);
    let negative = truth ^ i64::from(lie);
    let half = i64::from(2 * low + st >= d + negative);
    for (id, v) in [
        (c.output, high + half),
        (r.low, low),
        (r.half, half),
        (r.negative, negative),
        (r.twos, high + (truth << 16)),
        (
            r.tie,
            (2 * half - 1) * (2 * low + st - d - negative) - (1 - half),
        ),
    ] {
        write(case, values, id, index, v);
    }
}

/// Attacker assignments at one entry, each in range and aimed at one identity (named
/// by its label): every other relation it touches is re-satisfied by [`respond`].
fn attacks(case: &Case, index: usize) -> Vec<(&'static str, Values)> {
    let c = case.columns();
    let get = |id| read(case, &case.values, id, index);
    let mut out = Vec::new();
    let mut edit = |name: &'static str, changes: &[(ColumnId, i64)], complete: Option<bool>| {
        let mut values = case.values.clone();
        for &(id, v) in changes {
            write(case, &mut values, id, index, v);
        }
        if let Some(lie) = complete {
            respond(case, &mut values, index, lie);
        }
        out.push((name, values));
    };
    let o = get(c.output);
    match (c.rounding, c.auxiliary("scaled")) {
        (Some(r), _) => {
            let (b, flip) = (get(r.half), 1 - get(r.half));
            edit(
                "numerator",
                &[(c.output, o + 1), (r.twos, get(r.twos) + 1)],
                None,
            );
            edit(
                "round",
                &[(r.half, flip), (c.output, o + flip - b), (r.tie, 0)],
                None,
            );
            edit("sign", &[], Some(true));
        }
        (None, Some(scaled)) => {
            let m = case.module.shape.m;
            edit(
                "numerator",
                &[(scaled, get(scaled) + 1), (c.output, o + (1 << m))],
                None,
            );
            edit("scale", &[(c.output, o + 1)], None);
        }
        (None, None) => edit("numerator", &[(c.output, o + 1)], None),
    }
    // One step inside the column's own width.
    let bump = |id: ColumnId| {
        let v = get(id);
        if case.relation.columns[id.0 as usize].width.contains(v + 1) {
            v + 1
        } else {
            v - 1
        }
    };
    if c.auxiliary("narrow").is_some() {
        // The input moves while its narrow copy stays: only the copy identity sees it.
        let second = case.module.ordered().1;
        edit("copy", &[(second, bump(second))], None);
    }
    for (label, name) in [
        ("narrow", "copy"),
        ("first_high", "first"),
        ("second_high", "second"),
    ] {
        if let Some(id) = c.auxiliary(label) {
            edit(name, &[(id, bump(id))], Some(false));
        }
    }
    if let Some(carry) = c.auxiliary("carry") {
        edit("carry_sum", &[(carry, 1 - get(carry))], Some(false));
    }
    if let (Some(st), Some(gap)) = (c.auxiliary("sticky"), c.auxiliary("gap")) {
        let rest = c
            .auxiliary("rest")
            .or(c.auxiliary("first_low"))
            .map_or(0, get);
        let name = if rest > 0 {
            "sticky_zero"
        } else {
            "sticky_gap"
        };
        edit(name, &[(st, i64::from(rest == 0)), (gap, 0)], Some(false));
    }
    out
}

/// Padding attack: a nonzero input on a padding lane (an upstream that fails to pin
/// it), every module column completed consistently, keeping a nonzero output.
fn padding_attacks(case: &Case, index: usize) -> Vec<(&'static str, Values)> {
    let c = case.columns();
    let mut out = Vec::new();
    for v in [1, -1, 3, 16, -16, 1024, -32768] {
        for input in case.inputs {
            let mut values = case.values.clone();
            write(case, &mut values, input, index, v);
            let (first, second) = case.module.ordered();
            // Stage-1 columns of the new inputs; `respond` completes the rest.
            let row = case.module.solve(
                read(case, &values, first, index).into(),
                read(case, &values, second, index).into(),
                0,
            );
            let ids = core::iter::once(c.output).chain(c.auxiliary.iter().map(|a| a.1));
            for (id, v) in ids.zip(row) {
                let v = i64::try_from(v).expect("small");
                write(case, &mut values, id, index, v);
            }
            respond(case, &mut values, index, false);
            if read(case, &values, c.output, index) != 0 {
                out.push(("pad", values));
            }
        }
    }
    out
}

/// One stage-1 alternative: its column values, `T` and `st`.
type Alternative = (Vec<(ColumnId, i64)>, i64, i64);

/// In-range-elsewhere witnesses for each range: a search over the in-identity
/// alternatives of one real entry. Stage-1 splits move by whole multiples
/// (`F_h ± δ`, `F_l ∓ δ·2^s`, likewise `G`), the carry, sticky bit and gap follow
/// their identities, and stage 2 takes every `(H, β, ν)` near the honest one with `L`,
/// `out`, `tc`, `tie` from their identities. Each candidate satisfies every module
/// identity by construction; one that breaks exactly one range is kept.
fn range_candidates(case: &Case, index: usize) -> Vec<(&'static str, Row)> {
    let c = case.columns();
    let Some(r) = c.rounding else {
        return Vec::new();
    };
    let shape = case.module.shape;
    let get = |id| read(case, &case.values, id, index);
    let aux = |label: &str| c.auxiliary(label);
    let (first, second) = case.module.ordered();
    let (f, g) = (get(first), get(second));
    let s = shape.s;
    // (assignments, T, st) for every stage-1 alternative.
    let mut stage1: Vec<Alternative> = Vec::new();
    if s == 0 {
        stage1.push((Vec::new(), f + (g << shape.e), 0));
    } else {
        let (fh, fl) = (f.div_euclid(1 << s), f.rem_euclid(1 << s));
        for d1 in -2..=2 {
            let (fh, fl) = (fh + d1, fl - d1 * (1 << s));
            let mut splits = Vec::new();
            match (
                aux("second_high"),
                aux("second_low"),
                aux("carry"),
                aux("rest"),
            ) {
                (Some(gh_id), Some(gl_id), Some(k_id), Some(rest_id)) => {
                    let j = s - shape.e;
                    let (gh, gl) = (g.div_euclid(1 << j), g.rem_euclid(1 << j));
                    for d2 in -2..=2 {
                        let (gh, gl) = (gh + d2, gl - d2 * (1 << j));
                        for carry in -1..=2 {
                            let rest = fl + (gl << shape.e) - carry * (1 << s);
                            let cols =
                                vec![(gh_id, gh), (gl_id, gl), (k_id, carry), (rest_id, rest)];
                            splits.push((cols, fh + gh + carry, rest));
                        }
                    }
                }
                _ => splits.push((Vec::new(), fh + (g << (shape.e - s)), fl)),
            }
            for (cols, t, rest) in splits {
                for st in -1..=2 {
                    if rest != 0 && st != 1 {
                        continue;
                    }
                    let mut cols = cols.clone();
                    cols.extend([
                        (aux("first_high").expect("split"), fh),
                        (aux("first_low").expect("split"), fl),
                        (aux("sticky").expect("sticky"), st),
                        (aux("gap").expect("gap"), st * rest - st),
                    ]);
                    stage1.push((cols, t, st));
                }
            }
        }
    }
    let d = 1i64 << shape.k2();
    let honest = get(c.output) - get(r.half);
    let width = |id: ColumnId| case.relation.columns[id.0 as usize].width;
    let label = |id: ColumnId| {
        let name = &case.relation.columns[id.0 as usize].name;
        let label = &name[case.module.name.len() + 1..];
        [
            "out",
            "low",
            "half",
            "negative",
            "twos",
            "tie",
            "first_high",
            "first_low",
            "second_high",
            "second_low",
            "carry",
            "rest",
            "sticky",
            "gap",
        ]
        .into_iter()
        .find(|l| *l == label)
        .expect("label")
    };
    let mut found = Vec::new();
    for (cols, t, st) in &stage1 {
        for high in honest - 2..=honest + 2 {
            for half in -1..=2 {
                for negative in -1..=2 {
                    let low = t - high * d;
                    let mut row = cols.clone();
                    row.extend([
                        (c.output, high + half),
                        (r.low, low),
                        (r.half, half),
                        (r.negative, negative),
                        (r.twos, high + (negative << 16)),
                        (
                            r.tie,
                            (2 * half - 1) * (2 * low + st - d - negative) - (1 - half),
                        ),
                    ]);
                    let broken: Vec<_> = row
                        .iter()
                        .filter(|(id, v)| !width(*id).contains(*v))
                        .collect();
                    if let [(id, _)] = broken[..] {
                        found.push((label(*id), row));
                    }
                }
            }
        }
    }
    found
}

/// One entry's assignment: `(column, value)` pairs.
type Row = Vec<(ColumnId, i64)>;

fn apply(case: &Case, index: usize, row: &Row) -> Values {
    let mut values = case.values.clone();
    for &(id, v) in row {
        write(case, &mut values, id, index, v);
    }
    values
}

/// The first search witness per range label.
fn range_attacks(case: &Case, index: usize) -> Vec<(&'static str, Values)> {
    let mut out: Vec<(&'static str, Values)> = Vec::new();
    for (name, row) in range_candidates(case, index) {
        if !out.iter().any(|(n, _)| *n == name) {
            out.push((name, apply(case, index, &row)));
        }
    }
    out
}

/// The widen-by-one-bit variants of a range width: `signed(w+1)`, and for an unsigned
/// width also `unsigned(w+1)` and `signed(w+1)` (one more bit on either side).
fn widenings(width: Width) -> Vec<Width> {
    if width.signed {
        vec![Width::signed(width.bits + 1)]
    } else {
        vec![
            Width::unsigned(width.bits + 1),
            Width::signed(width.bits + 1),
        ]
    }
}

/// Plain-checker acceptance with range `index` evaluated at `width` instead of its
/// declared width: every other constraint by `check_except`, that range directly. A
/// 16-bit range widened to 17 bits is not a valid `Range` (RFC-0026 §3.4), so the
/// widened range is evaluated over Z rather than declared.
pub(crate) fn accepts_widened(
    relation: &Relation,
    values: &Values,
    index: usize,
    width: Width,
) -> bool {
    let range = &relation.ranges[index];
    check_except(relation, values, &[range.name.as_str()]).is_ok()
        && values
            .get(relation, range.column)
            .is_some_and(|c| c.iter().all(|&v| width.contains(v)))
}

/// Why a widened range admits no output-changing witness; `None` when one must exist.
fn widen_reason(label: &str, width: Width) -> Option<&'static str> {
    Some(match (label, width.signed) {
        ("negative", _) => "|out − β| <= 2^15 + 1 and tc = out − β + 2^16·ν ∈ [0, 2^16) force ν ∈ {0, 1} at any ν width",
        ("tie", false) => "only the sign of tie carries information: with L, st, ν, β in range, tie <= D2 < 2^(k2+1) already",
        ("first_high" | "second_high", true) => "F_h = (F − F_l)/2^s with F ∈ s16 and F_l ∈ u(s) is floor(F/2^s), already inside signed(16 − s) (likewise G_h)",
        ("first_low", true) => "F_l < 0 with F_h + 1: when F_l is ρ, st = 1 and gap = F_l − 1 < 0; otherwise κ − 1 absorbs the −2^s and T = F_h + G_h + κ is unchanged",
        ("second_low", _) => "moving 2^j between G_h and G_l moves ±2^s through carry_sum; κ absorbs it (T = F_h + G_h + κ unchanged) or ρ leaves its range",
        ("carry", _) => "carry_sum: F_l + 2^e·G_l ∈ [0, 2^(s+1)) and ρ ∈ [0, 2^s) leave only κ ∈ {0, 1}",
        ("rest", true) => "ρ < 0 is nonzero, so sticky_zero forces st = 1 and gap = ρ − 1 < 0",
        ("sticky", false) => "st >= 2 forces ρ = 0 (sticky_zero), then gap = −st < 0",
        ("gap", false) => "with st and ρ in range, gap = st·(ρ − 1) <= 2^s − 2: no reachable value above u(s)",
        ("narrow", true) => "copy forces G' = G; outside signed(w), |G·2^e'| >= 2^30 (2^16 when k = 0) puts out, tc or S out of range, so a wider G' only admits values every other range rejects",
        ("scaled", true) => "out = 2^m·S with out ∈ s16 bounds S to signed(16 − m) (S = 0 when m >= 16) at any S width",
        _ => return None,
    })
}

/// Widen-by-one-bit pass of one case: for every range of the module and every
/// widening, an attacker witness that the widened relation accepts, the true one
/// rejects, and that changes `out` at its entry (or is an executor overflow); or a
/// reason from [`widen_reason`]. Returns `(label, width, witness kind or reason)`.
fn widen_pass(
    case: &Case,
    extra: &[(&'static str, Values)],
) -> Vec<(String, Width, Option<&'static str>)> {
    let prefix = format!("{}/", case.module.name);
    let entries: Vec<_> = (0..1usize << case.module.log_len())
        .filter(|&i| case.module.entry(i).is_some())
        .map(|i| (i, range_candidates(case, i)))
        .collect();
    let output = case.columns().output;
    let mut table = Vec::new();
    for (index, range) in case.relation.ranges.iter().enumerate() {
        let Some(label) = range.name.strip_prefix(&prefix) else {
            continue;
        };
        for width in widenings(range.width) {
            let honest = |i: usize| read(case, &case.values, output, i);
            let search = entries.iter().find_map(|(i, candidates)| {
                candidates.iter().find_map(|(name, row)| {
                    let value = row.iter().find(|(id, _)| *id == range.column)?.1;
                    let changed = row.iter().any(|&(id, v)| id == output && v != honest(*i));
                    (*name == label && width.contains(value) && changed)
                        .then(|| apply(case, *i, row))
                })
            });
            let overflow = (label == "out")
                .then(|| extra.iter().find(|(n, _)| *n == "out").map(|e| e.1.clone()))
                .flatten();
            let witness = search.or(overflow).filter(|values| {
                check(&case.relation, values).is_err()
                    && accepts_widened(&case.relation, values, index, width)
            });
            let reason = widen_reason(label, width);
            assert!(
                witness.is_none() || reason.is_none(),
                "{label} {width:?}: reason given but a witness exists {:?}",
                case.module.shape
            );
            table.push((label.into(), width, witness.map(|_| "witness").or(reason)));
        }
    }
    table
}

/// Ranges no in-identity witness can break alone over Z, and why. Each is still
/// required: it disciplines its column (RFC-0026 §3.6 item 3), so the bound rule of
/// every identity reading it holds and no identity wraps modulo p.
fn redundant(label: &str, shape: Shape, overflows: bool) -> Option<&'static str> {
    Some(match label {
        "negative" => "ν = (tc − out + β)/2^16 with tc ∈ u16, out ∈ s16, β ∈ u1 forces ν ∈ {0, 1}",
        "narrow" => "G' = G; outside signed(w), |G'·2^e'| ≥ 2^30 (2^16 when k = 0) puts out, tc or S outside its range",
        "scaled" => "out = 2^m·S with out ∈ s16 gives S ∈ signed(16 − m) (signed 1 when m ≥ 15)",
        "first_high" => "F = 2^s·F_h + F_l with F ∈ s16 (upstream) and F_l ∈ u(s) gives F_h ∈ signed(16 − s)",
        "second_high" => "G = 2^j·G_h + G_l with G ∈ s16 and G_l ∈ u(j) gives G_h ∈ signed(16 − j)",
        "carry" => "2^s·κ = F_l + 2^e·G_l − ρ ∈ (−2^s, 2^(s+1)) with every term in range gives κ ∈ {0, 1}",
        "out" if shape.k == 0 && shape.m > 0 => "out = 2^m·S with S ∈ signed(16 − m) gives out ∈ s16",
        "out" if !overflows => "every other relation forces out = R(N/2^k), and |R(N/2^k)| < 2^15 for all int16 inputs of this shape",
        _ => return None,
    })
}

/// Whether some int16 inputs overflow the int16 output (the extremes suffice).
fn overflows(fractions: (u8, u8, u8)) -> bool {
    let ends = [i64::from(i16::MIN), i64::from(i16::MAX)];
    ends.iter()
        .any(|x| ends.iter().any(|y| !int16(reference(*x, *y, fractions))))
}

/// RFC-0026 §5.2 deletion survey of one case: for every constraint of the module, an
/// attacker witness that `check` rejects and `check_except([name])` accepts (it breaks
/// that constraint alone), or a reason from [`redundant`]; `None` when this shape
/// has neither (another shape must supply the witness). Returns `(label, witness)`.
fn survey(
    case: &Case,
    extra: &[(&'static str, Values)],
    overflows: bool,
) -> Vec<(String, Option<&'static str>)> {
    let mut attacks: Vec<_> = (0..1 << case.module.log_len())
        .flat_map(|i| {
            let mut all = self::attacks(case, i);
            if case.module.entry(i).is_none() {
                all.extend(padding_attacks(case, i));
            } else {
                all.extend(range_attacks(case, i));
            }
            all
        })
        .collect();
    attacks.extend(extra.iter().cloned());
    attacks.retain(|(_, values)| values != &case.values);
    // Every attack is a different assignment, so the complete relation must reject it:
    // deleting the constraint an attack alone breaks makes this fail.
    for (name, values) in &attacks {
        assert!(check(&case.relation, values).is_err(), "{name} accepted");
    }
    let prefix = format!("{}/", case.module.name);
    let names = case
        .relation
        .identities
        .iter()
        .map(|i| &i.name)
        .chain(case.relation.ranges.iter().map(|r| &r.name))
        .filter(|n| n.starts_with(&prefix));
    let mut table = Vec::new();
    for name in names {
        let label = &name[prefix.len()..];
        let witness = attacks
            .iter()
            .find(|(_, values)| check_except(&case.relation, values, &[name]).is_ok())
            .map(|(attack, _)| *attack);
        let reason = redundant(label, case.module.shape, overflows);
        assert!(
            witness.is_none() || reason.is_none(),
            "{name} is listed redundant but breaks alone {:?}",
            case.module.shape
        );
        // check rejects the witness; check_except([name]) accepts it.
        table.push((label.into(), witness.or(reason)));
    }
    table
}

/// An overflowing executor entry (`|out| ∈ [2^15, 2^16)`): every column of the
/// honest assignment satisfies its identity, and only `out`'s range rejects it.
fn overflow(fractions: (u8, u8, u8)) -> Option<Case> {
    let candidates = [
        32767, -32768, 16384, -16384, 8192, 1500, 1024, 128, 16, 3, -3, 2, 1,
    ];
    candidates
        .iter()
        .flat_map(|x| candidates.iter().map(move |y| (*x, *y)))
        .find_map(|(x, y)| {
            let out = reference(x, y, fractions);
            (!int16(out) && out.abs() < (1 << 16) - 2).then(|| case(&[x], &[y], fractions, 1, 1))
        })
}

/// `(fractions, x, y)` of one survey scenario.
type Scenario = ((u8, u8, u8), [i64; 6], [i64; 6]);

#[test]
fn rejects_each_constraint_removed() {
    // (fractions, x, y) on 2 tokens × 3 lanes (one padding lane per row).
    let scenarios: [Scenario; 8] = [
        // Exact positive tie with ρ = 0 in two stages (X = 0, Y = 2).
        ((16, 2, 0), [0, 4, -8, 0, 12, -4], [2, 0, 1, -2, 0, 3]),
        ((12, 8, 9), [1, -1, 3, -5, 100, -77], [0, 2, -3, 4, -6, 9]),
        (
            (0, 30, 14),
            [0, 1, -1, -1, 0, 1],
            [5, -6, 32767, -32768, 8, -1],
        ),
        (
            (30, 28, 13),
            [32764, -1, 0, -32768, 5, 4],
            [8193, 1, -1, -32768, 32767, 1],
        ),
        ((8, 8, 12), [1, -1, 3, -5, 100, -77], [0, 2, -3, 4, -6, 9]),
        ((0, 16, 30), [0; 6], [1, -2, 0, 1, -1, 0]),
        (
            (16, 0, 0),
            [-32768, -32767, 3, 4, 0, -1],
            [0, -1, 1, 0, -2, 0],
        ),
        ((23, 0, 5), [1, -8, 7, 16, -16, 0], [0, 1, -1, 2, 0, 0]),
    ];
    let mut covered: Vec<(String, Option<&str>)> = Vec::new();
    let mut wide: Vec<((String, bool), Option<&str>)> = Vec::new();
    for (fractions, x, y) in scenarios {
        let case = case(&x, &y, fractions, 2, 3);
        assert_eq!(check(&case.relation, &case.values), Ok(()));
        // The overflow entry, moved onto entry 0 of this case's layout.
        let mut extra = Vec::new();
        if let Some(over) = overflow(fractions) {
            let mut values = case.values.clone();
            for (id, column) in [over.inputs[0], over.inputs[1]]
                .into_iter()
                .zip(case.inputs)
                .chain(
                    core::iter::once(over.columns().output)
                        .chain(over.columns().auxiliary.iter().map(|a| a.1))
                        .chain(
                            over.columns()
                                .rounding
                                .into_iter()
                                .flat_map(|r| [r.low, r.half, r.negative, r.twos, r.tie]),
                        )
                        .zip(
                            core::iter::once(case.columns().output)
                                .chain(case.columns().auxiliary.iter().map(|a| a.1))
                                .chain(
                                    case.columns()
                                        .rounding
                                        .into_iter()
                                        .flat_map(|r| [r.low, r.half, r.negative, r.twos, r.tie]),
                                ),
                        ),
                )
            {
                write(&case, &mut values, column, 0, over.column(id)[0]);
            }
            extra.push(("out", values));
        }
        for (label, by) in survey(&case, &extra, overflows(fractions)) {
            let entry = match covered.iter().position(|(l, _)| *l == label) {
                Some(i) => &mut covered[i].1,
                None => {
                    covered.push((label, None));
                    &mut covered.last_mut().expect("pushed").1
                }
            };
            *entry = entry.or(by);
        }
        for (label, width, by) in widen_pass(&case, &extra) {
            let key = (label, width.signed);
            match wide.iter().position(|(k, _)| *k == key) {
                Some(i) => wide[i].1 = wide[i].1.or(by),
                None => wide.push((key, by)),
            }
        }
    }
    // Widen-by-one-bit: every (range, widening) has an output-changing witness in some
    // shape, or a stated reason it is safe.
    let unsafe_widenings: Vec<_> = wide.iter().filter(|(_, by)| by.is_none()).collect();
    assert!(unsafe_widenings.is_empty(), "{unsafe_widenings:?}");
    // No unexplained survivor: every constraint label breaks alone in some shape, or
    // its redundancy is stated by `redundant`.
    let survivors: Vec<_> = covered.iter().filter(|(_, by)| by.is_none()).collect();
    assert!(survivors.is_empty(), "{survivors:?}");
}

#[test]
fn rejects_nonzero_padding() {
    let mut rng = Rng(3);
    // Padded lanes and rows (3 × 6), and padded rows only (3 × 8, T not a power of two).
    for (tokens, width) in [(3, 6), (3, 8)] {
        for fractions in [(8, 8, 8), (12, 8, 9), (23, 0, 5)] {
            let (x, y) = (rng.input(tokens * width, false), vec![0; tokens * width]);
            let case = case(&x, &y, fractions, tokens, width);
            check(&case.relation, &case.values).expect("honest");
            let padding = (0..1 << case.module.log_len())
                .filter(|&i| case.module.entry(i).is_none())
                .collect::<Vec<_>>();
            for index in [padding[0], padding[padding.len() - 1]] {
                rejects_output(&case, index, 1);
                rejects_output(&case, index, -1);
                // A nonzero upstream value on padding, every column completed: only
                // the pad mask rejects it.
                let pad = format!("{}/pad", case.module.name);
                let attacks = padding_attacks(&case, index);
                assert!(attacks
                    .iter()
                    .all(|(_, v)| check(&case.relation, v).is_err()));
                assert!(attacks.iter().any(|(_, v)| check_except(
                    &case.relation,
                    v,
                    &[pad.as_str()]
                )
                .is_ok()));
            }
        }
    }
}

/// Every fraction triple in `[0, 30]^3` is a valid relation (RFC-0026 §3.6).
#[test]
fn accepts_static_validity_every_fraction_triple() {
    for fx in 0..=30 {
        for fy in 0..=30 {
            for fo in 0..=30 {
                let mut relation = Relation::default();
                let group = relation.add_group("L0/projection/test", 0);
                for name in ["x", "y"] {
                    let id = relation.add_column(name, Kind::Witness(group), Width::signed(16), 0);
                    relation.ranges.push(Range {
                        name: name.into(),
                        column: id,
                        width: Width::signed(16),
                    });
                }
                Residual::new(0, "mid", (ColumnId(0), fx), (ColumnId(1), fy), fo, 1, 1)
                    .expect("plan")
                    .declare(&mut relation);
                assert_eq!(relation.validate(), Ok(()), "({fx}, {fy}, {fo})");
            }
        }
    }
    assert!(Residual::new(0, "mid", (ColumnId(0), 31), (ColumnId(1), 0), 0, 1, 1).is_err());
}

/// The Llama-3.1-8B fixture's residual fractions validate at the E16-10 shapes, with
/// both adds of every layer sharing one group.
#[test]
fn accepts_static_validity_realistic_shapes() {
    let model = stele_cqis::model::Model::decode(include_bytes!(
        "../../../stele-cqis/tests/fixtures/original-llama-rotation-reference/model.bin"
    ))
    .expect("fixture Model");
    let width = usize::from(model.shape().width());
    for tokens in [64, 128] {
        let mut relation = Relation::default();
        let n = log2_ceil(tokens) + log2_ceil(width);
        let group = relation.add_group("L/projection/test", n);
        let input = |relation: &mut Relation, name: &str| {
            let id = relation.add_column(name, Kind::Witness(group), Width::signed(16), n);
            relation.ranges.push(Range {
                name: name.into(),
                column: id,
                width: Width::signed(16),
            });
            id
        };
        let (mut stream, mut incoming) = (input(&mut relation, "r0"), model.initial_fraction());
        for (layer, block) in model.blocks().iter().enumerate() {
            let f = block.projection_fractions();
            let (o, down) = (input(&mut relation, "o"), input(&mut relation, "down"));
            for (role, right, fo) in [
                ("mid", (o, f[3]), block.mid_fraction()),
                ("out", (down, f[f.len() - 1]), block.output_fraction()),
            ] {
                let mut residual =
                    Residual::new(layer, role, (stream, incoming), right, fo, tokens, width)
                        .expect("plan");
                residual.declare(&mut relation);
                stream = residual.columns().expect("declared").output;
                incoming = fo;
            }
        }
        relation.validate().expect("valid");
        assert_eq!(relation.groups.len(), 1 + model.blocks().len());
    }
}

/// Number after `key` in `text`.
fn number(text: &str, key: &str) -> usize {
    let start = text.find(key).expect("key") + key.len();
    let end = text[start..]
        .find(|c: char| !c.is_ascii_digit())
        .expect("end");
    text[start..start + end].parse().expect("number")
}

/// One executor fixture: the Model, its prefill capture, the tokens, the Scales and
/// the artifact bytes (weights).
pub(crate) struct Fixture {
    pub(crate) model: stele_cqis::model::Model,
    pub(crate) capture: stele_cqis::execution::Capture,
    pub(crate) tokens: Vec<u32>,
    pub(crate) scales: stele_cqis::model::Scales,
    pub(crate) artifact: &'static [u8],
}

/// `Executor::capture` of every successful family-1 version-1 case of the stele-cqis
/// `model-execution` fixtures (the byte spans are read directly, without JSON).
pub(crate) fn executor_captures() -> Vec<Fixture> {
    use stele_cqis::execution::Executor;
    use stele_cqis::model::{Model, Preparation, Scales};
    let json = include_str!("../../../stele-cqis/tests/fixtures/model-execution.json");
    const RAW: &[u8] = include_bytes!("../../../stele-cqis/tests/fixtures/model-execution.bin");
    let span = |case: &str, key: &str| -> &'static [u8] {
        let at = &case[case.find(&format!("\"{key}\":{{")).expect("span")..];
        let offset = number(at, "\"offset\":");
        &RAW[offset..offset + number(at, "\"length\":")]
    };
    let mut out = Vec::new();
    for case in json.split("{\"model\":").skip(1) {
        let case = &format!("\"model\":{case}");
        if !case.contains("\"expected\":{\"cuts\"") {
            continue;
        }
        let model = Model::decode(span(case, "model")).expect("Model");
        if model.shape().family() != 1 || model.wide() {
            continue;
        }
        let prep = Preparation::decode(&model, span(case, "preparation")).expect("Preparation");
        let scales = Scales::decode(&model, span(case, "scales")).expect("Scales");
        let at = case.find("\"artifact_id\":\"").expect("id") + 15;
        let id: [u8; 32] = core::array::from_fn(|i| {
            u8::from_str_radix(&case[at + 2 * i..at + 2 * i + 2], 16).expect("hex")
        });
        let at = case.find("\"tokens\":[").expect("tokens") + 10;
        let tokens: Vec<u32> = case[at..at + case[at..].find(']').expect("]")]
            .split(',')
            .map(|t| t.parse().expect("token"))
            .collect();
        let capture = Executor::new(&model, &prep, &scales, span(case, "artifact"), &id, 1 << 30)
            .expect("load")
            .capture(&tokens)
            .expect("capture");
        let artifact = span(case, "artifact");
        out.push(Fixture {
            model,
            capture,
            tokens,
            scales,
            artifact,
        });
    }
    assert!(!out.is_empty(), "family-1 fixtures");
    out
}

/// Every residual add of every family-1 fixture, from `Executor::capture`: the
/// executor's inputs and quotients pass the plain checker, and the quotient ±1 with
/// the strongest re-solved rounding columns does not.
#[test]
fn matches_executor_capture_fixtures() {
    use stele_cqis::execution::capture::Block;
    for crate::residual::tests::Fixture {
        model,
        capture,
        tokens,
        ..
    } in executor_captures()
    {
        let (t, width) = (tokens.len(), usize::from(model.shape().width()));
        let cut = |layer: usize| -> Vec<i64> {
            capture.full().cuts()[layer]
                .iter()
                .flatten()
                .map(|v| i64::from(*v))
                .collect()
        };
        let (mut stream, mut incoming) = (cut(0), model.initial_fraction());
        for (layer, block) in model.blocks().iter().enumerate() {
            let rows = &capture.blocks[layer];
            let flat = |pick: fn(&Block) -> &Vec<i64>| -> Vec<i64> {
                rows.iter().flat_map(|b| pick(b).iter().copied()).collect()
            };
            let f = block.projection_fractions();
            let adds = [
                (
                    flat(|b| &b.output.output.quotient),
                    f[3],
                    flat(|b| &b.mid.quotient),
                    block.mid_fraction(),
                ),
                (
                    flat(|b| &b.down.output.quotient),
                    f[f.len() - 1],
                    flat(|b| &b.residual.quotient),
                    block.output_fraction(),
                ),
            ];
            for (right, fy, output, fo) in adds {
                let case = case(&stream, &right, (incoming, fy, fo), t, width);
                assert_eq!(check(&case.relation, &case.values), Ok(()), "layer {layer}");
                let column = case.column(case.columns().output);
                for (index, v) in column.iter().enumerate() {
                    let want = case
                        .module
                        .entry(index)
                        .map_or(0, |(t, lane)| output[t * width + lane]);
                    assert_eq!(*v, want, "layer {layer} entry {index}");
                }
                for index in [0, column.len() / 2] {
                    let out = column[index];
                    rejects_output(&case, index, out + 1);
                    rejects_output(&case, index, out - 1);
                }
                (stream, incoming) = (output, fo);
            }
            assert_eq!(stream, cut(layer + 1), "R_{} is the cut", layer + 1);
        }
    }
}

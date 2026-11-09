//! Row conversion and projection: honest executor values pass the plain checker,
//! RFC-0026 §5.2 near misses fail it, and realistic plans pass the bound rule.

use super::*;
use stele_cqis::bounds::arithmetic::Row;
use stele_cqis::row::Quantiser;
use stele_ir::relation::{check, Module, Relation, Values, Violation};

/// Deterministic test stream (xorshift64*); not a protocol RNG.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn range(&mut self, low: i64, high: i64) -> i64 {
        low + (self.next() % (high - low + 1) as u64) as i64
    }
}

fn mode(policy: Policy) -> (u8, u32) {
    match policy {
        Policy::Dynamic => (0, 0),
        Policy::Static(s) => (1, s),
        Policy::Grouped(g) => (2, g),
    }
}

/// Executor conversion of `inputs` (RFC-0025 §2.2), or `None` if it rejects.
fn convert(policy: Policy, inputs: &[Vec<i64>]) -> Option<ConversionCapture> {
    let (policy_mode, scale) = mode(policy);
    let quantiser = Quantiser::new(Row {
        dimension: inputs[0].len() as u16,
        kind: 0,
        fraction: 8,
        policy: policy_mode,
        scale,
    })
    .expect("row parameters");
    let mut capture = ConversionCapture {
        inputs: inputs.to_vec(),
        ..ConversionCapture::default()
    };
    for row in inputs {
        let narrow: Vec<i16> = row.iter().map(|&v| v as i16).collect();
        let out = quantiser.convert_wide(&narrow).ok()?;
        capture
            .codes
            .push(out.codes().iter().map(|&c| i64::from(c)).collect());
        capture.scales.push(out.scales().to_vec());
    }
    Some(capture)
}

/// Executor-equivalent affine output (stele_cqis execution `Data::affine`, family 1,
/// no bias): `R(V*m*u*2^l)`, ties away from zero, int16 or `None`.
fn affine(
    capture: &ConversionCapture,
    weights: &[Vec<i64>],
    m: &[u16],
    shift: i32,
) -> Option<Vec<Vec<i64>>> {
    let mut out = Vec::new();
    for (codes, scales) in capture.codes.iter().zip(&capture.scales) {
        let g = codes.len() / scales.len();
        let mut row = Vec::new();
        for (w, mj) in weights.iter().zip(m) {
            let v: i128 = if scales.len() > 1 {
                codes
                    .iter()
                    .zip(w)
                    .enumerate()
                    .map(|(i, (c, w))| i128::from(scales[i / g]) * i128::from(c * w))
                    .sum()
            } else {
                i128::from(scales[0])
                    * codes
                        .iter()
                        .zip(w)
                        .map(|(c, w)| i128::from(c * w))
                        .sum::<i128>()
            };
            let p = v * i128::from(*mj);
            // |p| < 2^90, so shifts beyond 100 are exact zeros or overflow.
            let y = if p == 0 {
                0
            } else if shift >= 0 {
                p.checked_mul(1i128.checked_shl(shift.min(120) as u32)?)?
            } else {
                let k = (-shift).min(100);
                p.signum() * ((p.abs() + (1 << (k - 1))) >> k)
            };
            row.push(i64::from(i16::try_from(y).ok()?));
        }
        out.push(row);
    }
    Some(out)
}

struct Setup {
    relation: Relation,
    values: Values,
    conversion: RowConversion,
    projection: Projection,
    rows: ConversionCapture,
    capture: ProjectionCapture,
    input: stele_ir::relation::ColumnId,
}

fn padded(rows: &[Vec<i64>], log_rows: u8, log_lanes: u8) -> Vec<i64> {
    let mut out = vec![0; 1 << (log_rows + log_lanes)];
    for (r, row) in rows.iter().enumerate() {
        for (i, v) in row.iter().enumerate() {
            out[(r << log_lanes) | i] = *v;
        }
    }
    out
}

/// Random rows of mixed magnitude, a random int8/int4 weight, and a shift that
/// keeps the executor's outputs inside int16.
fn setup(rows: usize, d: usize, o: usize, policy: Policy, bits: u8, seed: u64) -> Setup {
    let mut rng = Rng(seed);
    let inputs: Vec<Vec<i64>> = loop {
        let inputs: Vec<Vec<i64>> = (0..rows)
            .map(|r| {
                let cap = match policy {
                    Policy::Static(s) => 127 * i64::from(s),
                    _ => 32767,
                };
                let peak = [0, 1, 300, 32767, 4000][(r + seed as usize) % 5].min(cap);
                let mut row: Vec<i64> = (0..d).map(|_| rng.range(-peak, peak)).collect();
                if r % 5 == 3 && cap == 32767 {
                    row[d / 2] = -32768;
                }
                row
            })
            .collect();
        if convert(policy, &inputs).is_some() {
            break inputs;
        }
    };
    let rows_capture = convert(policy, &inputs).expect("converted");
    let w_max = (1 << (bits - 1)) - 1;
    let weights: Vec<Vec<i64>> = (0..o)
        .map(|_| (0..d).map(|_| rng.range(-w_max, w_max)).collect())
        .collect();
    let m: Vec<u16> = (0..o).map(|_| rng.range(1, 65535) as u16).collect();
    let shift = (-60..=4)
        .rev()
        .find(|&l| affine(&rows_capture, &weights, &m, l).is_some())
        .expect("fitting shift");
    let outputs = affine(&rows_capture, &weights, &m, shift).expect("outputs");
    build(rows_capture, weights, m, shift, policy, bits, outputs)
}

fn build(
    rows_capture: ConversionCapture,
    weights: Vec<Vec<i64>>,
    m: Vec<u16>,
    shift: i32,
    policy: Policy,
    bits: u8,
    outputs: Vec<Vec<i64>>,
) -> Setup {
    let (rows, d, o) = (
        rows_capture.inputs.len(),
        rows_capture.inputs[0].len(),
        weights.len(),
    );
    let (t, ld, lo) = (log2_ceil(rows), log2_ceil(d), log2_ceil(o));
    let mut relation = Relation::default();
    let input = Builder::new(&mut relation, "L0/norm").witness("output", Width::signed(16), t + ld);
    let mut conversion = RowConversion::new("L0/row", input, rows, d, policy).expect("row plan");
    conversion.declare(&mut relation);
    let plan = ProjectionPlan {
        rows,
        inner: d,
        outputs: o,
        weight_bits: bits,
        mantissas: m,
        shift,
    };
    let mut projection = Projection::new(
        "L0/query",
        conversion.output().expect("declared"),
        None,
        plan,
    )
    .expect("projection plan");
    projection.declare(&mut relation);
    let capture = ProjectionCapture {
        codes: rows_capture.codes.clone(),
        scales: rows_capture.scales.clone(),
        weights: weights.clone(),
        outputs,
    };
    let mut values = Values::new(&relation);
    values
        .set(&relation, input, padded(&rows_capture.inputs, t, ld))
        .expect("input");
    let weight = projection.weight().expect("weight");
    values
        .set(&relation, weight, padded(&weights, lo, ld))
        .expect("weight");
    conversion
        .assign(&relation, &rows_capture, &mut values)
        .expect("row assign");
    projection
        .assign(&relation, &capture, &mut values)
        .expect("projection assign");
    Setup {
        relation,
        values,
        conversion,
        projection,
        rows: rows_capture,
        capture,
        input,
    }
}

impl Setup {
    fn check(&self) -> Result<(), Violation> {
        check(&self.relation, &self.values)
    }
    /// Reassign every witness from (possibly tampered) captures: the strongest
    /// auxiliary assignment the modules derive for those outputs.
    fn reassign(&mut self) -> Result<(), Violation> {
        self.conversion
            .assign(&self.relation, &self.rows, &mut self.values)?;
        self.capture.codes = self.rows.codes.clone();
        self.capture.scales = self.rows.scales.clone();
        self.projection
            .assign(&self.relation, &self.capture, &mut self.values)?;
        check(&self.relation, &self.values)
    }
}

const POLICIES: [Policy; 4] = [
    Policy::Dynamic,
    Policy::Static(7),
    Policy::Static(300),
    Policy::Grouped(8),
];

#[test]
fn accepts_honest_conversion_and_projection() {
    for (k, policy) in POLICIES.into_iter().enumerate() {
        for (rows, d, o, bits) in [(5, 24, 6, 8), (4, 32, 8, 4), (1, 16, 3, 8)] {
            let s = setup(rows, d, o, policy, bits, 1 + k as u64);
            assert_eq!(s.check(), Ok(()), "{policy:?} {rows}x{d}x{o} int{bits}");
        }
    }
}

#[test]
fn accepts_honest_projection_with_left_shift() {
    // l >= 0: Y = V*m*s*2^l exactly, including l mod 8 != 0 and l >= 8.
    let rows = convert(Policy::Static(1), &[vec![3, -2, 1, 0]]).expect("row");
    let weights = vec![vec![1, 1, 0, 0], vec![1, 0, 0, 0]];
    for shift in [0, 3, 9] {
        let m = vec![1, 3];
        let outputs = affine(&rows, &weights, &m, shift).expect("fits");
        let s = build(
            rows.clone(),
            weights.clone(),
            m,
            shift,
            Policy::Static(1),
            8,
            outputs,
        );
        assert_eq!(s.check(), Ok(()), "l = {shift}");
    }
}

#[test]
fn accepts_extreme_shifts_and_rejects_their_near_misses() {
    // l = -200: every admissible product rounds to 0. l = 300: only V = 0 fits int16.
    let rows = convert(Policy::Dynamic, &[vec![32767, -5, 9, 0]]).expect("row");
    let weights = vec![vec![127, 127, -127, 3], vec![0, 0, 0, 0]];
    for shift in [-200, 300] {
        let m = vec![65535, 7];
        let outputs = if shift < 0 {
            vec![vec![0, 0]]
        } else {
            let mut zero = weights.clone();
            zero[0] = vec![0; 4];
            let s = build(
                rows.clone(),
                zero,
                m.clone(),
                shift,
                Policy::Dynamic,
                8,
                vec![vec![0, 0]],
            );
            assert_eq!(s.check(), Ok(()));
            continue;
        };
        let mut s = build(
            rows.clone(),
            weights.clone(),
            m,
            shift,
            Policy::Dynamic,
            8,
            outputs,
        );
        assert_eq!(s.check(), Ok(()));
        s.capture.outputs[0][0] = 1;
        assert!(s.reassign().is_err());
    }
    // l = 300 with V != 0: the executor rejects (int16 overflow), and so do the relations.
    let s = build(
        rows,
        weights,
        vec![1, 1],
        300,
        Policy::Dynamic,
        8,
        vec![vec![0, 0]],
    );
    assert!(s.check().is_err());
}

fn first_nonzero(rows: &[Vec<i64>]) -> (usize, usize) {
    rows.iter()
        .enumerate()
        .find_map(|(r, row)| row.iter().position(|&c| c != 0).map(|i| (r, i)))
        .expect("a nonzero entry")
}

#[test]
fn rejects_code_off_by_one() {
    for (k, policy) in POLICIES.into_iter().enumerate() {
        for delta in [-1, 1] {
            let mut s = setup(5, 24, 6, policy, 8, 10 + k as u64);
            assert_eq!(s.check(), Ok(()));
            let (r, i) = first_nonzero(&s.rows.codes);
            s.rows.codes[r][i] += delta;
            assert!(s.reassign().is_err(), "{policy:?} code {delta:+}");
        }
    }
}

#[test]
fn rejects_code_other_rounding_direction() {
    // max 254 -> s = 2; 3/2 = 1.5 rounds away to 2 (floor 1); -3 -> -2 (ceil -1).
    let inputs = vec![vec![254, 3, -3, 1, -1, 0, 5, -5]];
    let honest = convert(Policy::Dynamic, &inputs).expect("row");
    assert_eq!(honest.codes[0], vec![127, 2, -2, 1, -1, 0, 3, -3]);
    for (lane, other) in [(1, 1), (2, -1), (3, 0), (4, 0), (6, 2), (7, -2)] {
        let mut s = build(
            honest.clone(),
            vec![vec![0; 8]],
            vec![1],
            0,
            Policy::Dynamic,
            8,
            vec![vec![0]],
        );
        assert_eq!(s.check(), Ok(()));
        s.rows.codes[0][lane] = other;
        assert!(s.reassign().is_err(), "lane {lane} code {other}");
    }
}

/// Codes for `inputs` under a given (possibly wrong) scale, rounded honestly.
fn codes_for(inputs: &[i64], s: u32) -> Vec<i64> {
    inputs
        .iter()
        .map(|&x| {
            let q = if s == 0 {
                0
            } else {
                (2 * x.abs() + i64::from(s)) / (2 * i64::from(s))
            };
            x.signum() * q
        })
        .collect()
}

#[test]
fn rejects_scale_off_by_one_with_consistent_codes() {
    for (k, policy) in [Policy::Dynamic, Policy::Grouped(8)]
        .into_iter()
        .enumerate()
    {
        for delta in [-1i64, 1] {
            let mut s = setup(5, 24, 6, policy, 8, 20 + k as u64);
            assert_eq!(s.check(), Ok(()));
            let r = s
                .rows
                .scales
                .iter()
                .position(|row| row[0] > 1)
                .expect("scaled row");
            let wrong = (i64::from(s.rows.scales[r][0]) + delta) as u32;
            s.rows.scales[r][0] = wrong;
            let g = 24 / s.rows.scales[r].len();
            let lanes = &s.rows.inputs[r][..g];
            let codes = codes_for(lanes, wrong);
            s.rows.codes[r][..g].copy_from_slice(&codes);
            assert!(s.reassign().is_err(), "{policy:?} scale {delta:+}");
        }
    }
}

#[test]
fn rejects_ceiling_near_miss_at_multiples_of_127() {
    // M = 127*3 exactly: s = 3, not 4. M = 127*3 + 1: s = 4, not 3.
    for (peak, honest, wrong) in [(381, 3, 4), (382, 4, 3)] {
        let inputs = vec![vec![peak, -7, 100, 0]];
        let capture = convert(Policy::Dynamic, &inputs).expect("row");
        assert_eq!(capture.scales[0], vec![honest]);
        let mut s = build(
            capture,
            vec![vec![0; 4]],
            vec![1],
            0,
            Policy::Dynamic,
            8,
            vec![vec![0]],
        );
        assert_eq!(s.check(), Ok(()));
        s.rows.scales[0][0] = wrong;
        s.rows.codes[0] = codes_for(&inputs[0], wrong);
        assert!(
            matches!(s.reassign(), Err(Violation::Lookup { relation, .. }) if relation == "L0/row/ceiling"),
            "peak {peak} scale {wrong}"
        );
    }
}

#[test]
fn rejects_zero_row_branch_near_misses() {
    let inputs = vec![vec![0; 4], vec![5, 0, 0, 0]];
    let capture = convert(Policy::Dynamic, &inputs).expect("rows");
    assert_eq!(capture.scales, vec![vec![0], vec![1]]);
    let honest = build(
        capture,
        vec![vec![1; 4]],
        vec![1],
        0,
        Policy::Dynamic,
        8,
        vec![vec![0], vec![5]],
    );
    assert_eq!(honest.check(), Ok(()));
    let zero = honest.conversion.zero().expect("dynamic");

    // Zero row with scale 1 (z = 0): the ceiling rejects 127*1 - 0 = 127.
    let mut s = build(
        honest.rows.clone(),
        vec![vec![1; 4]],
        vec![1],
        0,
        Policy::Dynamic,
        8,
        vec![vec![0], vec![5]],
    );
    s.rows.scales[0][0] = 1;
    assert!(s.reassign().is_err());

    // Zero row, z cleared: the divisor s + z = 0 leaves no remainder range.
    let mut s = build(
        honest.rows.clone(),
        vec![vec![1; 4]],
        vec![1],
        0,
        Policy::Dynamic,
        8,
        vec![vec![0], vec![5]],
    );
    let mut z = s.values.get(&s.relation, zero).expect("z").to_vec();
    z[0] = 0;
    s.values.set(&s.relation, zero, z).expect("z");
    assert!(s.check().is_err());

    // Nonzero row claiming the zero branch: z*M = 0 rejects.
    let mut s = build(
        honest.rows.clone(),
        vec![vec![1; 4]],
        vec![1],
        0,
        Policy::Dynamic,
        8,
        vec![vec![0], vec![5]],
    );
    let mut z = s.values.get(&s.relation, zero).expect("z").to_vec();
    z[1] = 1;
    s.values.set(&s.relation, zero, z).expect("z");
    assert!(s.check().is_err());

    // Zero row with a nonzero code: z*q = 0 rejects.
    let mut s = build(
        honest.rows,
        vec![vec![1; 4]],
        vec![1],
        0,
        Policy::Dynamic,
        8,
        vec![vec![1], vec![5]],
    );
    s.rows.codes[0][0] = 1;
    assert!(s.reassign().is_err());
}

#[test]
fn rejects_projection_output_off_by_one_and_other_rounding() {
    for (k, policy) in POLICIES.into_iter().enumerate() {
        let base = setup(5, 24, 6, policy, 8, 30 + k as u64);
        for (r, j) in [(0, 0), (1, 2), (4, 5), (3, 1)] {
            for delta in [-1, 1] {
                let mut s = setup(5, 24, 6, policy, 8, 30 + k as u64);
                assert_eq!(s.check(), Ok(()));
                s.capture.outputs[r][j] += delta;
                assert!(s.reassign().is_err(), "{policy:?} Y[{r}][{j}] {delta:+}");
            }
            // The other rounding direction of the exact quotient (toward zero vs away).
            let honest = base.capture.outputs[r][j];
            let mut s = setup(5, 24, 6, policy, 8, 30 + k as u64);
            s.capture.outputs[r][j] = if honest > 0 { honest - 1 } else { honest + 1 };
            assert!(s.reassign().is_err());
        }
    }
}

#[test]
fn rejects_projection_tie_rounded_toward_zero() {
    // V*m = 3 at l = -1: 1.5 rounds away to 2; 1 (toward zero) must fail. Likewise -1.5.
    let rows = convert(Policy::Static(1), &[vec![3, 0], vec![-3, 0]]).expect("rows");
    let outputs = affine(&rows, &[vec![1, 0]], &[1], -1).expect("fits");
    assert_eq!(outputs, vec![vec![2], vec![-2]]);
    let mut s = build(
        rows,
        vec![vec![1, 0]],
        vec![1],
        -1,
        Policy::Static(1),
        8,
        outputs,
    );
    assert_eq!(s.check(), Ok(()));
    for (r, toward_zero) in [(0, 1), (1, -1)] {
        let honest = s.capture.outputs[r][0];
        s.capture.outputs[r][0] = toward_zero;
        assert!(s.reassign().is_err());
        s.capture.outputs[r][0] = honest;
    }
    assert_eq!(s.reassign(), Ok(()));
}

#[test]
fn rejects_nonzero_padding() {
    let mut s = setup(3, 24, 6, Policy::Dynamic, 8, 40);
    let output = s.projection.output().expect("declared");
    let mut y = s.values.get(&s.relation, output).expect("Y").to_vec();
    let padded = y.len() - 1;
    y[padded] = 1;
    s.values.set(&s.relation, output, y).expect("Y");
    assert!(s.check().is_err());
    let mut s = setup(3, 24, 6, Policy::Dynamic, 8, 40);
    let codes = s.conversion.output().expect("declared").codes;
    let mut c = s.values.get(&s.relation, codes).expect("codes").to_vec();
    c[30] = 1; // row 0, padded lane 30 >= 24
    s.values.set(&s.relation, codes, c).expect("codes");
    assert!(s.check().is_err());
    // A padded input lane is ignored: the honest witness still passes.
    let mut s = setup(3, 24, 6, Policy::Dynamic, 8, 40);
    let mut x = s.values.get(&s.relation, s.input).expect("x").to_vec();
    x[30] = 12345;
    s.values.set(&s.relation, s.input, x).expect("x");
    assert_eq!(s.check(), Ok(()));
}

/// Declare a conversion and its projection with no values and validate them.
fn validate(
    rows: usize,
    d: usize,
    o: usize,
    policy: Policy,
    bits: u8,
) -> Result<(), stele_ir::relation::Invalid> {
    let mut relation = Relation::default();
    let input = Builder::new(&mut relation, "L0/norm").witness(
        "output",
        Width::signed(16),
        log2_ceil(rows) + log2_ceil(d),
    );
    let mut conversion = RowConversion::new("L0/row", input, rows, d, policy).expect("row plan");
    conversion.declare(&mut relation);
    let plan = ProjectionPlan {
        rows,
        inner: d,
        outputs: o,
        weight_bits: bits,
        mantissas: vec![65535; o],
        shift: -40,
    };
    let mut projection =
        Projection::new("L0/q", conversion.output().expect("declared"), None, plan).expect("plan");
    projection.declare(&mut relation);
    relation.validate()
}

#[test]
fn accepts_realistic_shapes_under_the_bound_rule() {
    for (rows, d, o, policy, bits) in [
        (64, 4096, 4096, Policy::Dynamic, 8),
        (64, 4096, 4096, Policy::Grouped(128), 8),
        (64, 512, 1536, Policy::Static(65535), 4),
        (32, 8192, 2048, Policy::Dynamic, 8),
        (16, 8192, 128, Policy::Grouped(128), 8),
        (16, 14336, 128, Policy::Dynamic, 8),
    ] {
        assert_eq!(
            validate(rows, d, o, policy, bits),
            Ok(()),
            "{rows}x{d}x{o} {policy:?}"
        );
    }
}

#[test]
fn accepts_gated_scale_bound_under_the_bound_rule() {
    // Down projection after a gated conversion (scale up to 8454661, RFC-0004 A8).
    let mut relation = Relation::default();
    let mut b = Builder::new(&mut relation, "L0/gated");
    let codes = b.witness("codes", Width::signed(8), 6 + 13);
    let scale = b.public("scale", vec![8454661; 64], Width::unsigned(24), 6);
    let input = RowOutput {
        codes,
        scale,
        log_rows: 6,
        log_dimension: 13,
        log_group: 13,
        scale_bound: 8454661,
    };
    let plan = ProjectionPlan {
        rows: 64,
        inner: 8192,
        outputs: 2048,
        weight_bits: 8,
        mantissas: vec![65535; 2048],
        shift: -60,
    };
    let mut projection = Projection::new("L0/down", input, None, plan).expect("plan");
    projection.declare(&mut relation);
    assert_eq!(relation.validate(), Ok(()));
}

#[test]
fn rejects_projection_domain_over_max_vars() {
    // shortcut: T=64, d=o=8192 needs the plan-fixed row-block split (gap, see module doc).
    let mut relation = Relation::default();
    let input = Builder::new(&mut relation, "L0/norm").witness("output", Width::signed(16), 6 + 13);
    let mut conversion =
        RowConversion::new("L0/row", input, 64, 8192, Policy::Dynamic).expect("row plan");
    conversion.declare(&mut relation);
    let plan = ProjectionPlan {
        rows: 64,
        inner: 8192,
        outputs: 8192,
        weight_bits: 8,
        mantissas: vec![1; 8192],
        shift: -20,
    };
    assert!(matches!(
        Projection::new("L0/q", conversion.output().expect("declared"), None, plan),
        Err(Unsupported::Domain)
    ));
}

/// `(model, scales)` byte spans of every case in a stele-cqis fixture corpus.
fn spans<'a>(json: &str, bin: &'a [u8]) -> Vec<(&'a [u8], &'a [u8])> {
    let span = |from: &str, key: &str| -> Option<(usize, &'a [u8])> {
        let at = from.find(&alloc::format!("\"{key}\":{{\"offset\":"))?;
        let rest = &from[at..];
        let number = |label: &str| -> Option<usize> {
            let start = rest.find(label)? + label.len();
            let digits: String = rest[start..]
                .chars()
                .take_while(char::is_ascii_digit)
                .collect();
            digits.parse().ok()
        };
        let (offset, length) = (number("\"offset\":")?, number("\"length\":")?);
        Some((at, bin.get(offset..offset + length)?))
    };
    let mut out = Vec::new();
    let mut rest = json;
    while let Some((at, model)) = span(rest, "model") {
        let Some((_, scales)) = span(&rest[at..], "scales") else {
            break;
        };
        out.push((model, scales));
        rest = &rest[at + 1..];
    }
    out
}

/// Every family-1 projection of every layer of the stele-cqis execution fixtures:
/// real policies, fractions, exponents and channel mantissas; random rows/weights.
#[test]
fn accepts_honest_projections_on_family_one_fixtures() {
    use stele_cqis::model::{Model, Role, Scales};
    let corpora: [(&str, &[u8]); 3] = [
        (
            include_str!("../../../stele-cqis/tests/fixtures/execution-boundaries.json"),
            include_bytes!("../../../stele-cqis/tests/fixtures/execution-boundaries.bin"),
        ),
        (
            include_str!("../../../stele-cqis/tests/fixtures/model-execution.json"),
            include_bytes!("../../../stele-cqis/tests/fixtures/model-execution.bin"),
        ),
        (
            include_str!("../../../stele-cqis/tests/fixtures/grouped-rows.json"),
            include_bytes!("../../../stele-cqis/tests/fixtures/grouped-rows.bin"),
        ),
    ];
    let (mut checked, mut grouped, mut skipped) = (0, 0, 0);
    let mut rng = Rng(7);
    for (json, bin) in corpora {
        for (model, scales) in spans(json, bin) {
            let Ok(model) = Model::decode(model) else {
                continue;
            };
            let Ok(scales) = Scales::decode(&model, scales) else {
                continue;
            };
            let shape = model.shape();
            if shape.family() != 1 || model.wide() {
                continue;
            }
            let ordinal = |role: Role, layer: Option<u16>| {
                (0..shape.record_count())
                    .find(|&o| {
                        shape
                            .physical(o)
                            .is_some_and(|p| p.role() == role && p.layer() == layer)
                    })
                    .expect("record")
            };
            let mut roles = Vec::new();
            for (layer, block) in model.blocks().iter().enumerate() {
                let (p, f) = (block.policies(), block.projection_fractions());
                let layer = Some(layer as u16);
                let first = block.first_norm().function().parameters()[4];
                let second = block.second_norm().function().parameters()[4];
                let ap = block.activation().function().parameters()[1];
                for (role, row, fraction, fo) in [
                    (Role::Query, 0, first, f[0]),
                    (Role::Key, 0, first, f[1]),
                    (Role::Value, 0, first, f[2]),
                    (Role::Output, 4, block.attention_fraction(), f[3]),
                    (Role::Up, 5, second, f[4]),
                    (Role::Gate, 5, second, f[5]),
                    (Role::Down, 6, ap + f[4], f[f.len() - 1]),
                ] {
                    roles.push((
                        ordinal(role, layer),
                        p[row],
                        fraction,
                        fo,
                        role == Role::Down,
                    ));
                }
            }
            let fraction = model.final_norm().function().parameters()[4];
            let head = ordinal(Role::Head, None);
            roles.push((
                head,
                model.final_policy(),
                fraction,
                model.logits_fraction(),
                false,
            ));
            for (ordinal, policy, fraction, fo, gated) in roles {
                if gated && policy.mode() == 2 {
                    // shortcut: grouped gated rows fold s_k up to 8454661 in limbs (E16-08).
                    skipped += 1;
                    continue;
                }
                let physical = shape.physical(ordinal).expect("record");
                let dims = physical.dimensions();
                let (o, d) = (dims[0] as usize, dims[1] as usize);
                let matrix = scales.matrix(ordinal).expect("matrix scale");
                let bits = model.formats()[ordinal as usize].bits();
                let shift = i32::from(matrix.exponent()) - i32::from(fraction) + i32::from(fo);
                let w_max = (1i64 << (bits - 1)) - 1;
                let weights: Vec<Vec<i64>> = (0..o)
                    .map(|_| (0..d).map(|_| rng.range(-w_max, w_max)).collect())
                    .collect();
                let m = matrix.mantissas().to_vec();
                let quantiser = Quantiser::new(Row {
                    dimension: d as u16,
                    kind: u8::from(gated),
                    fraction,
                    policy: policy.mode(),
                    scale: policy.scale(),
                })
                .expect("row");
                // Shrink the rows until the executor accepts conversion and projection.
                let peaks = [1i64 << 30, 1 << 20, 32767, 3000, 300, 30, 3, 0];
                let found = peaks.into_iter().find_map(|peak| {
                    let peak = if gated { peak } else { peak.min(32767) };
                    let inputs: Vec<Vec<i64>> = (0..3)
                        .map(|_| (0..d).map(|_| rng.range(-peak, peak)).collect())
                        .collect();
                    let mut capture = ConversionCapture {
                        inputs: inputs.clone(),
                        ..ConversionCapture::default()
                    };
                    for row in &inputs {
                        let out = if gated {
                            let row: Vec<i32> = row.iter().map(|&v| v as i32).collect();
                            quantiser.convert_gated(&row)
                        } else {
                            let row: Vec<i16> = row.iter().map(|&v| v as i16).collect();
                            quantiser.convert_wide(&row)
                        }
                        .ok()?;
                        capture
                            .codes
                            .push(out.codes().iter().map(|&c| i64::from(c)).collect());
                        capture.scales.push(out.scales().to_vec());
                    }
                    let outputs = affine(&capture, &weights, &m, shift)?;
                    Some((capture, outputs))
                });
                let (capture, outputs) = found.expect("an executable row");
                let result = if gated {
                    gated_check(&capture, &weights, &m, shift, bits, outputs, policy.scale())
                } else {
                    let row_policy = match policy.mode() {
                        0 => Policy::Dynamic,
                        1 => Policy::Static(policy.scale()),
                        _ => Policy::Grouped(policy.scale()),
                    };
                    grouped += usize::from(policy.mode() == 2);
                    build(capture, weights, m, shift, row_policy, bits, outputs).check()
                };
                assert_eq!(result, Ok(()), "ordinal {ordinal} {policy:?} gated {gated}");
                checked += 1;
            }
        }
    }
    assert!(
        checked >= 16 && grouped > 0,
        "{checked} checked, {grouped} grouped, {skipped} skipped"
    );
}

/// A down projection after a gated conversion; E16-08 supplies its codes and scales,
/// here a witness code column and a public scale column stand in for them.
fn gated_check(
    rows: &ConversionCapture,
    weights: &[Vec<i64>],
    m: &[u16],
    shift: i32,
    bits: u8,
    outputs: Vec<Vec<i64>>,
    configured: u32,
) -> Result<(), Violation> {
    let t = log2_ceil(rows.codes.len());
    let (ld, lo) = (log2_ceil(rows.codes[0].len()), log2_ceil(weights.len()));
    let mut relation = Relation::default();
    let mut b = Builder::new(&mut relation, "L0/gated");
    let codes = b.witness("codes", Width::signed(8), t + ld);
    let mut scale_values = vec![0; 1 << t];
    for (r, s) in rows.scales.iter().enumerate() {
        scale_values[r] = i64::from(s[0]);
    }
    let scale = b.public("scale", scale_values, Width::unsigned(24), t);
    let input = RowOutput {
        codes,
        scale,
        log_rows: t,
        log_dimension: ld,
        log_group: ld,
        scale_bound: if configured > 0 { configured } else { 8454661 },
    };
    let plan = ProjectionPlan {
        rows: rows.codes.len(),
        inner: rows.codes[0].len(),
        outputs: weights.len(),
        weight_bits: bits,
        mantissas: m.to_vec(),
        shift,
    };
    let mut projection = Projection::new("L0/down", input, None, plan).expect("down plan");
    projection.declare(&mut relation);
    let mut values = Values::new(&relation);
    values
        .set(&relation, codes, padded(&rows.codes, t, ld))
        .expect("codes");
    let weight = projection.weight().expect("weight");
    values
        .set(&relation, weight, padded(weights, lo, ld))
        .expect("weight");
    let capture = ProjectionCapture {
        codes: rows.codes.clone(),
        scales: rows.scales.clone(),
        weights: weights.to_vec(),
        outputs,
    };
    projection.assign(&relation, &capture, &mut values)?;
    check(&relation, &values)
}

//! Row conversion and projection: honest executor values pass the plain checker
//! (random rows, model fixtures, the executor capture), RFC-0026 §5.2 near misses
//! fail it, realistic plans pass the bound rule, and the per-constraint mutation
//! survey shows every constraint is load-bearing or explained.

extern crate std;

use super::*;
use projection::{ProjectionWitness, Step as PStep};
use row::{RowWitness, Step as RStep};
use stele_cqis::bounds::arithmetic::Row;
use stele_cqis::row::Quantiser;
use stele_ir::relation::{check, check_except, ColumnId, Module, Relation, Values, Violation};

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

/// Executor-equivalent affine output (`Data::affine`, family 1, no bias):
/// `R(V*m*u*2^l)`, ties away from zero, int16 or `None`.
fn affine(
    codes: &[Vec<i64>],
    scales: &[Vec<u32>],
    weights: &[Vec<i64>],
    m: &[u16],
    shift: i32,
) -> Option<Vec<Vec<i64>>> {
    let mut out = Vec::new();
    for (codes, scales) in codes.iter().zip(scales) {
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

fn padded(rows: &[Vec<i64>], log_rows: u8, log_lanes: u8) -> Vec<i64> {
    let mut out = vec![0; 1 << (log_rows + log_lanes)];
    for (r, row) in rows.iter().enumerate() {
        for (i, v) in row.iter().enumerate() {
            out[(r << log_lanes) | i] = *v;
        }
    }
    out
}

/// Row conversion and projection in one relation, honestly assigned.
struct Setup {
    relation: Relation,
    values: Values,
    conversion: RowConversion,
    projection: Projection,
    input: ColumnId,
}

fn build(
    rows: &ConversionCapture,
    weights: &[Vec<i64>],
    m: &[u16],
    shift: i32,
    policy: Policy,
    bits: u8,
    outputs: Vec<Vec<i64>>,
) -> Result<Setup, Violation> {
    let (t, ld) = (
        log2_ceil(rows.inputs.len()),
        log2_ceil(rows.inputs[0].len()),
    );
    let lo = log2_ceil(weights.len());
    let mut relation = Relation::default();
    let input = Builder::new(&mut relation, "L0/norm").witness("output", Width::signed(16), t + ld);
    let mut conversion = RowConversion::new(
        "L0/row",
        input,
        rows.inputs.len(),
        rows.inputs[0].len(),
        policy,
    )
    .expect("row plan");
    conversion.declare(&mut relation);
    let plan = ProjectionPlan {
        rows: rows.inputs.len(),
        inner: rows.inputs[0].len(),
        outputs: weights.len(),
        weight_bits: bits,
        mantissas: m.to_vec(),
        shift,
    };
    let output = conversion.output().expect("declared");
    let mut projection = Projection::new("L0/q", output, None, plan).expect("projection plan");
    projection.declare(&mut relation);
    let mut values = Values::new(&relation);
    values.set(&relation, input, padded(&rows.inputs, t, ld))?;
    let weight = projection.weight().expect("weight");
    values.set(&relation, weight, padded(weights, lo, ld))?;
    conversion.assign(&relation, rows, &mut values)?;
    let capture = ProjectionCapture {
        codes: rows.codes.clone(),
        scales: rows.scales.clone(),
        weights: weights.to_vec(),
        outputs,
    };
    projection.assign(&relation, &capture, &mut values)?;
    Ok(Setup {
        relation,
        values,
        conversion,
        projection,
        input,
    })
}

/// Random rows of mixed magnitude, a random int8/int4 weight, and a shift that keeps
/// the executor's outputs inside int16.
fn random(rows: usize, d: usize, o: usize, policy: Policy, bits: u8, seed: u64) -> Setup {
    let mut rng = Rng(seed);
    let cap = match policy {
        Policy::Static(s) => 127 * i64::from(s),
        _ => 32767,
    };
    let inputs: Vec<Vec<i64>> = (0..rows)
        .map(|r| {
            let peak = [0, 1, 300, 32767, 4000][(r + seed as usize) % 5].min(cap);
            let mut row: Vec<i64> = (0..d).map(|_| rng.range(-peak, peak)).collect();
            if r % 5 == 3 && cap == 32767 {
                row[d / 2] = -32768;
            }
            row
        })
        .collect();
    let rows_capture = convert(policy, &inputs).expect("converted");
    let w_max = (1 << (bits - 1)) - 1;
    let weights: Vec<Vec<i64>> = (0..o)
        .map(|_| (0..d).map(|_| rng.range(-w_max, w_max)).collect())
        .collect();
    let m: Vec<u16> = (0..o).map(|_| rng.range(1, 65535) as u16).collect();
    let fits = |l| affine(&rows_capture.codes, &rows_capture.scales, &weights, &m, l);
    let shift = (-60..=4)
        .rev()
        .find(|&l| fits(l).is_some())
        .expect("fitting shift");
    let outputs = fits(shift).expect("outputs");
    build(&rows_capture, &weights, &m, shift, policy, bits, outputs).expect("honest")
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
            let s = random(rows, d, o, policy, bits, 1 + k as u64);
            assert_eq!(
                check(&s.relation, &s.values),
                Ok(()),
                "{policy:?} {rows}x{d}x{o} int{bits}"
            );
        }
    }
}

#[test]
fn accepts_honest_left_and_extreme_shifts() {
    // l >= 0: Y = V*m*s*2^l exactly, with l mod 8 != 0 and l >= 8.
    let rows = convert(Policy::Static(1), &[vec![3, -2, 1, 0]]).expect("row");
    let weights = vec![vec![1, 1, 0, 0], vec![1, 0, 0, 0]];
    for shift in [0, 3, 9] {
        let m = [1, 3];
        let outputs = affine(&rows.codes, &rows.scales, &weights, &m, shift).expect("fits");
        let s = build(&rows, &weights, &m, shift, Policy::Static(1), 8, outputs).expect("honest");
        assert_eq!(check(&s.relation, &s.values), Ok(()), "l = {shift}");
    }
    // l = -200: every admissible product rounds to 0. l = 300 (clamped to 16): only
    // V = 0 fits int16, and V != 0 is rejected as the executor rejects it.
    let rows = convert(Policy::Dynamic, &[vec![32767, -5, 9, 0]]).expect("row");
    let weights = vec![vec![127, 127, -127, 3], vec![0, 0, 0, 0]];
    let s = build(
        &rows,
        &weights,
        &[65535, 7],
        -200,
        Policy::Dynamic,
        8,
        vec![vec![0, 0]],
    )
    .expect("honest");
    assert_eq!(check(&s.relation, &s.values), Ok(()));
    let zero = vec![vec![0; 4], vec![0; 4]];
    let s = build(
        &rows,
        &zero,
        &[1, 1],
        300,
        Policy::Dynamic,
        8,
        vec![vec![0, 0]],
    )
    .expect("V = 0");
    assert_eq!(check(&s.relation, &s.values), Ok(()));
    assert!(affine(&rows.codes, &rows.scales, &weights, &[1, 1], 300).is_none());
    // Its witness is the V = 0 one with the real weights: the matmul rejects.
    let mut s = s;
    let weight = s.projection.weight().expect("weight");
    s.values
        .set(&s.relation, weight, padded(&weights, 1, 2))
        .expect("weights");
    assert!(check(&s.relation, &s.values).is_err());
}

// ---------- RFC-0026 §5.2 near misses (forged by the attacker's completion) ----------

/// Row conversion alone, honestly assigned, with its completed witness.
struct RowCase {
    relation: Relation,
    values: Values,
    conversion: RowConversion,
    honest: RowWitness,
}

fn row_case(policy: Policy, inputs: &[Vec<i64>]) -> RowCase {
    let (t, ld) = (log2_ceil(inputs.len()), log2_ceil(inputs[0].len()));
    let mut relation = Relation::default();
    let input = Builder::new(&mut relation, "L0/norm").witness("output", Width::signed(16), t + ld);
    let mut conversion = RowConversion::new("L0/row", input, inputs.len(), inputs[0].len(), policy)
        .expect("row plan");
    conversion.declare(&mut relation);
    let capture = convert(policy, inputs).expect("executor accepts");
    let mut values = Values::new(&relation);
    values
        .set(&relation, input, padded(inputs, t, ld))
        .expect("input");
    conversion
        .assign(&relation, &capture, &mut values)
        .expect("honest assign");
    let mut honest = conversion.source(&capture).expect("source");
    conversion.complete(&mut honest, RStep::Sign, None);
    assert_eq!(check(&relation, &values), Ok(()));
    RowCase {
        relation,
        values,
        conversion,
        honest,
    }
}

impl RowCase {
    /// Lie at `step` (entry `i` set to `value`), complete the later steps, write.
    fn forge(&self, step: RStep, i: usize, value: i64) -> Values {
        self.forge_frozen(step, i, value, None)
    }

    /// As `forge`, keeping the `frozen` step's honest value.
    fn forge_frozen(&self, step: RStep, i: usize, value: i64, frozen: Option<RStep>) -> Values {
        let mut w = self.honest.clone();
        w.column(step)[i] = value;
        if let Some(next) = RStep::ALL.iter().find(|s| **s > step) {
            self.conversion.complete(&mut w, *next, frozen);
        }
        let mut values = self.values.clone();
        self.conversion
            .write(&self.relation, &w, &mut values)
            .expect("forged lengths");
        values
    }
}

const ROW_INPUTS: [[i64; 6]; 5] = [
    [300, -7, 150, 0, 3, -150],     // s = 3, ties at 1.5 and -50 exactly
    [0, 0, 0, 0, 0, 0],             // zero row
    [381, 1, -382, 254, -127, 128], // M = 382 -> s = 4; grouped: 381 = 127*3 -> 3
    [509, -500, 3, 0, 0, 0],        // s = 5; a false M = 500 gives s = 4, q(509) = 127
    [-32768, 32767, 1, 2, 3, 4],    // extremes
];

fn row_inputs() -> Vec<Vec<i64>> {
    ROW_INPUTS.iter().map(|r| r.to_vec()).collect()
}

/// The rows a policy's executor accepts: a small static scale drops the extremes.
fn row_inputs_for(policy: Policy) -> Vec<Vec<i64>> {
    let mut rows = row_inputs();
    if matches!(policy, Policy::Static(_)) {
        rows.pop();
    }
    rows
}

#[test]
fn rejects_code_near_misses() {
    for policy in [Policy::Dynamic, Policy::Static(5), Policy::Grouped(2)] {
        let case = row_case(policy, &row_inputs_for(policy));
        for x in (0..case.honest.codes.len()).filter(|&x| case.conversion.real(x)) {
            let q = case.honest.quotient[x];
            // Output +-1, with q (and so c) completed consistently.
            for wrong in [q - 1, q + 1].into_iter().filter(|v| (0..=127).contains(v)) {
                let forged = case.forge(RStep::Quotient, x, wrong);
                assert!(
                    check(&case.relation, &forged).is_err(),
                    "{policy:?} lane {x} q {wrong}"
                );
            }
            // The other rounding direction: flip beta, q follows.
            let beta = case.honest.half[x];
            let forged = case.forge(RStep::Half, x, 1 - beta);
            assert!(
                check(&case.relation, &forged).is_err(),
                "{policy:?} lane {x} beta"
            );
            // The code itself +-1.
            for delta in [-1, 1] {
                let c = case.honest.codes[x] + delta;
                let forged = case.forge(RStep::Code, x, c);
                assert!(check(&case.relation, &forged).is_err());
            }
        }
    }
}

#[test]
fn rejects_scale_near_misses() {
    for policy in [Policy::Dynamic, Policy::Grouped(2)] {
        let case = row_case(policy, &row_inputs());
        for k in 0..case.honest.scale.len() {
            for delta in [-1, 1] {
                let s = case.honest.scale[k] + delta;
                if s < 0 {
                    continue;
                }
                // Scale +-1 with every later step (codes included) recomputed.
                let forged = case.forge(RStep::Scale, k, s);
                assert!(
                    check(&case.relation, &forged).is_err(),
                    "{policy:?} group {k} s {s}"
                );
            }
        }
    }
    // Ceiling boundary: M = 381 = 127*3 gives 3, not 4; M = 382 gives 4, not 3.
    let case = row_case(Policy::Grouped(2), &row_inputs());
    assert_eq!(&case.honest.scale[8..10], &[3, 4]);
    for (k, wrong) in [(8, 4), (9, 3)] {
        let forged = case.forge(RStep::Scale, k, wrong);
        assert!(matches!(
            check(&case.relation, &forged),
            Err(Violation::Lookup { relation, .. }) if relation == "L0/row/slack/range"
        ));
    }
}

#[test]
fn rejects_zero_row_branch_near_misses() {
    let case = row_case(Policy::Dynamic, &row_inputs());
    assert_eq!(case.honest.scale[1], 0);
    assert_eq!(case.honest.zero[1], 1);
    // Zero row with scale 1 (z completed to 0): the ceiling rejects 127*1 - 0 = 127.
    let forged = case.forge(RStep::Scale, 1, 1);
    assert!(check(&case.relation, &forged).is_err());
    // Zero row with z cleared: the divisor s + z = 0 leaves no remainder range.
    let forged = case.forge(RStep::Zero, 1, 0);
    assert!(check(&case.relation, &forged).is_err());
    // Nonzero row claiming the zero branch: z*M = 0 rejects.
    let forged = case.forge(RStep::Zero, 0, 1);
    assert!(check(&case.relation, &forged).is_err());
    // Zero row with a nonzero code: rejected through the division and the half bit.
    let lane = 1 << 3; // row 1, lane 0
    let forged = case.forge(RStep::Quotient, lane, 1);
    assert!(check(&case.relation, &forged).is_err());
}

/// Projection alone over test-declared input columns, honestly assigned.
struct ProjectionCase {
    relation: Relation,
    values: Values,
    projection: Projection,
    honest: ProjectionWitness,
    codes: ColumnId,
}

fn projection_case(
    policy: Policy,
    inputs: &[Vec<i64>],
    weights: &[Vec<i64>],
    m: &[u16],
    shift: i32,
) -> ProjectionCase {
    let rows = convert(policy, inputs).expect("rows");
    let (t, ld, lo) = (
        log2_ceil(inputs.len()),
        log2_ceil(inputs[0].len()),
        log2_ceil(weights.len()),
    );
    let lg = match policy {
        Policy::Grouped(g) => g.trailing_zeros() as u8,
        _ => ld,
    };
    let mut relation = Relation::default();
    let mut b = Builder::new(&mut relation, "L0/row");
    let codes = b.witness("codes", Width::signed(8), t + ld);
    let per_row = 1usize << (ld - lg);
    let mut scales = vec![0; 1 << (t + ld - lg)];
    for (r, row) in rows.scales.iter().enumerate() {
        for (k, s) in row.iter().enumerate() {
            scales[r * per_row + k] = i64::from(*s);
        }
    }
    let (scale, bound) = match policy {
        Policy::Static(s) => (
            b.public("scale", vec![i64::from(s); 1 << t], Width::unsigned(16), t),
            s,
        ),
        _ => (b.witness("scale", Width::unsigned(9), t + ld - lg), 259),
    };
    let input = RowOutput {
        codes,
        scale,
        log_rows: t,
        log_dimension: ld,
        log_group: lg,
        scale_bound: bound,
    };
    let plan = ProjectionPlan {
        rows: inputs.len(),
        inner: inputs[0].len(),
        outputs: weights.len(),
        weight_bits: 8,
        mantissas: m.to_vec(),
        shift,
    };
    let mut projection = Projection::new("L0/q", input, None, plan).expect("plan");
    projection.declare(&mut relation);
    let mut values = Values::new(&relation);
    values
        .set(&relation, codes, padded(&rows.codes, t, ld))
        .expect("codes");
    if !matches!(policy, Policy::Static(_)) {
        values.set(&relation, scale, scales).expect("scales");
    }
    let weight = projection.weight().expect("weight");
    values
        .set(&relation, weight, padded(weights, lo, ld))
        .expect("weight");
    let outputs = affine(&rows.codes, &rows.scales, weights, m, shift).expect("fits");
    let capture = ProjectionCapture {
        codes: rows.codes,
        scales: rows.scales,
        weights: weights.to_vec(),
        outputs,
    };
    projection
        .assign(&relation, &capture, &mut values)
        .expect("honest assign");
    let mut honest = projection.source(&relation, &capture).expect("source");
    projection.complete(&mut honest, PStep::Digits, None);
    assert_eq!(check(&relation, &values), Ok(()));
    ProjectionCase {
        relation,
        values,
        projection,
        honest,
        codes,
    }
}

/// The limbs a projection step defines.
fn limbs(w: &mut ProjectionWitness, step: PStep) -> Vec<&mut Vec<i64>> {
    match step {
        PStep::Digits => w.digits.iter_mut().collect(),
        PStep::Sums => w.sums.iter_mut().collect(),
        PStep::Sign => vec![&mut w.sign],
        PStep::Bytes => w.bytes.iter_mut().collect(),
        PStep::ScaleBytes => w.scale_bytes.iter_mut().collect(),
        PStep::Magnitude => vec![&mut w.magnitude],
        PStep::Remainder => w.remainder.iter_mut().collect(),
        PStep::Output => vec![&mut w.output],
    }
}

const PSTEPS: [PStep; 8] = [
    PStep::Digits,
    PStep::Sums,
    PStep::Sign,
    PStep::Bytes,
    PStep::ScaleBytes,
    PStep::Magnitude,
    PStep::Remainder,
    PStep::Output,
];

impl ProjectionCase {
    /// Apply `lie` to a copy of the honest witness at `step`, complete the later
    /// steps, write (carries around `skip`).
    fn forge(
        &self,
        step: PStep,
        lie: impl Fn(&mut Vec<&mut Vec<i64>>),
        skip: Option<(&str, usize)>,
    ) -> (Values, ProjectionWitness) {
        self.forge_frozen(step, lie, skip, None)
    }

    /// As `forge`, keeping the `frozen` step's honest value.
    fn forge_frozen(
        &self,
        step: PStep,
        lie: impl Fn(&mut Vec<&mut Vec<i64>>),
        skip: Option<(&str, usize)>,
        frozen: Option<PStep>,
    ) -> (Values, ProjectionWitness) {
        let mut w = self.honest.clone();
        lie(&mut limbs(&mut w, step));
        if let Some(next) = PSTEPS.iter().find(|s| **s > step) {
            self.projection.complete(&mut w, *next, frozen);
        }
        let mut values = self.values.clone();
        self.projection
            .write(&self.relation, &w, &mut values, skip)
            .expect("forged lengths");
        (values, w)
    }
}

fn projection_inputs() -> (Vec<Vec<i64>>, Vec<Vec<i64>>, Vec<u16>) {
    let inputs = vec![
        vec![300, -7, 150, 0, 3, -150],
        vec![32767, -32768, 5, 9, -1000, 77],
        vec![0, 0, 0, 0, 0, 0],
    ];
    let weights = vec![
        vec![127, -127, 3, 0, 100, -5],
        vec![-1, 2, -3, 4, -5, 6],
        vec![0, 0, 0, 0, 0, 1],
    ];
    (inputs, weights, vec![65535, 300, 1])
}

#[test]
fn rejects_projection_output_near_misses() {
    let (inputs, weights, m) = projection_inputs();
    for policy in [Policy::Dynamic, Policy::Static(300), Policy::Grouped(2)] {
        let shift = (-60..0)
            .rev()
            .find(|&l| {
                convert(policy, &inputs)
                    .and_then(|r| affine(&r.codes, &r.scales, &weights, &m, l))
                    .is_some()
            })
            .expect("shift");
        let case = projection_case(policy, &inputs, &weights, &m, shift);
        for x in (0..case.honest.output.len()).filter(|&x| case.projection.real(x)) {
            for delta in [-1i64, 1] {
                // |Y| +-1 with the remainder limbs and Y completed (the other rounding
                // direction is one of these).
                let (forged, _) = case.forge(PStep::Magnitude, |l| l[0][x] += delta, None);
                assert!(
                    check(&case.relation, &forged).is_err(),
                    "{policy:?} Y[{x}] {delta:+}"
                );
                let (forged, _) = case.forge(PStep::Output, |l| l[0][x] += delta, None);
                assert!(check(&case.relation, &forged).is_err());
            }
        }
    }
    // Ties at +-1.5: R rounds away to +-2; toward zero (+-1) is rejected.
    let case = projection_case(
        Policy::Static(1),
        &[vec![3, 0], vec![-3, 0]],
        &[vec![1, 0]],
        &[1],
        -1,
    );
    assert_eq!(case.honest.output, vec![2, -2]);
    for x in 0..2 {
        let (forged, _) = case.forge(PStep::Magnitude, |l| l[0][x] = 1, None);
        assert!(check(&case.relation, &forged).is_err());
    }
}

#[test]
fn rejects_nonzero_padding() {
    let s = random(3, 24, 6, Policy::Dynamic, 8, 40);
    let output = s.projection.output().expect("declared");
    let mut values = s.values.clone();
    let mut y = values.get(&s.relation, output).expect("Y").to_vec();
    let padded = y.len() - 1;
    y[padded] = 1;
    values.set(&s.relation, output, y).expect("Y");
    assert!(check(&s.relation, &values).is_err());
    let codes = s.conversion.output().expect("declared").codes;
    let mut values = s.values.clone();
    let mut c = values.get(&s.relation, codes).expect("codes").to_vec();
    c[30] = 1; // row 0, padded lane 30 >= 24
    values.set(&s.relation, codes, c).expect("codes");
    assert!(check(&s.relation, &values).is_err());
    // A padded input lane is ignored: the honest witness still passes.
    let mut values = s.values.clone();
    let mut x = values.get(&s.relation, s.input).expect("x").to_vec();
    x[30] = 12345;
    values.set(&s.relation, s.input, x).expect("x");
    assert_eq!(check(&s.relation, &values), Ok(()));
}

// ---------- mutation survey: every constraint killed or explained ----------

/// Every constraint of `relation` whose name starts with `prefix`.
fn constraints(relation: &Relation, prefix: &str) -> Vec<String> {
    let names = relation
        .identities
        .iter()
        .map(|c| &c.name)
        .chain(relation.lookups.iter().map(|c| &c.name))
        .chain(relation.ranges.iter().map(|c| &c.name))
        .chain(relation.matmuls.iter().map(|c| &c.name))
        .chain(relation.composes.iter().map(|c| &c.name));
    let mut out: Vec<String> = names.filter(|n| n.starts_with(prefix)).cloned().collect();
    out.sort();
    out.dedup();
    out
}

/// `name` is a chain position `{chain}/{k}`: its carries are assigned around `k`.
fn chain_position(name: &str) -> Option<(&str, usize)> {
    let (chain, k) = name.rsplit_once('/')?;
    Some((chain, k.parse().ok()?))
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Outcome {
    /// An in-range forged witness that changes an output, or that is accepted for an
    /// input the executor rejects.
    Killed(String),
    /// Only an auxiliary column changes (the outputs stay the executor's).
    Auxiliary(String),
    Survived,
}

/// One forged assignment. `rejected` marks an input the executor rejects, so any
/// accepting assignment is an exploit whatever its outputs.
struct Candidate {
    description: String,
    values: Values,
    rejected: bool,
}

/// Survivors whose deletion changes no output over Z, with the reason. Each reason
/// names the constraints that imply it; none hides an output change.
fn explanation(name: &str) -> Option<&'static str> {
    let rules: [(&str, &str); 14] = [
        (
            "L0/q/magnitude/range",
            "implied: the rounding chain gives Ymag = floor((P + 2^(K-1))/2^K) >= 0 (or \
             Ymag' = P*256^(l/8) >= 0) exactly, and |Y| = f*Ymag <= 32768 by the output range",
        ),
        (
            "L0/q/digit/",
            "output-neutral: the fold fixes b0 + 256 b1 = q*s, and V = C_0 + 256 C_1 = \
             sum (b0 + 256 b1) w depends only on that sum; the ranges bound the matmul outputs \
             for the bound rule mod p",
        ),
        (
            "/carry",
            "chain carry range: each carry is fixed by its position identities (chain \
             lemma); the range keeps every position wrap-free mod p (bound rule), which the \
             integer checker cannot exercise",
        ),
        (
            "/weight/range",
            "committed model data, never prover-chosen (RFC-0026 §2.2); kept for the bound rule",
        ),
        (
            "L0/row/codes/range",
            "implied: c = (1 - 2 sigma) q with sigma in {0,1} and q in [0,127]",
        ),
        (
            "L0/row/magnitude/range",
            "implied: a = q0*D + rho with q0 >= 0, D >= 1, rho >= 0 (floor, spare, remainder)",
        ),
        (
            "L0/row/maximum/range",
            "implied: M = a_j at a lane with h_j != 0 (attained, one-hot) and a <= 32768",
        ),
        (
            "L0/row/scale/range",
            "implied: 127 s = M + slack <= 32768 + 126 (ceiling, slack lookup, maximum)",
        ),
        (
            "L0/row/floor/range",
            "implied: q0 = q - beta <= 127 (quotient range) and q0 > -1 (a >= 0, rho < D)",
        ),
        (
            "L0/row/hit/range",
            "implied for M: sum h = 1 forces a lane with h != 0, where h*gap = 0 makes \
             M attained, whatever integers h holds",
        ),
        (
            "L0/row/zero/range",
            "output-neutral: z matters only where M = 0, where a = 0 gives q = 0 for every \
             divisor s + z >= 1",
        ),
        (
            "L0/row/quotient/range",
            "implied in dynamic mode (a <= M <= 127 s gives q <= 127); in static mode an \
             overflowing input kills it (static table)",
        ),
        (
            "L0/row/sign/range",
            "output-neutral: sigma only multiplies q, and a(1 - 2 sigma) = x with a >= 0 \
             fixes sigma wherever x != 0",
        ),
        (
            "L0/q/scale/",
            "scale byte range: s = sum 256^c s_c is fixed by the scale identity; only the \
             byte representation moves, never the product sum",
        ),
    ];
    rules
        .iter()
        .find(|(pattern, _)| name.contains(pattern))
        .map(|(_, reason)| *reason)
}

/// For each constraint: delete it (`check_except`) and look for a forged witness the
/// full checker rejects and the mutated one accepts. `forged(skip, phase)` lists
/// candidates; phase 0 lies at one step and completes the rest, phase 1 also keeps
/// one later step frozen (tried only when phase 0 changes no output).
fn survey<F>(
    relation: &Relation,
    prefix: &str,
    honest: &Values,
    outputs: impl Fn(&Values) -> Vec<i64>,
    forged: F,
) -> Vec<(String, Outcome)>
where
    F: Fn(Option<(&str, usize)>, usize) -> Vec<Candidate>,
{
    let truth = outputs(honest);
    let plain = forged(None, 0);
    constraints(relation, prefix)
        .into_iter()
        .map(|name| {
            let skip = [name.as_str()];
            let position = chain_position(&name).filter(|(chain, _)| {
                relation
                    .identities
                    .iter()
                    .any(|i| i.name.starts_with(&alloc::format!("{chain}/")) && *chain != prefix)
            });
            let mut outcome = Outcome::Survived;
            'phases: for phase in 0..2 {
                let fresh;
                let candidates = match (position, phase) {
                    (None, 0) => &plain,
                    (skip, phase) => {
                        fresh = forged(skip, phase);
                        &fresh
                    }
                };
                for c in candidates {
                    if check(relation, &c.values).is_ok()
                        || check_except(relation, &c.values, &skip).is_err()
                    {
                        continue;
                    }
                    if c.rejected || outputs(&c.values) != truth {
                        outcome = Outcome::Killed(c.description.clone());
                        break 'phases;
                    }
                    if outcome == Outcome::Survived {
                        outcome = Outcome::Auxiliary(c.description.clone());
                    }
                }
            }
            (name, outcome)
        })
        .collect()
}

fn report(rows: &[(String, Outcome)]) -> Vec<String> {
    let mut table = String::from("| constraint | result |\n|---|---|\n");
    let mut unexplained = Vec::new();
    for (name, outcome) in rows {
        let result = match outcome {
            Outcome::Killed(how) => alloc::format!("killed: {how}"),
            Outcome::Auxiliary(how) => match explanation(name) {
                Some(reason) => alloc::format!("auxiliary only ({how}); {reason}"),
                None => {
                    unexplained.push(name.clone());
                    alloc::format!("auxiliary only ({how}); UNEXPLAINED")
                }
            },
            Outcome::Survived => match explanation(name) {
                Some(reason) => alloc::format!("redundant: {reason}"),
                None => {
                    unexplained.push(name.clone());
                    String::from("UNEXPLAINED")
                }
            },
        };
        table.push_str(&alloc::format!("| `{name}` | {result} |\n"));
    }
    std::println!("{table}");
    unexplained
}

/// Every table's unexplained survivor must be killed in some other table.
fn assert_covered(tables: &[Vec<(String, Outcome)>]) {
    let killed: Vec<&String> = tables
        .iter()
        .flatten()
        .filter(|(_, o)| matches!(o, Outcome::Killed(_)))
        .map(|(n, _)| n)
        .collect();
    let mut open: Vec<String> = tables
        .iter()
        .flat_map(|t| report(t))
        .filter(|n| !killed.contains(&n))
        .collect();
    open.dedup();
    assert!(open.is_empty(), "unexplained survivors: {open:?}");
}

const ROW_DELTAS: [i64; 12] = [1, -1, 2, -2, 127, -127, 128, -128, 256, -256, 32768, -32768];
const FROZEN_DELTAS: [i64; 6] = [1, -1, 2, 127, 128, -128];

fn row_survey(policy: Policy) -> Vec<(String, Outcome)> {
    let case = row_case(policy, &row_inputs_for(policy));
    let c = case.conversion.columns.expect("declared");
    let outputs = |v: &Values| {
        let mut o = v.get(&case.relation, c.codes).expect("codes").to_vec();
        o.extend_from_slice(v.get(&case.relation, c.scale).expect("scale"));
        o
    };
    let lie = |step: RStep, i: usize, delta: i64, frozen: Option<RStep>| Candidate {
        description: match frozen {
            Some(f) => alloc::format!("{step:?}[{i}] {delta:+}, {f:?} kept"),
            None => alloc::format!("{step:?}[{i}] {delta:+}"),
        },
        values: case.forge_frozen(step, i, case.honest.clone().column(step)[i] + delta, frozen),
        rejected: false,
    };
    let forged = |_: Option<(&str, usize)>, phase: usize| {
        let mut all = Vec::new();
        for step in RStep::ALL {
            let n = case.honest.clone().column(step).len();
            for i in 0..n {
                if phase == 0 {
                    all.extend(ROW_DELTAS.iter().map(|&d| lie(step, i, d, None)));
                } else {
                    for frozen in RStep::ALL.iter().filter(|f| **f > step) {
                        all.extend(
                            FROZEN_DELTAS
                                .iter()
                                .map(|&d| lie(step, i, d, Some(*frozen))),
                        );
                    }
                }
            }
        }
        if phase == 0 {
            // M set to another lane's magnitude in its group (a smaller "maximum").
            let width = case.honest.magnitude.len() / case.honest.maximum.len();
            for (k, m) in case.honest.maximum.iter().enumerate() {
                for x in k * width..(k + 1) * width {
                    let delta = case.honest.magnitude[x] - m;
                    if delta != 0 {
                        all.push(lie(RStep::Maximum, k, delta, None));
                    }
                }
            }
        }
        if let (0, Policy::Static(s)) = (phase, policy) {
            // An input the executor rejects (|x|/s rounds to 128, q0 = 127): honest
            // completion gives the code -128, inside int8.
            let x = -(127 * i64::from(s) + (i64::from(s) + 1) / 2);
            let mut w = case.honest.clone();
            w.input[0] = x;
            case.conversion.complete(&mut w, RStep::Sign, None);
            let mut values = case.values.clone();
            case.conversion
                .write(&case.relation, &w, &mut values)
                .expect("lengths");
            let input = case.relation.ranges[0].column;
            let mut column = values.get(&case.relation, input).expect("x").to_vec();
            column[0] = x;
            values.set(&case.relation, input, column).expect("x");
            all.push(Candidate {
                description: alloc::format!("input x = {x}, which the executor rejects"),
                values,
                rejected: true,
            });
        }
        all
    };
    survey(&case.relation, "L0/row/", &case.values, outputs, forged)
}

const PROJECTION_DELTAS: [i64; 10] = [1, -1, 2, -2, 255, -255, 256, -256, 65536, -65536];

fn projection_survey(
    policy: Policy,
    inputs: &[Vec<i64>],
    weights: &[Vec<i64>],
    m: &[u16],
    shift: i32,
) -> Vec<(String, Outcome)> {
    std::println!("projection, {policy:?}, l = {shift}");
    let case = projection_case(policy, inputs, weights, m, shift);
    let output = case.projection.output().expect("declared");
    let outputs = |v: &Values| v.get(&case.relation, output).expect("Y").to_vec();
    let real: Vec<usize> = (0..case.honest.output.len())
        .filter(|&x| case.projection.real(x))
        .collect();
    // Write a whole forged witness completed from `from`.
    let custom = |description: String,
                  lie: &dyn Fn(&mut ProjectionWitness),
                  from: Option<PStep>,
                  skip: Option<(&str, usize)>| {
        let mut w = case.honest.clone();
        lie(&mut w);
        if let Some(from) = from {
            case.projection.complete(&mut w, from, None);
        }
        let mut values = case.values.clone();
        case.projection
            .write(&case.relation, &w, &mut values, skip)
            .expect("lengths");
        // An input the executor rejects: the completed output leaves int16.
        let rejected = w.output.iter().any(|y| !(-32768..=32767).contains(y));
        (description, values, rejected, w)
    };
    let forged = |skip: Option<(&str, usize)>, phase: usize| {
        let mut all = Vec::new();
        let frozen: Vec<Option<PStep>> = if phase == 0 {
            vec![None]
        } else {
            PSTEPS.iter().map(|s| Some(*s)).collect()
        };
        for step in PSTEPS {
            let mut probe = case.honest.clone();
            let shape: Vec<usize> = limbs(&mut probe, step).iter().map(|l| l.len()).collect();
            for f in frozen.iter().filter(|f| f.is_none_or(|f| f > step)) {
                let deltas: &[i64] = if phase == 0 {
                    &PROJECTION_DELTAS
                } else {
                    &[1, -1, 256]
                };
                for (k, n) in shape.iter().enumerate() {
                    for i in 0..*n {
                        for &delta in deltas {
                            let (values, _) =
                                case.forge_frozen(step, |l| l[k][i] += delta, skip, *f);
                            all.push(Candidate {
                                description: alloc::format!(
                                    "{step:?}[{k}][{i}] {delta:+}{}",
                                    kept(*f)
                                ),
                                values,
                                rejected: false,
                            });
                        }
                        // Borrow between adjacent limbs: same total, other representation.
                        if k + 1 < shape.len() {
                            let (values, _) = case.forge_frozen(
                                step,
                                |l| {
                                    l[k][i] += 256;
                                    l[k + 1][i] -= 1;
                                },
                                skip,
                                *f,
                            );
                            all.push(Candidate {
                                description: alloc::format!(
                                    "{step:?}[{k}][{i}] borrow{}",
                                    kept(*f)
                                ),
                                values,
                                rejected: false,
                            });
                        }
                    }
                }
            }
        }
        if phase == 1 {
            return all;
        }
        let k_bits = -shift;
        for &x in &real {
            // |Y| +-1 with remainder limb `r` absorbing -+2^(K - 8r): the chain holds
            // exactly; only that limb leaves its range.
            for r in 0..case.honest.remainder.len() {
                for d in [-1i64, 1] {
                    let lie = move |w: &mut ProjectionWitness| {
                        w.magnitude[x] += d;
                        w.remainder[r][x] -= d << (k_bits - 8 * r as i32);
                    };
                    let (description, values, rejected, _) = custom(
                        alloc::format!("Magnitude[{x}] {d:+}, remainder limb {r} absorbs it"),
                        &lie,
                        Some(PStep::Output),
                        skip,
                    );
                    all.push(Candidate {
                        description,
                        values,
                        rejected,
                    });
                }
            }
            // tau flipped, (1 - 2 tau) |V| = V carried whole by byte `b`.
            for b in 0..case.honest.bytes.len() {
                let lie = move |w: &mut ProjectionWitness| {
                    let v: i128 = w
                        .sums
                        .iter()
                        .enumerate()
                        .map(|(t, s)| i128::from(s[x]) << (8 * t))
                        .sum();
                    w.sign[x] = 1 - w.sign[x];
                    let target = v * (1 - 2 * i128::from(w.sign[x]));
                    // Canonical bytes below `b`, the signed rest in byte `b`, zero above.
                    for (j, limb) in w.bytes.iter_mut().enumerate() {
                        limb[x] = match j.cmp(&b) {
                            core::cmp::Ordering::Less => ((target >> (8 * j)) & 255) as i64,
                            core::cmp::Ordering::Equal => (target >> (8 * j)) as i64,
                            core::cmp::Ordering::Greater => 0,
                        };
                    }
                };
                let (description, values, rejected, _) = custom(
                    alloc::format!("sign[{x}] flipped, |V| carried by byte {b}"),
                    &lie,
                    Some(PStep::ScaleBytes),
                    skip,
                );
                all.push(Candidate {
                    description,
                    values,
                    rejected,
                });
            }
        }
        // Inputs the executor rejects: one code set to +-127, honestly completed.
        let lanes = case.honest.codes.len();
        for i in 0..lanes {
            for code in [-127i64, 127] {
                let lie = move |w: &mut ProjectionWitness| w.codes[i] = code;
                let (description, mut values, rejected, w) = custom(
                    alloc::format!("input code[{i}] = {code}"),
                    &lie,
                    Some(PStep::Digits),
                    skip,
                );
                if rejected {
                    values
                        .set(&case.relation, case.codes, w.codes.clone())
                        .expect("codes");
                    all.push(Candidate {
                        description: alloc::format!("{description}, which the executor rejects"),
                        values,
                        rejected,
                    });
                }
            }
        }
        all
    };
    survey(&case.relation, "L0/q/", &case.values, outputs, forged)
}

fn kept(frozen: Option<PStep>) -> String {
    frozen.map_or(String::new(), |f| alloc::format!(", {f:?} kept"))
}

#[test]
fn survey_row_conversion_constraints() {
    for policy in [Policy::Dynamic, Policy::Grouped(2), Policy::Static(5)] {
        std::println!("row conversion, {policy:?}");
        assert_covered(&[row_survey(policy)]);
    }
}

#[test]
fn survey_projection_constraints() {
    let (inputs, weights, m) = projection_inputs();
    let tie = |v: i64| vec![vec![v, 0], vec![-v, 0]];
    // The least right shift that keeps every output inside int16.
    let fit = |policy: Policy| {
        let rows = convert(policy, &inputs).expect("rows");
        (-60..0)
            .rev()
            .find(|&l| affine(&rows.codes, &rows.scales, &weights, &m, l).is_some())
            .expect("shift")
    };
    let tables = [
        projection_survey(Policy::Dynamic, &inputs, &weights, &m, fit(Policy::Dynamic)),
        projection_survey(
            Policy::Grouped(2),
            &inputs,
            &weights,
            &m,
            fit(Policy::Grouped(2)),
        ),
        projection_survey(
            Policy::Static(300),
            &inputs,
            &weights,
            &m,
            fit(Policy::Static(300)),
        ),
        projection_survey(Policy::Dynamic, &inputs, &weights, &m, -200),
        // l = 9 >= 0 with small codes; a code of 127 overflows int16.
        projection_survey(
            Policy::Static(1),
            &[vec![3, -2, 1, 0]],
            &[vec![1, 1, 0, 0], vec![1, 0, 0, 0]],
            &[1, 3],
            9,
        ),
        // Exact ties: P = 2^(K-1) with V = 1 (K = 1) and V = 256 (K = 9), and with
        // three and four sign-chain bytes (4 lanes; grouped digit rows).
        projection_survey(Policy::Static(1), &tie(1), &[vec![1, 0]], &[1], -1),
        projection_survey(
            Policy::Static(1),
            &[vec![1, 0, 0, 0], vec![-1, 0, 0, 0]],
            &[vec![1, 0, 0, 0]],
            &[1],
            -1,
        ),
        projection_survey(
            Policy::Grouped(2),
            &[vec![1, 0, 0, 0], vec![-1, 0, 0, 0]],
            &[vec![1, 0, 0, 0]],
            &[1],
            -1,
        ),
        projection_survey(
            Policy::Static(1),
            &[vec![64, 64], vec![-64, -64]],
            &[vec![2, 2]],
            &[1],
            -9,
        ),
    ];
    assert_covered(&tables);
}

// ---------- bound rule on realistic shapes ----------

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
    let output = conversion.output().expect("declared");
    let mut projection = Projection::new("L0/q", output, None, plan).expect("plan");
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
    // Down projection after E16-08's gated conversion (scale up to 8454661).
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
    // T=64, d=o=8192 needs the plan-fixed row-block split (E16-10, graph.yaml).
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
    let output = conversion.output().expect("declared");
    assert!(matches!(
        Projection::new("L0/q", output, None, plan),
        Err(Unsupported::Domain)
    ));
}

// ---------- model fixtures and the executor capture ----------

/// One case of a stele-cqis fixture corpus.
struct Case<'a> {
    model: &'a [u8],
    preparation: &'a [u8],
    scales: &'a [u8],
    artifact: &'a [u8],
    artifact_id: Option<[u8; 32]>,
    tokens: Vec<u32>,
}

/// Every case of a corpus (the JSON is the fixtures' own compact form).
fn cases<'a>(json: &str, bin: &'a [u8]) -> Vec<Case<'a>> {
    let span = |segment: &str, key: &str| -> Option<&'a [u8]> {
        let rest = &segment[segment.find(&alloc::format!("\"{key}\":{{\"offset\":"))?..];
        let number = |label: &str| -> Option<usize> {
            let start = rest.find(label)? + label.len();
            let digits: String = rest[start..]
                .chars()
                .take_while(char::is_ascii_digit)
                .collect();
            digits.parse().ok()
        };
        let (offset, length) = (number("\"offset\":")?, number("\"length\":")?);
        bin.get(offset..offset + length)
    };
    json.split("{\"model\":")
        .skip(1)
        .filter_map(|segment| {
            let segment = alloc::format!("{{\"model\":{segment}");
            let id = segment.find("\"artifact_id\":\"").and_then(|at| {
                let hex = segment.get(at + 15..at + 79)?;
                let mut out = [0u8; 32];
                for (k, byte) in out.iter_mut().enumerate() {
                    *byte = u8::from_str_radix(hex.get(2 * k..2 * k + 2)?, 16).ok()?;
                }
                Some(out)
            });
            let tokens = segment
                .find("\"tokens\":[")
                .map(|at| {
                    let rest = &segment[at + 10..];
                    rest[..rest.find(']').unwrap_or(0)]
                        .split(',')
                        .filter_map(|t| t.trim().parse().ok())
                        .collect()
                })
                .unwrap_or_default();
            Some(Case {
                model: span(&segment, "model")?,
                preparation: span(&segment, "preparation")?,
                scales: span(&segment, "scales")?,
                artifact: span(&segment, "artifact")?,
                artifact_id: id,
                tokens,
            })
        })
        .collect()
}

const CORPORA: [(&str, &[u8]); 3] = [
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

/// Every family-1 projection of every layer of the stele-cqis execution fixtures:
/// real policies, fractions, exponents and channel mantissas; random rows/weights.
#[test]
fn accepts_honest_projections_on_family_one_fixtures() {
    use stele_cqis::model::{Model, Role, Scales};
    let (mut checked, mut grouped) = (0, 0);
    let mut rng = Rng(7);
    for (json, bin) in CORPORA {
        for case in cases(json, bin) {
            let Ok(model) = Model::decode(case.model) else {
                continue;
            };
            let Ok(scales) = Scales::decode(&model, case.scales) else {
                continue;
            };
            let shape = model.shape();
            if shape.family() != 1 || model.wide() {
                continue;
            }
            for (ordinal, policy, fraction, fo) in roles(&model, &[Role::Down]) {
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
                let found = [32767i64, 3000, 300, 30, 3, 0]
                    .into_iter()
                    .find_map(|peak| {
                        let inputs: Vec<Vec<i64>> = (0..3)
                            .map(|_| (0..d).map(|_| rng.range(-peak, peak)).collect())
                            .collect();
                        let rows = convert(policy, &inputs)?;
                        let outputs = affine(&rows.codes, &rows.scales, &weights, &m, shift)?;
                        Some((rows, outputs))
                    });
                let (rows, outputs) = found.expect("an executable row");
                grouped += usize::from(matches!(policy, Policy::Grouped(_)));
                let s = build(&rows, &weights, &m, shift, policy, bits, outputs).expect("honest");
                assert_eq!(
                    check(&s.relation, &s.values),
                    Ok(()),
                    "ordinal {ordinal} {policy:?}"
                );
                checked += 1;
            }
        }
    }
    assert!(
        checked >= 16 && grouped > 0,
        "{checked} checked, {grouped} grouped"
    );
}

/// `(ordinal, policy, row fraction, output fraction)` of every family-1 projection
/// whose input is an int16 row (`skip` roles excluded).
fn roles(
    model: &stele_cqis::model::Model,
    skip: &[stele_cqis::model::Role],
) -> Vec<(u16, Policy, u8, u8)> {
    use stele_cqis::model::Role;
    let shape = model.shape();
    let ordinal = |role: Role, layer: Option<u16>| {
        (0..shape.record_count())
            .find(|&o| {
                shape
                    .physical(o)
                    .is_some_and(|p| p.role() == role && p.layer() == layer)
            })
            .expect("record")
    };
    let policy = |p: stele_cqis::model::Policy| match p.mode() {
        0 => Policy::Dynamic,
        1 => Policy::Static(p.scale()),
        _ => Policy::Grouped(p.scale()),
    };
    let mut out = Vec::new();
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
            if !skip.contains(&role) {
                out.push((ordinal(role, layer), policy(p[row]), fraction, fo));
            }
        }
    }
    let fraction = model.final_norm().function().parameters()[4];
    out.push((
        ordinal(Role::Head, None),
        policy(model.final_policy()),
        fraction,
        model.logits_fraction(),
    ));
    out
}

/// The signed weight codes of one artifact record (`Data::code`'s decoding).
fn weights_of(model: &stele_cqis::model::Model, artifact: &[u8], ordinal: u16) -> Vec<Vec<i64>> {
    let layout = stele_cqis::model::ArtifactLayout::new(model).expect("layout");
    let record = layout
        .records()
        .iter()
        .find(|r| r.ordinal() == ordinal)
        .expect("record");
    let raw = &artifact[record.payload_offset() as usize..][..record.payload_length() as usize];
    let dims = model
        .shape()
        .physical(ordinal)
        .expect("physical")
        .dimensions()
        .to_vec();
    let (rows, columns) = (dims[0] as usize, dims.get(1).copied().unwrap_or(1) as usize);
    let code = |index: usize| -> i64 {
        match record.bits() {
            16 => i64::from(i16::from_le_bytes([raw[2 * index], raw[2 * index + 1]])),
            8 => i64::from(raw[index] as i8),
            _ => {
                let n = i64::from((raw[index / 2] >> (4 * (index % 2))) & 15);
                if n >= 8 {
                    n - 16
                } else {
                    n
                }
            }
        }
    };
    (0..rows)
        .map(|j| (0..columns).map(|k| code(j * columns + k)).collect())
        .collect()
}

/// RFC-0026 §3.7 against the real executor: `Executor::capture` on every family-1
/// fixture prompt it accepts supplies the rows, codes, scales and projection
/// outputs; the artifact supplies the weights.
#[test]
fn matches_reference_executor_capture() {
    use stele_cqis::execution::{capture::Quantised, Executor};
    use stele_cqis::model::{Model, Preparation, Scales};
    let mut checked = 0;
    for (json, bin) in CORPORA {
        for case in cases(json, bin) {
            let (Ok(model), Some(id)) = (Model::decode(case.model), case.artifact_id) else {
                continue;
            };
            if model.shape().family() != 1 || model.wide() || case.tokens.is_empty() {
                continue;
            }
            let Ok(scales) = Scales::decode(&model, case.scales) else {
                continue;
            };
            let Ok(preparation) = Preparation::decode(&model, case.preparation) else {
                continue;
            };
            let Ok(mut executor) =
                Executor::new(&model, &preparation, &scales, case.artifact, &id, 1 << 30)
            else {
                continue;
            };
            let Ok(capture) = executor.capture(&case.tokens) else {
                continue;
            };
            let roles = roles(&model, &[]);
            let layers = model.blocks().len();
            for (index, (ordinal, policy, _, _)) in roles.iter().enumerate() {
                let (layer, role) = (index / 7, index % 7);
                // The down row is E16-08's gated conversion.
                if layer < layers && role == 6 {
                    continue;
                }
                let picked: Vec<(&Quantised, &Vec<i64>)> = (0..case.tokens.len())
                    .map(|p| pick(&capture, layer, layers, role, p))
                    .collect();
                let rows = ConversionCapture {
                    inputs: picked.iter().map(|(q, _)| q.input.clone()).collect(),
                    codes: picked.iter().map(|(q, _)| q.codes.clone()).collect(),
                    scales: picked.iter().map(|(q, _)| q.scales.clone()).collect(),
                };
                let outputs = picked.iter().map(|(_, y)| (*y).clone()).collect();
                let weights = weights_of(&model, case.artifact, *ordinal);
                let matrix = scales.matrix(*ordinal).expect("matrix");
                let (_, _, fraction, fo) = roles[index];
                let shift = i32::from(matrix.exponent()) - i32::from(fraction) + i32::from(fo);
                let bits = model.formats()[*ordinal as usize].bits();
                let s = build(
                    &rows,
                    &weights,
                    matrix.mantissas(),
                    shift,
                    *policy,
                    bits,
                    outputs,
                )
                .expect("capture is consistent with the relations");
                assert_eq!(check(&s.relation, &s.values), Ok(()), "ordinal {ordinal}");
                checked += 1;
            }
        }
    }
    assert!(checked > 0, "no family-1 capture checked");
    std::println!("executor capture: {checked} projections checked");
}

/// The input row and projection output of one (layer, role, position) of a capture;
/// `layer == layers` is the head.
fn pick(
    capture: &stele_cqis::execution::Capture,
    layer: usize,
    layers: usize,
    role: usize,
    p: usize,
) -> (&stele_cqis::execution::capture::Quantised, &Vec<i64>) {
    if layer == layers {
        let head = &capture.head[p];
        return (&head.row, &head.logits.output.quotient);
    }
    let b = &capture.blocks[layer][p];
    let (row, projection) = match role {
        0 => (&b.first_row, &b.query),
        1 => (&b.first_row, &b.key),
        2 => (&b.first_row, &b.value),
        3 => (&b.attention_row, &b.output),
        4 => (&b.second_row, &b.up),
        _ => (&b.second_row, &b.gate),
    };
    (row, &projection.output.quotient)
}

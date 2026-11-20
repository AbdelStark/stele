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
pub(crate) fn affine(
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
    build_with_bits(rows, weights, m, shift, policy, bits, 16, outputs)
}

#[allow(clippy::too_many_arguments)]
fn build_with_bits(
    rows: &ConversionCapture,
    weights: &[Vec<i64>],
    m: &[u16],
    shift: i32,
    policy: Policy,
    bits: u8,
    output_bits: u8,
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
        output_bits,
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
            let q0 = case.honest.quotient[x];
            // Committed quotient +-1 (covers both off-by-one code and the other rounding direction).
            for wrong in [q0 - 1, q0 + 1]
                .into_iter()
                .filter(|v| (0..=127).contains(v))
            {
                let forged = case.forge(RStep::Quotient, x, wrong);
                assert!(
                    check(&case.relation, &forged).is_err(),
                    "{policy:?} lane {x} quotient {wrong}"
                );
            }
            // Flip sign when nonzero (flips virtual code sign).
            if case.honest.codes[x] != 0 {
                let forged = case.forge(RStep::Sign, x, 1 - case.honest.sign[x]);
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
    // Zero row with a nonzero code via committed floor=1 or half=1: rejected.
    let lane = 1 << 3; // row 1, lane 0
    let forged = case.forge(RStep::Floor, lane, 1);
    assert!(check(&case.relation, &forged).is_err());
    let forged = case.forge(RStep::Half, lane, 1);
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
    projection_case_within(policy, inputs, weights, m, shift, 0)
}

/// [`projection_case`] with each sum matmul split `splits` times into row blocks (A6).
fn projection_case_within(
    policy: Policy,
    inputs: &[Vec<i64>],
    weights: &[Vec<i64>],
    m: &[u16],
    shift: i32,
    splits: u8,
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
        output_bits: 16,
    };
    let mut projection = Projection::new("L0/q", input, None, plan).expect("plan");
    projection.limit = t + lo + ld - splits;
    projection.declare(&mut relation);
    assert!(
        relation.matmuls.is_empty(),
        "projection sums are virtual contractions (RFC-0028 §1.2)"
    );
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
                if case
                    .projection
                    .columns
                    .as_ref()
                    .expect("declared")
                    .mixed
                    .is_some()
                {
                    // Mixed-radix fast path: shifting top rounding carry by +-1 shifts virtual Y by +-1.
                    let mut w = case.honest.clone();
                    w.mixed_rcs.last_mut().expect("rc_last")[x] += delta;
                    let mut forged = case.values.clone();
                    case.projection
                        .write(&case.relation, &w, &mut forged, None)
                        .expect("write");
                    assert!(
                        check(&case.relation, &forged).is_err(),
                        "{policy:?} mixed rc_last[{x}] {delta:+}"
                    );
                } else {
                    // |Y| +-1 with virtual remainder limbs and virtual Y following.
                    let (forged, _) = case.forge(PStep::Magnitude, |l| l[0][x] += delta, None);
                    assert!(
                        check(&case.relation, &forged).is_err(),
                        "{policy:?} Y[{x}] {delta:+}"
                    );
                }
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
    let y = stele_ir::relation::eval_column(&s.relation, &s.values, output).expect("Y");
    let padded = y.len() - 1;
    assert_eq!(y[padded], 0);
    // Tampering a committed column on the padded cell is rejected.
    let mut values = s.values.clone();
    let cols = s.projection.columns.as_ref().expect("declared");
    let target = cols
        .mixed
        .as_ref()
        .map_or(cols.magnitude, |m| *m.rcs.last().expect("rc_last"));
    let mut col = values.get(&s.relation, target).expect("col").to_vec();
    col[padded] += 1;
    values.set(&s.relation, target, col).expect("col");
    assert!(check(&s.relation, &values).is_err());
    let codes = s.conversion.output().expect("declared").codes;
    let c = stele_ir::relation::eval_column(&s.relation, &s.values, codes).expect("codes");
    assert_eq!(c[30], 0); // row 0, padded lane 30 >= 24 is pinned to 0 by virtual definition
                          // Tampering committed quotient on the padded lane is rejected.
    let quotient = s.conversion.columns.expect("declared").quotient;
    let mut values = s.values.clone();
    let mut f = values
        .get(&s.relation, quotient)
        .expect("quotient")
        .to_vec();
    f[30] = 1;
    values.set(&s.relation, quotient, f).expect("quotient");
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
    let rules: [(&str, &str); 23] = [
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
        (
            "L0/q/fold_scale/",
            "scale byte range: s = sum 256^c s_c is fixed by the fold scale decomposition; \
             only the byte representation moves, never the product sum",
        ),
        (
            "L0/q/v0/range",
            "output-neutral: v0 + 2^r0 v1 = V identically; w0 + 2^r0 w1 + 2^K w2 = V*s \
             depends only on V; the range bounds v0*s for the bound rule mod p",
        ),
        (
            "L0/q/v1/range",
            "implied over Z by v0 = V - 2^r0 v1 in [0, 2^r0); width feeds the bound rule mod p",
        ),
        (
            "L0/q/c0/range",
            "implied over Z by w0 = v0*s - 2^r0 c0 in [0, 2^r0); width feeds the bound rule mod p",
        ),
        (
            "L0/q/q0/range",
            "implied over Z by w0 = C0 + 256*b0 - 2^r0 q0 in [0, 2^r0); width feeds the bound rule mod p",
        ),
        (
            "L0/q/b1/range",
            "implied over Z by b0 = C1 - 2^r0 b1 in [0, 2^r0); width feeds the bound rule mod p",
        ),
        (
            "L0/q/w2/range",
            "implied over Z by w1 = v1*s + c0 - 2^r1 w2 in [0, 2^r1); width feeds the bound rule mod p",
        ),
        (
            "L0/q/rc0/range",
            "implied over Z by rho0 = 2^r0 rc0 - w0*m - 1 + tau in [0, 2^r0); width feeds the bound rule mod p",
        ),
        (
            "L0/q/rc1/range",
            "implied over Z by rho1 = 2^r1 rc1 + 2^(r1-1) - w1*m - rc0 in [0, 2^r1); width feeds the bound rule mod p",
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
/// What a survey does to each constraint.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Delete it (`check_except`).
    Delete,
    /// Widen a range or range lookup by one bit (RFC-0026 §5.2 follow-up).
    Widen,
}

/// The constraint `name` one bit wider: `values` pass every other constraint and
/// the column lies in the wider width (a range's width plus one bit; a range
/// lookup's table `[0, t]` grown to `[0, 2t + 1]`). This evaluates the wider range
/// over Z directly, so 16-bit ranges, which the API cannot declare at 17 bits, are
/// surveyed too.
fn accepts_widened(relation: &Relation, values: &Values, name: &str) -> bool {
    let wider = if let Some(range) = relation.ranges.iter().find(|r| r.name == name) {
        let w = Width {
            bits: range.width.bits + 1,
            ..range.width
        };
        Some((range.column, w.min(), w.max()))
    } else {
        relation
            .lookups
            .iter()
            .find(|l| l.name == name)
            .map(|lookup| {
                let table = &relation.tables[lookup.table.0 as usize];
                let top = table.rows.iter().map(|row| row[0]).max().unwrap_or(0);
                (lookup.tuple[0].column, 0, 2 * top + 1)
            })
    };
    let Some((column, low, high)) = wider else {
        return false;
    };
    check_except(relation, values, &[name]).is_ok()
        && stele_ir::relation::eval_column(relation, values, column)
            .is_ok_and(|v| v.iter().all(|x| (low..=high).contains(x)))
}

fn survey_mode<F>(
    mode: Mode,
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
    let filter_bad = |mut list: Vec<Candidate>| {
        list.retain(|c| check(relation, &c.values).is_err());
        list
    };
    let plain = filter_bad(forged(None, 0));
    let frozen = core::cell::OnceCell::new();
    let names: Vec<String> = match mode {
        Mode::Delete => constraints(relation, prefix),
        Mode::Widen => relation
            .ranges
            .iter()
            .map(|r| &r.name)
            .chain(relation.lookups.iter().map(|l| &l.name))
            .filter(|n| n.starts_with(prefix))
            .cloned()
            .collect(),
    };
    names
        .into_iter()
        .map(|name| {
            let skip = [name.as_str()];
            let position = chain_position(&name)
                .filter(|_| mode == Mode::Delete)
                .filter(|(chain, _)| {
                    relation.identities.iter().any(|i| {
                        i.name.starts_with(&alloc::format!("{chain}/")) && *chain != prefix
                    })
                });
            let mut outcome = Outcome::Survived;
            'phases: for phase in 0..2 {
                let fresh;
                let candidates = match (position, phase) {
                    (None, 0) => &plain,
                    (None, _) => frozen.get_or_init(|| filter_bad(forged(None, 1))),
                    (skip, phase) => {
                        fresh = filter_bad(forged(skip, phase));
                        &fresh
                    }
                };
                for c in candidates {
                    let mutated_accepts = match mode {
                        Mode::Delete => check_except(relation, &c.values, &skip).is_ok(),
                        Mode::Widen => accepts_widened(relation, &c.values, &name),
                    };
                    if !mutated_accepts {
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
    report_with(rows, explanation)
}

fn report_with(
    rows: &[(String, Outcome)],
    explanation: fn(&str) -> Option<&'static str>,
) -> Vec<String> {
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

fn row_survey(policy: Policy, mode: Mode) -> Vec<(String, Outcome)> {
    let case = row_case(policy, &row_inputs_for(policy));
    let c = case.conversion.columns.expect("declared");
    let outputs = |v: &Values| {
        let mut o = stele_ir::relation::eval_column(&case.relation, v, c.codes).expect("codes");
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
    survey_mode(
        mode,
        &case.relation,
        "L0/row/",
        &case.values,
        outputs,
        forged,
    )
}

const PROJECTION_DELTAS: [i64; 10] = [1, -1, 2, -2, 255, -255, 256, -256, 65536, -65536];

fn projection_survey(
    policy: Policy,
    inputs: &[Vec<i64>],
    weights: &[Vec<i64>],
    m: &[u16],
    shift: i32,
    mode: Mode,
) -> Vec<(String, Outcome)> {
    projection_survey_within(policy, inputs, weights, m, shift, mode, 0)
}

fn projection_survey_within(
    policy: Policy,
    inputs: &[Vec<i64>],
    weights: &[Vec<i64>],
    m: &[u16],
    shift: i32,
    mode: Mode,
    splits: u8,
) -> Vec<(String, Outcome)> {
    std::println!("projection, {policy:?}, l = {shift}, {splits} row-block splits");
    let case = projection_case_within(policy, inputs, weights, m, shift, splits);
    let output = case.projection.output().expect("declared");
    let outputs =
        |v: &Values| stele_ir::relation::eval_column(&case.relation, v, output).expect("Y");
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
        // For virtual remainder limbs in the `"round"` chain (RFC-0028 §1.2), recompute
        // the chain's carries so each virtual remainder limb evaluates to `w.remainder[k]`.
        let sync_round_carries = |values: &mut Values, w: &ProjectionWitness| {
            let Some(pcols) = case.projection.columns.as_ref() else {
                return;
            };
            if pcols.mixed.is_some() || w.remainder.is_empty() {
                return;
            }
            let Some((_, chain)) = pcols.chains.iter().find(|(n, _)| n.ends_with("/round")) else {
                return;
            };
            let size = 1usize << chain.vars;
            let n = chain.positions.len();
            let mut cache: alloc::collections::BTreeMap<ColumnId, Vec<i64>> =
                alloc::collections::BTreeMap::new();
            for terms in &chain.positions {
                for t in terms {
                    for f in &t.factors {
                        cache.entry(f.column).or_insert_with(|| {
                            stele_ir::relation::eval_column(&case.relation, values, f.column)
                                .expect("eval")
                        });
                    }
                }
            }
            let mut cols: Vec<Vec<i64>> = vec![vec![0; size]; n];
            for x in 0..size {
                let mut carry = 0i128;
                for (k, terms) in chain.positions.iter().enumerate() {
                    let mut sum = carry;
                    for t in terms {
                        let mut p = i128::from(t.coeff);
                        for f in &t.factors {
                            p *= i128::from(cache[&f.column][f.index(x as u64)]);
                        }
                        sum += p;
                    }
                    if k < w.remainder.len() {
                        sum -= i128::from(w.remainder[k][x]);
                    }
                    carry = sum.div_euclid(1 << chain.radix);
                    cols[k][x] = carry as i64;
                }
            }
            for (carry, column) in chain.carries.iter().zip(cols) {
                match *carry {
                    None => {}
                    Some(crate::development::Carry::One(c)) => {
                        values.set(&case.relation, c, column).expect("carry");
                    }
                    Some(crate::development::Carry::Split(lo, hi)) => {
                        values
                            .set(
                                &case.relation,
                                lo,
                                column.iter().map(|v| v.rem_euclid(1 << 16)).collect(),
                            )
                            .expect("lo");
                        values
                            .set(
                                &case.relation,
                                hi,
                                column.iter().map(|v| v.div_euclid(1 << 16)).collect(),
                            )
                            .expect("hi");
                    }
                }
            }
        };
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
                    let (description, mut values, rejected, w) = custom(
                        alloc::format!("Magnitude[{x}] {d:+}, remainder limb {r} absorbs it"),
                        &lie,
                        Some(PStep::Output),
                        skip,
                    );
                    sync_round_carries(&mut values, &w);
                    all.push(Candidate {
                        description,
                        values,
                        rejected,
                    });
                }
            }
            // |Y| - 1 with rho + 2^K packed greedily into limbs whose limb `r` may use one
            // more bit: in range only once that limb's range is widened.
            for r in 0..case.honest.remainder.len() {
                let widths: Vec<u8> = case
                    .projection
                    .columns
                    .as_ref()
                    .expect("declared")
                    .remainder
                    .iter()
                    .map(|id| {
                        case.relation
                            .ranges
                            .iter()
                            .find(|rg| rg.column == *id)
                            .map_or(case.relation.columns[id.0 as usize].width.bits, |rg| {
                                rg.width.bits
                            })
                    })
                    .collect();
                let lie = move |w: &mut ProjectionWitness| {
                    let rho: i128 = w
                        .remainder
                        .iter()
                        .enumerate()
                        .map(|(i, l)| i128::from(l[x]) << (8 * i))
                        .sum();
                    w.magnitude[x] -= 1;
                    let mut rest = rho + (1i128 << k_bits);
                    for i in (0..w.remainder.len()).rev() {
                        let bits = widths[i] + u8::from(i == r);
                        let limb = (rest >> (8 * i)).min((1 << bits) - 1);
                        w.remainder[i][x] = limb as i64;
                        rest -= limb << (8 * i);
                    }
                };
                let (description, mut values, rejected, w) = custom(
                    alloc::format!(
                        "Magnitude[{x}] -1, rho + 2^K packed with limb {r} one bit wider"
                    ),
                    &lie,
                    Some(PStep::Output),
                    skip,
                );
                sync_round_carries(&mut values, &w);
                all.push(Candidate {
                    description,
                    values,
                    rejected,
                });
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
        // Mixed-radix fast path: mutate committed columns directly, plus targeted
        // sign/tie/borrow/carry-bump attacks.
        let pcols = case.projection.columns.as_ref().expect("declared");
        if let Some(mc) = &pcols.mixed {
            let mut committed: Vec<(String, ColumnId)> = Vec::new();
            for (i, &cid) in mc.head.iter().enumerate() {
                committed.push((alloc::format!("head{i}"), cid));
            }
            committed.push(("w_top".into(), mc.w_top));
            committed.push(("sign".into(), pcols.sign));
            for (i, &cid) in mc.rcs.iter().enumerate() {
                committed.push((alloc::format!("rc{i}"), cid));
            }
            for (i, &cid) in mc.out_cols.iter().enumerate() {
                committed.push((alloc::format!("out{i}"), cid));
            }
            let rad0 = 1i64 << mc.plan.radices[0];
            let rad1 = 1i64 << mc.plan.radices[1];
            let len = case.honest.sign.len();
            for x in 0..len {
                for (cname, cid) in &committed {
                    for delta in [1i64, -1, 2, -2, rad0, -rad0, rad1, -rad1] {
                        let mut v = case.values.clone();
                        let mut col = v.get(&case.relation, *cid).expect("c").to_vec();
                        col[x] += delta;
                        v.set(&case.relation, *cid, col).expect("s");
                        all.push(Candidate {
                            description: alloc::format!("mixed {cname}[{x}] {delta:+}"),
                            values: v,
                            rejected: false,
                        });
                    }
                }
                // Flip sign and/or bump (w_top, rc0, rc_last) together to kill twos, w*, rho*.
                let s0 = case.values.get(&case.relation, pcols.sign).expect("s")[x];
                let w_top_0 = case.values.get(&case.relation, mc.w_top).expect("w_top")[x];
                let rc0_id = mc.rcs[0];
                let rc_last_id = *mc.rcs.last().expect("rc_last");
                let rc0_0 = case.values.get(&case.relation, rc0_id).expect("rc0")[x];
                let rc1_0 = case
                    .values
                    .get(&case.relation, rc_last_id)
                    .expect("rc_last")[x];
                for dw in [-1i64, 0, 1] {
                    for s_new in [0i64, 1, -1, 2] {
                        for d0 in [-1i64, 0, 1] {
                            for d1 in [-1i64, 0, 1] {
                                if dw == 0 && s_new == s0 && d0 == 0 && d1 == 0 {
                                    continue;
                                }
                                let mut v = case.values.clone();
                                let set_at = |v: &mut Values, id: ColumnId, val: i64| {
                                    let mut col = v.get(&case.relation, id).expect("c").to_vec();
                                    col[x] = val;
                                    v.set(&case.relation, id, col).expect("s");
                                };
                                set_at(&mut v, mc.w_top, w_top_0 + dw);
                                set_at(&mut v, pcols.sign, s_new);
                                set_at(&mut v, rc0_id, rc0_0 + d0);
                                set_at(&mut v, rc_last_id, rc1_0 + d1);
                                all.push(Candidate {
                                    description: alloc::format!(
                                        "mixed[{x}] w_top{dw:+} sign={s_new} rc0{d0:+} rc_last{d1:+}"
                                    ),
                                    values: v,
                                    rejected: false,
                                });
                            }
                        }
                    }
                }
                if let super::projection::MixedKind::PerRow {
                    c0_width: Some(_),
                    q1_width: None,
                    ..
                } = mc.plan.kind
                {
                    let (v1_id, c0_id) = (mc.head[0], mc.head[1]);
                    let c0_0 = case.values.get(&case.relation, c0_id).expect("c0")[x];
                    let v1_0 = case.values.get(&case.relation, v1_id).expect("v1")[x];
                    let v_val = i128::from(case.honest.sums[0][x]);
                    let v0_0 = v_val - i128::from(rad0) * i128::from(v1_0);
                    let (_, ld, lg, lo) = case.projection.logs();
                    let (row_idx, j_idx) = (x >> lo, x & ((1 << lo) - 1));
                    let s_val = i128::from(case.honest.scales[row_idx << (ld - lg)]);
                    let m_val = i128::from(m.get(j_idx).copied().unwrap_or(0));
                    for dc0 in [-1i64, 1] {
                        let c0_new = c0_0 + dc0;
                        let w0_new = v0_0 * s_val - i128::from(rad0) * i128::from(c0_new);
                        for dw2 in [-1i64, 0, 1] {
                            let w2_new = w_top_0 + dw2;
                            let w1_new = i128::from(v1_0) * s_val + i128::from(c0_new)
                                - i128::from(rad1) * i128::from(w2_new);
                            for s_new in [0i64, 1] {
                                let rc0_new = (w0_new * m_val - i128::from(s_new)
                                    + i128::from(rad0))
                                .div_euclid(i128::from(rad0))
                                    as i64;
                                let rc1_new =
                                    (w1_new * m_val + i128::from(rc0_new) + i128::from(rad1 / 2)
                                        - 1)
                                    .div_euclid(i128::from(rad1))
                                        as i64;
                                let mut v = case.values.clone();
                                let set_at = |v: &mut Values, id: ColumnId, val: i64| {
                                    let mut col = v.get(&case.relation, id).expect("c").to_vec();
                                    col[x] = val;
                                    v.set(&case.relation, id, col).expect("s");
                                };
                                set_at(&mut v, c0_id, c0_new);
                                set_at(&mut v, mc.w_top, w2_new);
                                set_at(&mut v, pcols.sign, s_new);
                                set_at(&mut v, rc0_id, rc0_new);
                                set_at(&mut v, rc_last_id, rc1_new);
                                all.push(Candidate {
                                    description: alloc::format!(
                                        "mixed[{x}] c0{dc0:+} w2{dw2:+} sign={s_new} rc0={rc0_new} rc1={rc1_new}"
                                    ),
                                    values: v,
                                    rejected: false,
                                });
                            }
                        }
                    }
                }
                // Grouped2: bump q0/b1 and rebalance (w_top, sign, rc0, rc_last) to kill w0/w1/b0.
                if let super::projection::MixedKind::Grouped2 {
                    b1_width,
                    q1_width: None,
                    ..
                } = mc.plan.kind
                {
                    let (_, _, _, lo) = case.projection.logs();
                    let j_idx = x & ((1 << lo) - 1);
                    let m_val = i128::from(m.get(j_idx).copied().unwrap_or(0));
                    let c0_val = i128::from(case.honest.sums[0][x]);
                    let c1_val = i128::from(case.honest.sums[1][x]);
                    let q0_id = if b1_width.is_some() {
                        mc.head[1]
                    } else {
                        mc.head[0]
                    };
                    let q0_0 = case.values.get(&case.relation, q0_id).expect("q0")[x];
                    let b1_id_opt = b1_width.map(|_| mc.head[0]);
                    let b1_0 = b1_id_opt
                        .map_or(0, |id| case.values.get(&case.relation, id).expect("b1")[x]);
                    for (db1, dq0) in [(0i64, -1i64), (0, 1), (-1, 0), (1, 0)] {
                        if db1 != 0 && b1_id_opt.is_none() {
                            continue;
                        }
                        let b1_new = b1_0 + db1;
                        let q0_new = q0_0 + dq0;
                        let (w0_new, w1_full) = if b1_id_opt.is_some() {
                            let b0_new = c1_val - i128::from(rad0) * i128::from(b1_new);
                            (
                                c0_val + 256 * b0_new - i128::from(rad0) * i128::from(q0_new),
                                i128::from(q0_new) + 256 * i128::from(b1_new),
                            )
                        } else {
                            (
                                c0_val + 256 * c1_val - i128::from(rad0) * i128::from(q0_new),
                                i128::from(q0_new),
                            )
                        };
                        for dw2 in [-1i64, 0, 1] {
                            let w2_new = w_top_0 + dw2;
                            let w1_new = w1_full - i128::from(rad1) * i128::from(w2_new);
                            for s_new in [0i64, 1] {
                                let rc0_new = (w0_new * m_val - i128::from(s_new)
                                    + i128::from(rad0))
                                .div_euclid(i128::from(rad0))
                                    as i64;
                                let rc1_new =
                                    (w1_new * m_val + i128::from(rc0_new) + i128::from(rad1 / 2)
                                        - 1)
                                    .div_euclid(i128::from(rad1))
                                        as i64;
                                let mut v = case.values.clone();
                                let set_at = |v: &mut Values, id: ColumnId, val: i64| {
                                    let mut col = v.get(&case.relation, id).expect("c").to_vec();
                                    col[x] = val;
                                    v.set(&case.relation, id, col).expect("s");
                                };
                                if let Some(b1_id) = b1_id_opt {
                                    set_at(&mut v, b1_id, b1_new);
                                }
                                set_at(&mut v, q0_id, q0_new);
                                set_at(&mut v, mc.w_top, w2_new);
                                set_at(&mut v, pcols.sign, s_new);
                                set_at(&mut v, rc0_id, rc0_new);
                                set_at(&mut v, rc_last_id, rc1_new);
                                all.push(Candidate {
                                    description: alloc::format!(
                                        "grouped2[{x}] b1{db1:+} q0{dq0:+} w2{dw2:+} sign={s_new}"
                                    ),
                                    values: v,
                                    rejected: false,
                                });
                            }
                        }
                    }
                }
            }
        }
        // Overflowing inputs that wrap modulo 256^k when a high `round/k` or `sign/k`
        // identity is deleted: honest `code = 64` (power of two) yields an exact multiple
        // of 2^24 or 2^32, so wrapping `Magnitude` or `Bytes` to 0 stays inside int16.
        if let Some((chain, k)) = skip {
            if pcols.mixed.is_none() && (chain.ends_with("/round") || chain.ends_with("/sign")) {
                let is_sign = chain.ends_with("/sign");
                for &code in &[4i64, 64, 127] {
                    let mut w = case.honest.clone();
                    let d_len = inputs[0].len();
                    for lane in 0..d_len {
                        if weights[0][lane] != 0 {
                            w.codes[lane] = code;
                        }
                    }
                    case.projection.complete(&mut w, PStep::Digits, None);
                    let honest_rejected = w.output.iter().any(|&y| i16::try_from(y).is_err());
                    if !honest_rejected {
                        continue;
                    }
                    if is_sign {
                        let modulus = 1i128 << (8 * k);
                        for x in 0..w.sign.len() {
                            let v_abs: i128 = w
                                .bytes
                                .iter()
                                .enumerate()
                                .map(|(j, b)| i128::from(b[x]) << (8 * j))
                                .sum();
                            let wrapped = v_abs % modulus;
                            for (j, b) in w.bytes.iter_mut().enumerate() {
                                b[x] = ((wrapped >> (8 * j)) & 255) as i64;
                            }
                        }
                        case.projection.complete(&mut w, PStep::Magnitude, None);
                    } else {
                        let k_bits = (-shift).max(0) as u32;
                        let shift_up = shift.max(0) as u32;
                        let step_bits = (8 * k as u32).saturating_sub(k_bits);
                        if step_bits == 0 || step_bits >= 62 {
                            continue;
                        }
                        let modulus = 1i128 << step_bits;
                        for x in 0..w.magnitude.len() {
                            let y_abs = i128::from(w.magnitude[x]);
                            if y_abs > 32767 {
                                let w_mag = (y_abs % modulus) >> shift_up;
                                w.magnitude[x] = (w_mag << shift_up) as i64;
                            }
                        }
                        case.projection.complete(&mut w, PStep::Output, None);
                    }
                    let mut values = case.values.clone();
                    values
                        .set(&case.relation, case.codes, w.codes.clone())
                        .expect("codes");
                    if case
                        .projection
                        .write(&case.relation, &w, &mut values, skip)
                        .is_ok()
                    {
                        all.push(Candidate {
                            description: alloc::format!(
                                "overflow code={code} wrapped at {chain}/{k}"
                            ),
                            values,
                            rejected: true,
                        });
                    }
                }
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
    survey_mode(mode, &case.relation, "L0/q/", &case.values, outputs, forged)
}

fn kept(frozen: Option<PStep>) -> String {
    frozen.map_or(String::new(), |f| alloc::format!(", {f:?} kept"))
}

/// Why widening a range or range lookup by one bit changes no output over Z.
fn widen_reason(name: &str) -> Option<&'static str> {
    let rules: [(&str, &str); 30] = [
        ("/carry", "chain carries are fixed by their position identities; width only feeds the bound rule"),
        ("/weight/range", "committed model data, never prover-chosen (RFC-0026 §2.2)"),
        ("L0/row/magnitude/range", "a = |x| <= 32768 by the sign identity with sigma in {0,1}"),
        ("L0/row/floor/range", "q0 = q - beta <= 127 by the quotient range"),
        ("L0/row/remainder/range", "rho <= D - 1 by spare >= 0; the lower bound 0 is unchanged"),
        ("L0/row/spare/range", "spare = D - 1 - rho <= D - 1 since rho >= 0; the lower bound is unchanged"),
        ("L0/row/half_gap/range", "half_gap <= D by its identity; only the unchanged lower bound 0 matters"),
        ("L0/row/codes/range", "c = (1 - 2 sigma) q with |q| <= 127"),
        ("L0/row/scale/range", "127 s = M + slack <= 32768 + 126, so s <= 259"),
        ("L0/row/zero/range", "z only matters where M = 0, where a = 0 gives q = 0 for any divisor"),
        ("L0/row/maximum/range", "M = a_j <= 32768 at a hit lane"),
        ("L0/row/gap/range", "gap = M - a; only the unchanged lower bound 0 matters"),
        ("L0/row/hit/range", "sum h = 1 over nonnegative h forces exactly one h = 1"),
        ("L0/row/quotient/range", "dynamic: q <= 127 since a <= M <= 127 s; static: killed by an overflowing input"),
        ("L0/q/digit/", "the fold fixes b0 + 256 b1 = q*s; V depends only on that sum"),
        ("L0/q/byte/", "bytes stay nonnegative, so (1 - 2 tau) sum 256^k v_k = V fixes tau and the sum; P uses only the sum"),
        ("L0/q/scale/", "s = sum 256^c s_c is fixed by the scale identity; P uses only the sum"),
        ("L0/q/fold_scale/", "s = sum 256^c s_c is fixed by the fold scale decomposition; P uses only the sum"),
        ("L0/q/v0/range", "v0 + 2^r0 v1 = V identically; w0 + 2^r0 w1 + 2^K w2 = V*s depends only on V"),
        ("L0/q/v1/range", "v1 is fixed over Z by v0 in [0, 2^r0); width only feeds the bound rule"),
        ("L0/q/c0/range", "c0 is fixed over Z by w0 in [0, 2^r0); width only feeds the bound rule"),
        ("L0/q/q0/range", "q0 is fixed over Z by w0 in [0, 2^r0); width only feeds the bound rule"),
        ("L0/q/b1/range", "b1 is fixed over Z by b0 in [0, 2^r0); width only feeds the bound rule"),
        ("L0/q/w0/range", "widened w0 stays nonnegative, so w0 + 2^r0 w1 + 2^K w2 = V*s keeps w2 sign when w0 + 2^r0 w1 < 2^K; width feeds the bound rule"),
        ("L0/q/w2/range", "w2 is fixed over Z by w1 in [0, 2^r1); width only feeds the bound rule"),
        ("L0/q/rc0/range", "rc0 is fixed over Z by rho0 in [0, 2^r0); width only feeds the bound rule"),
        ("L0/q/rc1/range", "rc1 is fixed over Z by rho1 in [0, 2^r1); width only feeds the bound rule"),
        ("L0/q/magnitude/range", "Ymag is fixed by the rounding chain; |Y| is bounded by the output range"),
        ("L0/q/sign/range", "twos = w2 + 2^b sign in [0, 2^b) already forces sign in {0, 1}; width only feeds the bound rule"),
        ("L0/q/output/range", "UNUSED"),
    ];
    rules
        .iter()
        .filter(|(_, reason)| *reason != "UNUSED")
        .find(|(pattern, _)| name.contains(pattern))
        .map(|(_, reason)| *reason)
}

/// Every unexplained widening survivor must be killed in some table.
fn assert_widening_covered(tables: &[Vec<(String, Outcome)>]) {
    let killed: Vec<&String> = tables
        .iter()
        .flatten()
        .filter(|(_, o)| matches!(o, Outcome::Killed(_)))
        .map(|(n, _)| n)
        .collect();
    let mut open: Vec<String> = tables
        .iter()
        .flat_map(|t| report_with(t, widen_reason))
        .filter(|n| !killed.contains(&n))
        .collect();
    open.dedup();
    assert!(open.is_empty(), "unexplained widening survivors: {open:?}");
}

#[test]
fn survey_row_conversion_constraints() {
    for policy in [Policy::Dynamic, Policy::Grouped(2), Policy::Static(5)] {
        std::println!("row conversion, {policy:?}");
        assert_covered(&[row_survey(policy, Mode::Delete)]);
    }
}

fn projection_tables(mode: Mode) -> Vec<Vec<(String, Outcome)>> {
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
    vec![
        projection_survey(
            Policy::Dynamic,
            &inputs,
            &weights,
            &m,
            fit(Policy::Dynamic),
            mode,
        ),
        projection_survey(
            Policy::Grouped(2),
            &inputs,
            &weights,
            &m,
            fit(Policy::Grouped(2)),
            mode,
        ),
        projection_survey(
            Policy::Static(300),
            &inputs,
            &weights,
            &m,
            fit(Policy::Static(300)),
            mode,
        ),
        projection_survey(Policy::Dynamic, &inputs, &weights, &m, -200, mode),
        // Row blocks of the weight (RFC-0026 A6): one real output channel per block,
        // so deleting any block's matmul must let a forged sum through to an output.
        {
            let mut weights = weights.clone();
            weights.push(vec![-9, 8, -7, 6, -5, 4]);
            let m = [m.as_slice(), &[777]].concat();
            projection_survey_within(
                Policy::Dynamic,
                &inputs,
                &weights,
                &m,
                fit(Policy::Dynamic),
                mode,
                2,
            )
        },
        // l = 9 >= 0 with small codes; a code of 127 overflows int16.
        projection_survey(
            Policy::Static(1),
            &[vec![3, -2, 1, 0]],
            &[vec![1, 1, 0, 0], vec![1, 0, 0, 0]],
            &[1, 3],
            9,
            mode,
        ),
        // Exact ties: P = 2^(K-1) with V = 1 (K = 1) and V = 256 (K = 9), and with
        // three and four sign-chain bytes (4 lanes; grouped digit rows).
        projection_survey(Policy::Static(1), &tie(1), &[vec![1, 0]], &[1], -1, mode),
        // V = -3: a sign bit widened to 2 bits admits tau = 2, (1 - 2 tau) = -3.
        projection_survey(Policy::Static(1), &tie(3), &[vec![1, 0]], &[1], -1, mode),
        projection_survey(
            Policy::Static(1),
            &[vec![1, 0, 0, 0], vec![-1, 0, 0, 0]],
            &[vec![1, 0, 0, 0]],
            &[1],
            -1,
            mode,
        ),
        projection_survey(
            Policy::Grouped(2),
            &[vec![1, 0, 0, 0], vec![-1, 0, 0, 0]],
            &[vec![1, 0, 0, 0]],
            &[1],
            -1,
            mode,
        ),
        projection_survey(
            Policy::Static(1),
            &[vec![64, 64], vec![-64, -64]],
            &[vec![2, 2]],
            &[1],
            -9,
            mode,
        ),
        // Mixed-radix tie with c0 present (s = 2, V = -1, m = 2, K = 3, r0 = 2, r1 = 1):
        // deleting w0/range admits c0 += 1, w2 += 1, sign = 0, rc0 = 0 >= 0, flipping -1 to 0.
        projection_survey(
            Policy::Static(2),
            &[vec![2, 0], vec![-2, 0]],
            &[vec![1, 0]],
            &[2],
            -3,
            mode,
        ),
        // General-path overflow at l = -1 (K = 1, outside mixed-radix): code = 4 gives
        // P = 4 * 128 * 256 * 32768 = 2^32, killing round/2, round/3, round/4 via wrapping.
        projection_survey(
            Policy::Static(256),
            &[vec![0, 0]],
            &[vec![-128, 0]],
            &[32768],
            -1,
            mode,
        ),
        // General-path grouped overflow at l = -1: 16 lanes (8 groups of 2) with
        // scale = 256, m = 256 (even lanes have x = 32512, w = 0; odd lanes have
        // x = 0, w = -128): honest Y = 0, while code = 64 on odd lanes gives
        // |V| = 2^24 and P = 2^32, killing sign/3 and round/2..4 via wrapping.
        projection_survey(
            Policy::Grouped(2),
            &[vec![
                32512, 0, 32512, 0, 32512, 0, 32512, 0, 32512, 0, 32512, 0, 32512, 0, 32512, 0,
            ]],
            &[vec![
                0, -128, 0, -128, 0, -128, 0, -128, 0, -128, 0, -128, 0, -128, 0, -128,
            ]],
            &[256],
            -1,
            mode,
        ),
    ]
}

#[test]
fn survey_projection_constraints() {
    assert_covered(&projection_tables(Mode::Delete));
}

#[test]
fn survey_projection_range_widening() {
    assert_widening_covered(&projection_tables(Mode::Widen));
}

#[test]
fn survey_row_conversion_range_widening() {
    let tables: Vec<_> = [Policy::Dynamic, Policy::Grouped(2), Policy::Static(5)]
        .into_iter()
        .map(|policy| {
            std::println!("row conversion widening, {policy:?}");
            row_survey(policy, Mode::Widen)
        })
        .collect();
    assert_widening_covered(&tables);
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
        output_bits: 16,
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
        output_bits: 16,
    };
    let mut projection = Projection::new("L0/down", input, None, plan).expect("plan");
    projection.declare(&mut relation);
    assert_eq!(relation.validate(), Ok(()));
}

#[test]
fn accepts_projection_domain_over_max_vars_in_row_blocks() {
    // T=64, d=o=8192: 6 + 13 + 13 bits, so each sum matmul is four row blocks (A6).
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
        output_bits: 16,
    };
    let output = conversion.output().expect("declared");
    let mut projection = Projection::new("L0/q", output, None, plan).expect("plan");
    projection.declare(&mut relation);
    assert_eq!(relation.validate(), Ok(()));
    assert!(
        !relation.matmuls.iter().any(|m| m.name.starts_with("L0/q/")),
        "virtual Contraction handles free + summed > MAX_VARS directly (RFC-0028 §2.1)"
    );
    let sum0 = projection.columns.as_ref().expect("declared").sums[0];
    assert!(matches!(
        relation.columns[sum0.0 as usize].kind,
        Kind::Virtual(stele_ir::relation::Def::Contraction {
            free: 19,
            summed: 13,
            ..
        })
    ));
}

#[test]
fn rejects_projection_output_domain_over_max_vars() {
    // The output domain (rows, outputs) carries identities, which are never split.
    let mut relation = Relation::default();
    let input = Builder::new(&mut relation, "L0/norm").witness("output", Width::signed(16), 6 + 4);
    let mut conversion =
        RowConversion::new("L0/row", input, 64, 16, Policy::Dynamic).expect("row plan");
    conversion.declare(&mut relation);
    let plan = ProjectionPlan {
        rows: 64,
        inner: 16,
        outputs: 1 << 25,
        weight_bits: 8,
        mantissas: vec![1; 1 << 25],
        shift: -20,
        output_bits: 16,
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

const CORPORA: [(&str, &[u8]); 4] = [
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
    (
        include_str!("../../../stele-cqis/tests/fixtures/wide-residual.json"),
        include_bytes!("../../../stele-cqis/tests/fixtures/wide-residual.bin"),
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
    let (mut checked, mut wide_checked, mut grouped_down) = (0, 0, 0);
    for (json, bin) in CORPORA {
        for case in cases(json, bin) {
            let (Ok(model), Some(id)) = (Model::decode(case.model), case.artifact_id) else {
                continue;
            };
            if model.shape().family() != 1 || case.tokens.is_empty() {
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
                let weights = weights_of(&model, case.artifact, *ordinal);
                let matrix = scales.matrix(*ordinal).expect("matrix");
                let (_, _, fraction, fo) = roles[index];
                let shift = i32::from(matrix.exponent()) - i32::from(fraction) + i32::from(fo);
                let bits = model.formats()[*ordinal as usize].bits();
                let output_bits = if model.wide() && layer < layers && matches!(role, 3 | 6) {
                    24
                } else {
                    16
                };
                if layer < layers && role == 6 {
                    // Check dynamic and grouped gated down projections (E16-08 / E22-03).
                    if matches!(policy, Policy::Static(_)) {
                        continue;
                    }
                    let tokens = case.tokens.len();
                    let hidden = usize::from(model.shape().hidden());
                    let n = log2_ceil(tokens) + log2_ceil(hidden);
                    let mut relation = Relation::default();
                    let g = relation.add_group("L0/gated/test", n);
                    let limb_bits = crate::silu::LOW_BITS;
                    let h_hi =
                        relation.add_column("high/hi", Kind::Witness(g), Width::signed(2), n);
                    let h_lo =
                        relation.add_column("high/lo", Kind::Witness(g), Width::unsigned(15), n);
                    let low =
                        relation.add_column("low", Kind::Witness(g), Width::unsigned(limb_bits), n);
                    for (col, w) in [
                        (h_hi, Width::signed(2)),
                        (h_lo, Width::unsigned(15)),
                        (low, Width::unsigned(limb_bits)),
                    ] {
                        relation.ranges.push(Range {
                            name: "limb".into(),
                            column: col,
                            width: w,
                        });
                    }
                    let high = relation.add_virtual(
                        "high",
                        stele_ir::relation::Def::Linear {
                            constant: 0,
                            terms: vec![(1 << 15, r(h_hi, 0..n)), (1, r(h_lo, 0..n))],
                        },
                        n,
                    );
                    let mut conv = crate::silu::GatedConversion::new(
                        layer, high, low, tokens, hidden, *policy,
                    )
                    .expect("gated conv plan");
                    conv.declare(&mut relation);
                    let plan = ProjectionPlan {
                        rows: tokens,
                        inner: hidden,
                        outputs: weights.len(),
                        weight_bits: bits,
                        mantissas: matrix.mantissas().to_vec(),
                        shift,
                        output_bits,
                    };
                    let mut proj =
                        Projection::new("L0/down", conv.output().expect("declared"), None, plan)
                            .expect("down plan");
                    proj.declare(&mut relation);
                    let mut values = Values::new(&relation);
                    let product: Vec<i64> = (0..tokens)
                        .flat_map(|p| capture.blocks[layer][p].gated.iter().copied())
                        .collect();
                    let d = log2_ceil(hidden);
                    let limb = 1i64 << limb_bits;
                    let mut h_hi_col = vec![0i64; 1 << n];
                    let mut h_lo_col = vec![0i64; 1 << n];
                    let mut l_col = vec![0i64; 1 << n];
                    for p in 0..tokens {
                        for j in 0..hidden {
                            let v = product[p * hidden + j];
                            let q = v.div_euclid(limb);
                            h_hi_col[(p << d) | j] = q.div_euclid(1 << 15);
                            h_lo_col[(p << d) | j] = q.rem_euclid(1 << 15);
                            l_col[(p << d) | j] = v.rem_euclid(limb);
                        }
                    }
                    values.set(&relation, h_hi, h_hi_col).expect("high/hi");
                    values.set(&relation, h_lo, h_lo_col).expect("high/lo");
                    values.set(&relation, low, l_col).expect("low");
                    conv.assign(&relation, &product, &mut values).expect("conv");
                    let lo = log2_ceil(weights.len());
                    values
                        .set(
                            &relation,
                            proj.weight().expect("w"),
                            padded(&weights, lo, d),
                        )
                        .expect("weight");
                    let down_cap = ProjectionCapture {
                        codes: (0..tokens)
                            .map(|p| capture.blocks[layer][p].down_row.codes.clone())
                            .collect(),
                        scales: (0..tokens)
                            .map(|p| capture.blocks[layer][p].down_row.scales.clone())
                            .collect(),
                        weights,
                        outputs: (0..tokens)
                            .map(|p| capture.blocks[layer][p].down.output.quotient.clone())
                            .collect(),
                    };
                    proj.assign(&relation, &down_cap, &mut values)
                        .expect("down capture consistent");
                    assert_eq!(check(&relation, &values), Ok(()), "down ordinal {ordinal}");
                    checked += 1;
                    wide_checked += usize::from(output_bits == 24);
                    grouped_down += usize::from(matches!(policy, Policy::Grouped(_)));
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
                let s = build_with_bits(
                    &rows,
                    &weights,
                    matrix.mantissas(),
                    shift,
                    *policy,
                    bits,
                    output_bits,
                    outputs,
                )
                .expect("capture is consistent with the relations");
                assert_eq!(check(&s.relation, &s.values), Ok(()), "ordinal {ordinal}");
                checked += 1;
                wide_checked += usize::from(output_bits == 24);
            }
        }
    }
    assert!(
        checked > 0 && wide_checked > 0 && grouped_down > 0,
        "checked={checked} wide={wide_checked} grouped_down={grouped_down}"
    );
    std::println!(
        "executor capture: {checked} projections checked ({wide_checked} wide, {grouped_down} grouped down)"
    );
}

/// Wide int24 projection outputs (RFC-0004 A14, RFC-0026 A25) and grouped gated inputs
/// (RFC-0004 A15): honest agreement across shifts and boundaries (`-2^23`, `2^23 - 1`),
/// overflow rejection (`+2^23`, `-2^23 - 1`), and adversarial near-miss rejection
/// (`output ± 1` and opposite rounding direction at ties, plus grouped gated `X - p` alias).
#[test]
fn accepts_wide_and_grouped_gated_projections_and_rejects_near_misses() {
    use stele_ir::relation::check;
    // Helper: signed-24 affine reference.
    let affine_wide = |codes: &[Vec<i64>],
                       scales: &[Vec<u32>],
                       weights: &[Vec<i64>],
                       m: &[u16],
                       shift: i32|
     -> Vec<Vec<i64>> {
        codes
            .iter()
            .zip(scales)
            .map(|(codes, scales)| {
                let g = codes.len() / scales.len();
                weights
                    .iter()
                    .zip(m)
                    .map(|(w, mj)| {
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
                        if p == 0 {
                            0
                        } else if shift >= 0 {
                            (p << shift) as i64
                        } else {
                            let k = (-shift).min(100);
                            (p.signum() * ((p.abs() + (1 << (k - 1))) >> k)) as i64
                        }
                    })
                    .collect()
            })
            .collect()
    };

    // 1. Wide int24 outputs on dynamic + grouped int16 inputs across shift < 0, 0, > 0, vanishing.
    for (policy, shift, m, peak) in [
        // Exact tie at shift = -1: P = 3 -> +2, P = -3 -> -2; plus wide magnitude > 2^16.
        (Policy::Dynamic, -1, vec![3, 100, 65535, 1], 32000),
        // Zero shift, large wide outputs up to ±2^23 - 1.
        (Policy::Grouped(4), 0, vec![1, 200, 1024, 3], 10000),
        // Positive shift with both byte offset (shift/8 = 1) and bit factor (shift%8 = 7 -> 128).
        (Policy::Dynamic, 15, vec![1, 2, 1, 0], 10),
        // Positive shift >= 24 (clamped to 24; only P = 0 fits).
        (Policy::Dynamic, 25, vec![0, 0, 0, 0], 100),
        // Vanishing negative shift (all outputs identically 0).
        (Policy::Grouped(4), -90, vec![65535, 32768, 1, 7], 32000),
    ] {
        let inputs = vec![
            vec![peak, -peak / 2, 3, 0, -3, peak / 4, 1, -1],
            vec![-peak, peak / 3, -1, 2, 1, -peak / 5, 0, 1],
        ];
        let rows = convert(policy, &inputs).expect("convert");
        let weights = vec![
            vec![1, 0, 0, 0, 0, 0, 0, 0],
            vec![-1, 1, 0, 0, 0, 0, 0, 0],
            vec![0, 0, 1, 0, 0, 0, 0, 0],
            vec![1, 1, -1, 1, 1, -1, 1, -1],
        ];
        let outputs = affine_wide(&rows.codes, &rows.scales, &weights, &m, shift);
        assert!(
            outputs
                .iter()
                .flatten()
                .all(|&v| Width::signed(24).contains(v)),
            "test outputs fit int24: {outputs:?}"
        );
        let setup = build_with_bits(&rows, &weights, &m, shift, policy, 8, 24, outputs.clone())
            .expect("honest wide");
        assert_eq!(check(&setup.relation, &setup.values), Ok(()));

        // Near-miss attack: forge output ± 1 (including opposite rounding direction), re-solving
        // magnitude, magnitude_bytes, remainder, output_bytes, and all chains.
        let mut w = setup
            .projection
            .source(
                &setup.relation,
                &ProjectionCapture {
                    codes: rows.codes.clone(),
                    scales: rows.scales.clone(),
                    weights: weights.clone(),
                    outputs: outputs.clone(),
                },
            )
            .expect("source");
        setup.projection.complete(&mut w, PStep::Digits, None);
        for x in 0..w.output.len() {
            if !setup.projection.real(x) {
                continue;
            }
            for delta in [-1i64, 1] {
                let forged = w.output[x] + delta;
                // Output/0 and output/1 are virtual (RFC-0028 §1.2); on non-vanishing shifts,
                // tampering committed output/2 shifts virtual output by +-65536 and must be rejected.
                if !setup.projection.vanishing() {
                    let mut bad = w.clone();
                    bad.output_bytes[2][x] += delta;
                    let mut v = setup.values.clone();
                    setup
                        .projection
                        .write(&setup.relation, &bad, &mut v, None)
                        .expect("write");
                    assert!(
                        check(&setup.relation, &v).is_err(),
                        "forged output/2 delta={delta} at x={x} shift={shift}"
                    );
                }
                // Also try forging magnitude directly to match |forged| and recomputing remainder!
                if shift < 0 && !setup.projection.vanishing() {
                    let mut bad_mag = w.clone();
                    bad_mag.sign[x] = i64::from(forged < 0);
                    bad_mag.magnitude[x] = forged.abs();
                    for k in 0..3 {
                        bad_mag.magnitude_bytes[k][x] = if k == 2 {
                            bad_mag.magnitude[x].div_euclid(1 << 16)
                        } else {
                            bad_mag.magnitude[x]
                                .div_euclid(1 << (8 * k))
                                .rem_euclid(256)
                        };
                    }
                    setup
                        .projection
                        .complete(&mut bad_mag, PStep::Remainder, None);
                    let mut v2 = setup.values.clone();
                    setup
                        .projection
                        .write(&setup.relation, &bad_mag, &mut v2, None)
                        .expect("write");
                    assert!(
                        check(&setup.relation, &v2).is_err(),
                        "forged magnitude for {forged} at x={x} shift={shift}"
                    );
                }
            }
        }
    }

    // 2. Exact int24 boundary (-2^23 accepted, +2^23 rejected) and exact tie half-away-from-zero.
    {
        // With Static(1), inputs = [1, -1, 3, -3], shift = 23 for lanes 0..2:
        // lane 0: -1 * 1 * 2^23 = -2^23 (VALID); lane 1: +1 * 1 * 2^23 = +2^23 (OVERFLOW!).
        let rows_ok = convert(Policy::Static(1), &[vec![-1, 0, 0, 0]]).expect("conv");
        let w = vec![vec![1, 0, 0, 0]];
        let ok = build_with_bits(
            &rows_ok,
            &w,
            &[1],
            23,
            Policy::Static(1),
            8,
            24,
            vec![vec![-(1 << 23)]],
        )
        .expect("ok -2^23");
        assert_eq!(check(&ok.relation, &ok.values), Ok(()));

        // +2^23 must be rejected!
        let rows_ov = convert(Policy::Static(1), &[vec![1, 0, 0, 0]]).expect("conv");
        let ov = build_with_bits(
            &rows_ov,
            &w,
            &[1],
            23,
            Policy::Static(1),
            8,
            24,
            vec![vec![1 << 23]],
        )
        .expect("assign ov");
        assert!(
            check(&ov.relation, &ov.values).is_err(),
            "+2^23 must reject"
        );

        // Exact ties ±3/2 with wide output: +3/2 -> +2, -3/2 -> -2; +1 / -1 (towards zero) rejected.
        let rows_tie = convert(Policy::Static(1), &[vec![3, -3, 0, 0]]).expect("conv");
        let w_tie = vec![vec![1, 0, 0, 0], vec![0, 1, 0, 0]];
        let tie = build_with_bits(
            &rows_tie,
            &w_tie,
            &[1, 1],
            -1,
            Policy::Static(1),
            8,
            24,
            vec![vec![2, -2]],
        )
        .expect("tie");
        assert_eq!(check(&tie.relation, &tie.values), Ok(()));
        let mut wt = tie
            .projection
            .source(
                &tie.relation,
                &ProjectionCapture {
                    codes: rows_tie.codes,
                    scales: rows_tie.scales,
                    weights: w_tie,
                    outputs: vec![vec![2, -2]],
                },
            )
            .expect("source");
        tie.projection.complete(&mut wt, PStep::Digits, None);
        for (x, toward_zero) in [(0usize, 1i64), (1, -1)] {
            let mut bad = wt.clone();
            bad.magnitude[x] = toward_zero.abs();
            for k in 0..3 {
                bad.magnitude_bytes[k][x] = bad.magnitude[x].div_euclid(1 << (8 * k)) & 255;
            }
            tie.projection.complete(&mut bad, PStep::Remainder, None);
            let mut v = tie.values.clone();
            tie.projection
                .write(&tie.relation, &bad, &mut v, None)
                .expect("write");
            assert!(check(&tie.relation, &v).is_err(), "tie toward zero at {x}");
        }
    }

    // 3. Grouped gated input (scale_bound = GATED_SCALE = 8454661, wide_grouped = true) with
    //    wide int24 output, including maximum gated fold 127 * 8454661 = 1_073_741_947 > p/2
    //    AND explicit test rejecting the RFC-0004 A15 `X - p` alias digits (124, 0, 0, -64)!
    {
        let (tokens, inner, outputs, group_size) = (2usize, 8usize, 4usize, 4u32);
        let mut relation = Relation::default();
        let (t, ld, lg) = (
            log2_ceil(tokens),
            log2_ceil(inner),
            group_size.trailing_zeros() as u8,
        );
        let mut b = Builder::new(&mut relation, "L0/gated/row");
        let codes_col = b.witness("codes", Width::signed(8), t + ld);
        let scale_lo = b.witness("scale/lo", Width::unsigned(16), t + ld - lg);
        let scale_hi = b.witness("scale/hi", Width::unsigned(8), t + ld - lg);
        let scale_col = b.column("scale", Width::unsigned(24), t + ld - lg);
        b.relation.composes.push(stele_ir::relation::Compose {
            name: "L0/gated/row/scale".into(),
            column: scale_col,
            limbs: vec![(scale_lo, 0), (scale_hi, 16)],
        });
        let input = RowOutput {
            codes: codes_col,
            scale: scale_col,
            log_rows: t,
            log_dimension: ld,
            log_group: lg,
            scale_bound: 8_454_661,
        };
        let m = vec![100, 3, 65535, 1];
        let shift = -24;
        let mut proj = Projection::new(
            "L0/down",
            input,
            None,
            ProjectionPlan {
                rows: tokens,
                inner,
                outputs,
                weight_bits: 8,
                mantissas: m.clone(),
                shift,
                output_bits: 24,
            },
        )
        .expect("grouped gated plan");
        proj.declare(&mut relation);
        assert_eq!(relation.validate(), Ok(()));

        // Row 0 group 0 attains max gated fold: q = 127, s = 8454661 (1_073_741_947 > p/2).
        // Row 0 group 1 has negative max fold: q = -127, s = 8454661.
        let codes = vec![
            vec![127, -100, 0, 5, -127, 64, -1, 0],
            vec![0, 0, 0, 0, 12, -12, 3, -3],
        ];
        let scales = vec![vec![8_454_661u32, 8_454_661], vec![0, 12_345]];
        let weights = vec![
            vec![127, -128, 1, 2, -127, 3, -4, 5],
            vec![1, 0, 0, 0, 0, 0, 0, 0],
            vec![0, 0, 0, 0, 1, 0, 0, 0],
            vec![-1, 1, -1, 1, -1, 1, -1, 1],
        ];
        let y = affine_wide(&codes, &scales, &weights, &m, shift);
        let mut values = Values::new(&relation);
        let flat_codes = padded(&codes, t, ld);
        let flat_scales: Vec<i64> = scales.iter().flatten().map(|&s| i64::from(s)).collect();
        values.set(&relation, codes_col, flat_codes).expect("codes");
        values
            .set(
                &relation,
                scale_lo,
                flat_scales.iter().map(|s| s & 65535).collect(),
            )
            .expect("slo");
        values
            .set(
                &relation,
                scale_hi,
                flat_scales.iter().map(|s| s >> 16).collect(),
            )
            .expect("shi");
        values
            .set(&relation, scale_col, flat_scales)
            .expect("scales");
        values
            .set(
                &relation,
                proj.weight().expect("w"),
                padded(&weights, log2_ceil(outputs), ld),
            )
            .expect("weights");
        let cap = ProjectionCapture {
            codes,
            scales,
            weights,
            outputs: y,
        };
        proj.assign(&relation, &cap, &mut values)
            .expect("honest grouped gated");
        assert_eq!(check(&relation, &values), Ok(()));

        // RFC-0004 A15 alias attack: replace lane 0's digits (123, 0, 0, 64) for
        // X = 1_073_741_947 with the mod-p alias X - p = -1_073_741_700 = (124, 0, 0, -64)
        // and recompute all downstream sums/bytes/output/chains -> MUST REJECT!
        let mut w_alias = proj.source(&relation, &cap).expect("source");
        proj.complete(&mut w_alias, PStep::Digits, None);
        assert_eq!(
            [
                w_alias.digits[0][0],
                w_alias.digits[1][0],
                w_alias.digits[2][0],
                w_alias.digits[3][0]
            ],
            [123, 0, 0, 64]
        );
        w_alias.digits[0][0] = 124;
        w_alias.digits[1][0] = 0;
        w_alias.digits[2][0] = 0;
        w_alias.digits[3][0] = -64;
        proj.complete(&mut w_alias, PStep::Sums, None);
        let mut v_alias = values.clone();
        proj.write(&relation, &w_alias, &mut v_alias, None)
            .expect("write alias");
        assert!(
            check(&relation, &v_alias).is_err(),
            "grouped gated X - p alias must reject"
        );
    }
}

/// Static validation of every Llama-3.1-8B G7 projection shape at T = 64 (RFC-0026 A25),
/// including A6 row blocks on Gate/Up (4 blocks), Down (4 blocks, wide int24, grouped gated)
/// and Head (32 blocks, int16, grouped int16).
#[test]
fn validates_llama31_8b_projection_shapes() {
    for (name, inner, outputs, output_bits, scale_bound, group) in [
        ("L0/q", 4096, 4096, 16, 259u32, 128u32),
        ("L0/k", 4096, 1024, 16, 259, 128),
        ("L0/o", 4096, 4096, 24, 259, 128),
        ("L0/gate", 4096, 14336, 16, 259, 128),
        ("L0/down", 14336, 4096, 24, 8_454_661, 128),
        ("G/head", 4096, 128256, 16, 259, 128),
    ] {
        let rows = 64usize;
        let (t, ld, lg) = (
            log2_ceil(rows),
            log2_ceil(inner),
            group.trailing_zeros() as u8,
        );
        let mut relation = Relation::default();
        let mut b = Builder::new(&mut relation, "L0/in");
        let codes = b.witness("codes", Width::signed(8), t + ld);
        let scale = if scale_bound <= 259 {
            b.witness("scale", Width::unsigned(9), t + ld - lg)
        } else {
            let lo = b.witness("scale/lo", Width::unsigned(16), t + ld - lg);
            let hi = b.witness("scale/hi", Width::unsigned(8), t + ld - lg);
            let s = b.column("scale", Width::unsigned(24), t + ld - lg);
            b.relation.composes.push(stele_ir::relation::Compose {
                name: "L0/in/scale".into(),
                column: s,
                limbs: vec![(lo, 0), (hi, 16)],
            });
            s
        };
        let input = RowOutput {
            codes,
            scale,
            log_rows: t,
            log_dimension: ld,
            log_group: lg,
            scale_bound,
        };
        let mut proj = Projection::new(
            name,
            input,
            None,
            ProjectionPlan {
                rows,
                inner,
                outputs,
                weight_bits: 8,
                mantissas: vec![65535; outputs],
                shift: -20,
                output_bits,
            },
        )
        .expect("Llama-3.1-8B projection plan");
        proj.declare(&mut relation);
        assert_eq!(relation.validate(), Ok(()), "{name} validates");
    }
    // Unsupported output_bits rejected directly by Projection::new.
    for bad_bits in [0, 8, 15, 23, 32] {
        let mut relation = Relation::default();
        let mut b = Builder::new(&mut relation, "L0/in");
        let input = RowOutput {
            codes: b.witness("codes", Width::signed(8), 4),
            scale: b.witness("scale", Width::unsigned(9), 1),
            log_rows: 1,
            log_dimension: 3,
            log_group: 3,
            scale_bound: 259,
        };
        let plan = ProjectionPlan {
            rows: 2,
            inner: 8,
            outputs: 4,
            weight_bits: 8,
            mantissas: vec![1; 4],
            shift: 0,
            output_bits: bad_bits,
        };
        assert_eq!(
            Projection::new("L0/bad", input, None, plan).err(),
            Some(Unsupported::Shape)
        );
    }
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

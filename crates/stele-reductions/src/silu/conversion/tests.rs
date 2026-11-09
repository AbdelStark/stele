//! Gated row conversion tests: executor values, near misses, deletion survey, shapes.

use super::*;
use crate::development::{Projection, ProjectionPlan};
use stele_ir::relation::{check, check_except, Kind, Range};

struct Case {
    relation: Relation,
    values: Values,
    module: GatedConversion,
    plan: Plan,
}

impl Case {
    fn column(&self, id: ColumnId) -> &[i64] {
        self.values.get(&self.relation, id).expect("column")
    }

    /// The honest values with every column of `plan` refilled, then `patches` applied.
    fn attack(&self, plan: &Plan, patches: &[(ColumnId, usize, i64)]) -> Values {
        let mut values = self.values.clone();
        for (id, column) in self.module.fill(plan) {
            values.set(&self.relation, id, column).expect("set");
        }
        for &(id, index, v) in patches {
            let mut column = values.get(&self.relation, id).expect("column").to_vec();
            column[index] = v;
            values.set(&self.relation, id, column).expect("set");
        }
        values
    }
}

/// Declare the product limbs as signed-16/unsigned-15 witness columns (as
/// [`super::super::GatedProduct`] does), the conversion, and assign both from `T`.
fn case(product: &[i64], tokens: usize, hidden: usize) -> Case {
    let mut relation = Relation::default();
    let n = log2_ceil(tokens) + log2_ceil(hidden);
    let group = relation.add_group("L0/gated/test", n);
    let mut limbs = [ColumnId(0); 2];
    for (slot, (name, width)) in limbs
        .iter_mut()
        .zip([("high", Width::signed(16)), ("low", Width::unsigned(15))])
    {
        *slot = relation.add_column(name, Kind::Witness(group), width, n);
        relation.ranges.push(Range {
            name: name.into(),
            column: *slot,
            width,
        });
    }
    let mut module =
        GatedConversion::new(0, limbs[0], limbs[1], tokens, hidden, Policy::Dynamic).expect("plan");
    module.declare(&mut relation);
    let mut values = Values::new(&relation);
    let plan = module.plan(product);
    let high = plan.product.iter().map(|v| v.div_euclid(LIMB)).collect();
    let low = plan.product.iter().map(|v| v.rem_euclid(LIMB)).collect();
    values.set(&relation, limbs[0], high).expect("high");
    values.set(&relation, limbs[1], low).expect("low");
    module
        .assign(&relation, product, &mut values)
        .expect("honest");
    Case {
        relation,
        values,
        module,
        plan,
    }
}

/// `stele_cqis::row::Quantiser::convert_gated` restated for a dynamic row: codes and
/// the scale of every row.
fn reference(product: &[i64], hidden: usize) -> (Vec<i64>, Vec<i64>) {
    let mut codes = Vec::new();
    let mut scales = Vec::new();
    for row in product.chunks(hidden) {
        let scale = (row.iter().map(|v| v.abs()).max().unwrap_or(0) + 126) / 127;
        scales.push(scale);
        for &v in row {
            let q = if scale == 0 {
                0
            } else {
                (2 * v.abs() + scale) / (2 * scale)
            };
            codes.push(v.signum() * q);
        }
    }
    (codes, scales)
}

/// Compare a case's codes and scales with expected unpadded values.
fn assert_output(case: &Case, codes: &[i64], scales: &[i64], tokens: usize, hidden: usize) {
    let out = case.module.output().expect("declared");
    let d = out.log_dimension;
    let got = case.column(out.codes);
    for t in 0..tokens {
        for j in 0..hidden {
            assert_eq!(got[(t << d) | j], codes[t * hidden + j], "code ({t}, {j})");
        }
        assert_eq!(case.column(out.scale)[t], scales[t], "scale {t}");
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
    /// One `T = U·a` with `U` int16 and `a` in `(−2^15, 2^15)`; extremes include the
    /// largest `|T|` and zero rows.
    fn product(&mut self, extreme: bool) -> i64 {
        let u = self.next() as i16 as i64;
        let a = (self.next() as i16 as i64).max(-32767);
        match (extreme, self.next() % 4) {
            (true, 0) => -32768 * 32767,
            (true, 1) => 32767 * 32767,
            (true, 2) => (self.next() % 3) as i64 - 1,
            _ => u * a,
        }
    }
}

#[test]
fn matches_reference_random_and_extreme_rows() {
    let mut rng = Rng(0x0e16_0081);
    for extreme in [false, true] {
        for (tokens, hidden) in [(1, 1), (3, 5), (4, 8), (2, 100)] {
            let mut product: Vec<i64> =
                (0..tokens * hidden).map(|_| rng.product(extreme)).collect();
            // A zero row exercises the zero-row branch.
            product[..hidden].iter_mut().for_each(|v| *v = 0);
            let case = case(&product, tokens, hidden);
            check(&case.relation, &case.values).expect("honest values pass");
            let (codes, scales) = reference(&product, hidden);
            assert_output(&case, &codes, &scales, tokens, hidden);
        }
    }
}

/// The real executor (`Executor::capture`): the gated product and the down row of every
/// dynamic family-1 fixture layer.
#[test]
fn matches_executor_capture() {
    let mut checked = 0;
    for (model, capture) in crate::executor_fixtures::captures() {
        if model.shape().family() != 1 {
            continue;
        }
        let hidden = usize::from(model.shape().hidden());
        for positions in &capture.blocks {
            if positions.iter().any(|b| b.down_row.maximum.is_none()) {
                continue;
            }
            let product: Vec<i64> = positions.iter().flat_map(|b| b.gated.clone()).collect();
            let case = case(&product, positions.len(), hidden);
            check(&case.relation, &case.values).expect("executor values pass");
            let codes: Vec<i64> = positions
                .iter()
                .flat_map(|b| b.down_row.codes.clone())
                .collect();
            let scales: Vec<i64> = positions
                .iter()
                .map(|b| i64::from(b.down_row.scales[0]))
                .collect();
            assert_output(&case, &codes, &scales, positions.len(), hidden);
            checked += 1;
        }
    }
    assert!(checked > 0, "no dynamic family-1 gated row");
}

/// A 3x8 case built so that every constraint has an in-range attacker:
/// - row 0: `M = 127·2^15` (`s = 2^15`, `sl = 0`, `e = 0`), a runner-up `M − 1`, a zero
///   lane, a small lane, a negative lane past `2^15` and lanes with high remainder and
///   spare limbs;
/// - row 1: `M = 127·4` attained twice (lanes 9 and 13), a tie `6/4` at lane 8 and a
///   negative non-maximum lane 11;
/// - row 2: all zero, and row 3 is padding.
fn survey_case() -> (Case, usize) {
    let mut product = vec![0; 24];
    product[..8].copy_from_slice(&[1000, -77, 5, 0, 4161536, -32668, 4161535, 20000]);
    product[8..16].copy_from_slice(&[6, -508, 300, -45, 2, 508, 7, 100]);
    let case = case(&product, 3, 8);
    check(&case.relation, &case.values).expect("honest");
    (case, 8)
}

/// Code `q ± 1` and the other rounding direction at a tie, with every other column
/// derived from the forged quotient: rejected.
#[test]
fn rejects_code_off_by_one_and_other_rounding_direction() {
    let (case, tie) = survey_case();
    assert_eq!(case.plan.quotient[tie], 2, "6/4 rounds half up to 2");
    for lane in 0..16 {
        for delta in [1, -1] {
            let mut plan = case.plan.clone();
            plan.quotient[lane] += delta;
            let values = case.attack(&plan, &[]);
            assert!(check(&case.relation, &values).is_err(), "lane {lane}");
        }
    }
}

/// A scale `s ± 1` with the slack recomputed, and a zero branch on a nonzero row.
#[test]
fn rejects_wrong_scale_and_zero_branch() {
    let (case, _) = survey_case();
    for row in 0..2 {
        for delta in [1, -1] {
            let mut plan = case.plan.clone();
            plan.scale[row] += delta;
            plan.slack[row] = 127 * plan.scale[row] - plan.maximum[row];
            plan.quotient = recomputed(&plan);
            assert!(check(&case.relation, &case.attack(&plan, &[])).is_err());
        }
        let mut plan = case.plan.clone();
        plan.zero[row] = 1;
        plan.quotient = recomputed(&plan);
        assert!(check(&case.relation, &case.attack(&plan, &[])).is_err());
    }
}

/// `q = floor((2A + D)/(2D))` for a plan's own scale and zero branch.
fn recomputed(plan: &Plan) -> Vec<i64> {
    let width = plan.product.len() / plan.scale.len();
    (0..plan.product.len())
        .map(|x| {
            let divisor = (plan.scale[x / width] + plan.zero[x / width]).max(1);
            (2 * plan.magnitude[x] + divisor) / (2 * divisor)
        })
        .collect()
}

/// RFC-0026 §5.2 deletion survey with `check_except`: for every constraint of the
/// module (relations and ranges), an in-range attacker that `check` rejects and
/// `check_except(.., [name])` accepts, or the range is listed as implied.
#[test]
fn rejects_relation_without_each_constraint() {
    let (case, tie) = survey_case();
    let c = case.module.columns().expect("declared");
    let honest = &case.plan;
    // Lanes of row 1: the maximum at 9, a non-maximum negative lane at 11.
    let (top, lane) = (9, 11);
    let mut attacks: Vec<(&str, Values)> = Vec::new();
    let mut plan = honest.clone();
    plan.magnitude[lane] += 1;
    plan.quotient = recomputed(&plan);
    attacks.push(("sign/low", case.attack(&plan, &[])));
    let mut plan = honest.clone();
    // A + 2^15 becomes the row maximum; everything downstream follows it.
    plan.magnitude[lane] += LIMB;
    plan.maximum[1] = plan.magnitude[lane];
    plan.gap_maximum[1] = plan.magnitude[lane];
    plan.hit[top] = 0;
    plan.hit[lane] = 1;
    plan.scale[1] = (plan.maximum[1] + 126) / 127;
    plan.slack[1] = 127 * plan.scale[1] - plan.maximum[1];
    plan.quotient = recomputed(&plan);
    attacks.push(("sign/high", case.attack(&plan, &[])));
    let mut plan = honest.clone();
    plan.maximum[1] += 1;
    plan.scale[1] = (plan.maximum[1] + 126) / 127;
    plan.slack[1] = 127 * plan.scale[1] - plan.maximum[1];
    plan.quotient = recomputed(&plan);
    attacks.push(("gap/low", case.attack(&plan, &[])));
    let mut plan = honest.clone();
    plan.maximum[1] += LIMB;
    plan.scale[1] = (plan.maximum[1] + 126) / 127;
    plan.slack[1] = 127 * plan.scale[1] - plan.maximum[1];
    plan.quotient = recomputed(&plan);
    attacks.push(("gap/high", case.attack(&plan, &[])));
    let mut plan = honest.clone();
    plan.maximum[1] += 127;
    plan.gap_maximum[1] += 127;
    plan.scale[1] += 1;
    plan.quotient = recomputed(&plan);
    attacks.push(("attained", case.attack(&plan, &[])));
    plan.hit[top] = 0;
    attacks.push(("attained/one-hot", case.attack(&plan, &[])));
    let honest_carry = case.column(c.ceiling_carry)[1];
    let mut plan = honest.clone();
    plan.scale[1] += 1;
    plan.quotient = recomputed(&plan);
    attacks.push((
        "ceiling/low",
        case.attack(&plan, &[(c.ceiling_carry, 1, honest_carry)]),
    ));
    let mut plan = honest.clone();
    plan.scale[1] += LIMB;
    plan.quotient = recomputed(&plan);
    attacks.push(("ceiling/high", case.attack(&plan, &[])));
    // Row 1 has slack 0 (M = 127·4); s = 5 needs slack 127, outside 0..=126.
    assert_eq!(honest.slack[1], 0);
    let mut plan = honest.clone();
    plan.scale[1] += 1;
    plan.slack[1] = 127;
    plan.quotient = recomputed(&plan);
    attacks.push(("ceiling", case.attack(&plan, &[])));
    let scale = case.column(c.scale)[1];
    attacks.push(("scale", case.attack(honest, &[(c.scale, 1, scale + 1)])));
    let mut plan = honest.clone();
    plan.zero[1] = 1;
    plan.quotient = recomputed(&plan);
    attacks.push(("zero", case.attack(&plan, &[])));
    let get = |id: ColumnId| case.column(id)[tie];
    attacks.push((
        "division/low",
        case.attack(
            honest,
            &[
                (c.remainder_low, tie, get(c.remainder_low) + 1),
                (c.spare_low, tie, get(c.spare_low) - 1),
            ],
        ),
    ));
    let big = (0..16)
        .find(|&x| case.column(c.spare_high)[x] > 0)
        .expect("a lane with a high spare limb");
    attacks.push((
        "division/high",
        case.attack(
            honest,
            &[
                (
                    c.remainder_high,
                    big,
                    case.column(c.remainder_high)[big] + 1,
                ),
                (c.spare_high, big, case.column(c.spare_high)[big] - 1),
            ],
        ),
    ));
    attacks.push((
        "spare/low",
        case.attack(honest, &[(c.spare_low, tie, get(c.spare_low) + 1)]),
    ));
    attacks.push((
        "spare/high",
        case.attack(honest, &[(c.spare_high, tie, get(c.spare_high) + 1)]),
    ));
    attacks.push((
        "code",
        case.attack(honest, &[(c.codes, tie, get(c.codes) + 1)]),
    ));
    attacks.extend(range_attacks(&case));
    let prefix = "L0/gated/row/";
    let names: Vec<String> = case
        .relation
        .identities
        .iter()
        .map(|i| i.name.clone())
        .chain(case.relation.lookups.iter().map(|l| l.name.clone()))
        .chain(case.relation.matmuls.iter().map(|m| m.name.clone()))
        .chain(case.relation.composes.iter().map(|m| m.name.clone()))
        .chain(case.relation.ranges.iter().map(|r| r.name.clone()))
        .filter(|name| name.starts_with(prefix))
        .collect();
    for name in &names {
        let short = &name[prefix.len()..];
        assert!(
            IMPLIED.contains(&short) || attacks.iter().any(|a| a.0 == short),
            "no attacker for {name}"
        );
    }
    assert_eq!(names.len(), attacks.len() + IMPLIED.len());
    for (short, values) in &attacks {
        let name = alloc::format!("{prefix}{short}");
        assert!(
            check(&case.relation, values).is_err(),
            "{name}: check rejects"
        );
        assert_eq!(
            check_except(&case.relation, values, &[name.as_str()]),
            Ok(()),
            "{name}: accepted without it"
        );
    }
}

/// Ranges implied by the other constraints (reasons in the review notes).
const IMPLIED: [&str; 9] = [
    "borrow/range",
    "gap/borrow/range",
    "quotient/range",
    "codes/range",
    "remainder/carry/range",
    "spare/carry/range",
    "ceiling/carry/range",
    "maximum/high/range",
    "scale/high/range",
];

/// One in-range attacker per range that is not implied; each keeps every relation.
fn range_attacks(case: &Case) -> Vec<(&'static str, Values)> {
    let c = case.module.columns().expect("declared");
    let honest = &case.plan;
    let get = |id: ColumnId, i: usize| case.column(id)[i];
    let mut attacks = Vec::new();
    // sign: σ = 2 on a zero lane (row 0 lane 3), where A = q = code = 0 for any σ.
    attacks.push(("sign/range", case.attack(honest, &[(c.sign, 3, 2)])));
    // magnitude/low: the row-0 maximum (Al = 0, Ah = 127) as Al = 2^15, Ah = 126.
    attacks.push((
        "magnitude/low/range",
        case.attack(
            honest,
            &[
                (c.magnitude_low, 4, get(c.magnitude_low, 4) + LIMB),
                (c.magnitude_high, 4, get(c.magnitude_high, 4) - 1),
                (c.borrow, 4, 1),
                (c.gap_borrow, 4, 1),
                (c.remainder_carry, 4, get(c.remainder_carry, 4) + 2),
            ],
        ),
    ));
    // magnitude/high: σ = 1 on the positive lane T = 5, so A = −5 (Ah = −1), q = 0.
    let mut plan = honest.clone();
    plan.sign[2] = 1;
    plan.magnitude[2] = -5;
    plan.quotient = recomputed(&plan);
    attacks.push(("magnitude/high/range", case.attack(&plan, &[])));
    // gap/low: the zero lane's gap 127·2^15 as gl = 2^15, gb = 1, gh = 126.
    attacks.push((
        "gap/low/range",
        case.attack(
            honest,
            &[
                (c.gap_low, 3, get(c.gap_low, 3) + LIMB),
                (c.gap_borrow, 3, 1),
                (c.gap_high, 3, get(c.gap_high, 3) - 1),
            ],
        ),
    ));
    // gap/high: M = the runner-up 4161535, hit there; the maximum lane has gap −1.
    let mut plan = honest.clone();
    plan.maximum[0] = 4161535;
    plan.gap_maximum[0] = 4161535;
    plan.hit[4] = 0;
    plan.hit[6] = 1;
    plan.slack[0] = 127 * plan.scale[0] - plan.maximum[0];
    plan.quotient = recomputed(&plan);
    attacks.push(("gap/high/range", case.attack(&plan, &[])));
    // hit: 2 and −1 on the two attained lanes of row 1.
    attacks.push((
        "hit/range",
        case.attack(honest, &[(c.hit, 9, 2), (c.hit, 13, -1)]),
    ));
    // remainder/low: lane 4 (r = 2^15) as rl = 2^15, rh = 0, carries moved.
    attacks.push((
        "remainder/low/range",
        case.attack(
            honest,
            &[
                (c.remainder_low, 4, get(c.remainder_low, 4) + LIMB),
                (c.remainder_high, 4, get(c.remainder_high, 4) - 1),
                (c.remainder_carry, 4, get(c.remainder_carry, 4) - 1),
                (c.spare_carry, 4, get(c.spare_carry, 4) - 1),
            ],
        ),
    ));
    // remainder/high: q + 1 on lane 0, so r < 0 (code 1 instead of 0).
    let mut plan = honest.clone();
    plan.quotient[0] += 1;
    attacks.push(("remainder/high/range", case.attack(&plan, &[])));
    // spare/low: lane 7 (ph = 1) as pl + 2^15, ph = 0, spare carry moved.
    attacks.push((
        "spare/low/range",
        case.attack(
            honest,
            &[
                (c.spare_low, 7, get(c.spare_low, 7) + LIMB),
                (c.spare_high, 7, get(c.spare_high, 7) - 1),
                (c.spare_carry, 7, get(c.spare_carry, 7) - 1),
            ],
        ),
    ));
    // spare/high: q − 1 on lane 7 (code 0 instead of 1), so the spare is negative.
    let mut plan = honest.clone();
    plan.quotient[7] -= 1;
    attacks.push(("spare/high/range", case.attack(&plan, &[])));
    // maximum/low: row 1 (M < 2^15, every gap borrow 0) as Ml = M − 2^15, Mh = 1.
    let mut patches = vec![
        (c.maximum_low, 1, get(c.maximum_low, 1) - LIMB),
        (c.maximum_high, 1, 1),
        (c.ceiling_carry, 1, get(c.ceiling_carry, 1) + 1),
    ];
    patches.extend((8..16).map(|lane| (c.gap_borrow, lane, 1)));
    attacks.push(("maximum/low/range", case.attack(honest, &patches)));
    // scale/low: row 0 (s = 2^15) as sl = 2^15, sh = 0, carries moved.
    let mut patches = vec![
        (c.scale_low, 0, LIMB),
        (c.scale_high, 0, 0),
        (c.ceiling_carry, 0, get(c.ceiling_carry, 0) + 127),
    ];
    for lane in 0..8 {
        let q = get(c.quotient, lane);
        patches.push((
            c.remainder_carry,
            lane,
            get(c.remainder_carry, lane) + 1 - 2 * q,
        ));
        patches.push((c.spare_carry, lane, get(c.spare_carry, lane) + 2));
    }
    attacks.push(("scale/low/range", case.attack(honest, &patches)));
    // zero: z = 2 on the zero row 2, D = 2.
    let mut plan = honest.clone();
    plan.zero[2] = 2;
    attacks.push(("zero/range", case.attack(&plan, &[])));
    attacks
}

/// Realistic shapes validate, and E16-05's down projection accepts the output: the
/// Llama-3.1-8B hidden width 14336 at T = 64.
#[test]
fn accepts_static_validity_and_down_projection_input() {
    for (tokens, hidden, outputs) in [(64, 14336, 4), (4, 8, 3)] {
        let mut relation = Relation::default();
        let n = log2_ceil(tokens) + log2_ceil(hidden);
        let group = relation.add_group("L0/gated/test", n);
        let high = relation.add_column("high", Kind::Witness(group), Width::signed(16), n);
        let low = relation.add_column("low", Kind::Witness(group), Width::unsigned(15), n);
        for (column, width) in [(high, Width::signed(16)), (low, Width::unsigned(15))] {
            relation.ranges.push(Range {
                name: "limb".into(),
                column,
                width,
            });
        }
        let mut module =
            GatedConversion::new(0, high, low, tokens, hidden, Policy::Dynamic).expect("plan");
        module.declare(&mut relation);
        let plan = ProjectionPlan {
            rows: tokens,
            inner: hidden,
            outputs,
            weight_bits: 8,
            mantissas: vec![1; outputs],
            shift: -20,
        };
        let output = module.output().expect("declared");
        assert_eq!(output.scale_bound, GATED_SCALE);
        let mut down = Projection::new("L0/down", output, None, plan).expect("accepted");
        down.declare(&mut relation);
        relation.validate().expect("valid");
    }
}

#[test]
fn rejects_unsupported_policy() {
    for policy in [Policy::Static(3), Policy::Grouped(4)] {
        assert_eq!(
            GatedConversion::new(0, ColumnId(0), ColumnId(1), 2, 8, policy).err(),
            Some(Unsupported::Policy)
        );
    }
}

/// `check` with the named range one bit wider: every other constraint as declared, and
/// that range's column within the wider width.
fn check_widened(relation: &Relation, values: &Values, name: &str) -> bool {
    let range = relation
        .ranges
        .iter()
        .find(|r| r.name == name)
        .expect("range");
    let wider = Width {
        bits: range.width.bits + 1,
        ..range.width
    };
    let column = values.get(relation, range.column).expect("column");
    check_except(relation, values, &[name]).is_ok() && column.iter().all(|&v| wider.contains(v))
}

/// RFC-0026 §5.2 widen-by-one-bit survey, the one range it catches: `σ` in `0..=3`
/// lets `σ = 2` take `A = −3T` on a negative lane past `2^15` (code −9 instead of −1).
/// Every other range is safe one bit wider (written reasons in the review notes).
#[test]
fn rejects_code_through_widened_sign() {
    let (case, _) = survey_case();
    let c = case.module.columns().expect("declared");
    let lane = 5;
    assert_eq!(case.plan.product[lane], -32668);
    assert_eq!(case.column(c.codes)[lane], -1);
    let mut plan = case.plan.clone();
    plan.sign[lane] = 2;
    plan.magnitude[lane] = 3 * 32668;
    plan.quotient = recomputed(&plan);
    let values = case.attack(&plan, &[(c.borrow, lane, 1)]);
    let codes = values.get(&case.relation, c.codes).expect("codes");
    assert_eq!(codes[lane], -9);
    assert!(check(&case.relation, &values).is_err());
    assert!(check_widened(
        &case.relation,
        &values,
        "L0/gated/row/sign/range"
    ));
}

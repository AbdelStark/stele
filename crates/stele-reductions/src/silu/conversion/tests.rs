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
    fn column(&self, id: ColumnId) -> Vec<i64> {
        stele_ir::relation::eval_column(&self.relation, &self.values, id).expect("column")
    }

    /// The honest values with every column of `plan` refilled, then `patches` applied.
    fn attack(&self, plan: &Plan, patches: &[(ColumnId, usize, i64)]) -> Values {
        let mut values = self.values.clone();
        for (id, column) in self.module.fill(plan) {
            if !matches!(self.relation.columns[id.0 as usize].kind, Kind::Virtual(_)) {
                values.set(&self.relation, id, column).expect("set");
            }
        }
        for &(id, index, v) in patches {
            let mut column =
                stele_ir::relation::eval_column(&self.relation, &values, id).expect("column");
            column[index] = v;
            values.set(&self.relation, id, column).expect("set");
        }
        values
    }
}

/// Declare virtual `high = 2^15·h_hi + h_lo` (matching [`super::super::GatedProduct`]'s
/// virtual `high`) and witness `low` (unsigned 14).
fn add_product_limbs(
    relation: &mut Relation,
    group: stele_ir::relation::GroupId,
    n: u8,
) -> (ColumnId, ColumnId, ColumnId, ColumnId) {
    let h_hi = relation.add_column("high/hi", Kind::Witness(group), Width::signed(2), n);
    let h_lo = relation.add_column("high/lo", Kind::Witness(group), Width::unsigned(15), n);
    let low = relation.add_column("low", Kind::Witness(group), Width::unsigned(LIMB_BITS), n);
    for (name, column, width) in [
        ("high/hi", h_hi, Width::signed(2)),
        ("high/lo", h_lo, Width::unsigned(15)),
        ("low", low, Width::unsigned(LIMB_BITS)),
    ] {
        relation.ranges.push(Range {
            name: name.into(),
            column,
            width,
        });
    }
    let high = relation.add_virtual(
        "high",
        Def::Linear {
            constant: 0,
            terms: vec![(1 << 15, r(h_hi, 0..n)), (1, r(h_lo, 0..n))],
        },
        n,
    );
    (high, low, h_hi, h_lo)
}

fn assign_product_limbs(
    relation: &Relation,
    values: &mut Values,
    h_hi: ColumnId,
    h_lo: ColumnId,
    low_id: ColumnId,
    product: &[i64],
) {
    let hi: Vec<i64> = product
        .iter()
        .map(|v| v.div_euclid(LIMB).div_euclid(1 << 15))
        .collect();
    let lo: Vec<i64> = product
        .iter()
        .map(|v| v.div_euclid(LIMB).rem_euclid(1 << 15))
        .collect();
    let low: Vec<i64> = product.iter().map(|v| v.rem_euclid(LIMB)).collect();
    values.set(relation, h_hi, hi).expect("high/hi");
    values.set(relation, h_lo, lo).expect("high/lo");
    values.set(relation, low_id, low).expect("low");
}

/// Declare the product limbs as radix-`2^14` limbs (matching
/// [`super::super::GatedProduct`]), the conversion, and assign both from `T`.
fn case(product: &[i64], tokens: usize, hidden: usize) -> Case {
    let mut relation = Relation::default();
    let n = log2_ceil(tokens) + log2_ceil(hidden);
    let group = relation.add_group("L0/gated/test", n);
    let (high, low, h_hi, h_lo) = add_product_limbs(&mut relation, group, n);
    let mut module =
        GatedConversion::new(0, high, low, tokens, hidden, Policy::Dynamic).expect("plan");
    module.declare(&mut relation);
    let mut values = Values::new(&relation);
    let plan = module.plan(product);
    assign_product_limbs(&relation, &mut values, h_hi, h_lo, low, &plan.product);
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
    attacks.push(("attained/low", case.attack(&plan, &[])));
    plan.hit[top] = 0;
    attacks.push(("attained/one-hot", case.attack(&plan, &[])));
    // attained/high: M = 508 + 2^15 with gaps from it; the hit lane has gl = 0, gh = 1.
    let mut plan = honest.clone();
    plan.maximum[1] += LIMB;
    plan.gap_maximum[1] += LIMB;
    plan.scale[1] = (plan.maximum[1] + 126) / 127;
    plan.slack[1] = 127 * plan.scale[1] - plan.maximum[1];
    plan.quotient = recomputed(&plan);
    assert_eq!((plan.scale[1], plan.quotient[top]), (134, 4));
    attacks.push(("attained/high", case.attack(&plan, &[])));
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
    // Virtualizations remove 11 identities/composes; retain attackers for remaining constraints.
    attacks.retain(|(short, _)| names.iter().any(|n| &n[prefix.len()..] == *short));
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
    // scale/low: row 0 (s = 2^15 = 2*LIMB) as sl = LIMB, sh = 1, carries moved.
    let mut patches = vec![
        (c.scale_low, 0, LIMB),
        (c.scale_high, 0, get(c.scale_high, 0) - 1),
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
        let (high, low, _, _) = add_product_limbs(&mut relation, group, n);
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
            output_bits: 16,
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
    for policy in [
        Policy::Static(3),
        Policy::Grouped(0),
        Policy::Grouped(3),
        Policy::Grouped(8),
        Policy::Grouped(16),
    ] {
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
    let codes = stele_ir::relation::eval_column(&case.relation, &values, c.codes).expect("codes");
    assert_eq!(codes[lane], -9);
    assert!(check(&case.relation, &values).is_err());
    assert!(check_widened(
        &case.relation,
        &values,
        "L0/gated/row/sign/range"
    ));
}

/// The widest remainder and spare high limbs (`ceil((2^31)/2^15) − 1 = 516`): a row at
/// the largest `|T| = 2^15·(2^15 − 1)` (`D = 8454402`), a lane just below a rounding tie
/// (`r = 2D − 2`) and one just above (`r = 0`, spare `2D − 1`). Both limbs exceed 511,
/// so their unsigned-10 ranges are needed at full width.
#[test]
fn accepts_largest_remainder_and_spare_limbs() {
    let top = 32768 * 32767;
    let divisor = (top + 126) / 127;
    let below = divisor / 2 - 1 + divisor % 2;
    let above = (divisor + 1) / 2;
    let mut product = vec![0; 8];
    product[..3].copy_from_slice(&[top, below, above]);
    let case = case(&product, 1, 8);
    check(&case.relation, &case.values).expect("honest");
    let c = case.module.columns().expect("declared");
    assert_eq!(case.column(c.quotient)[1..3], [0, 1]);
    let (rh, ph) = (
        case.column(c.remainder_high)[1],
        case.column(c.spare_high)[2],
    );
    assert!(
        rh > 1023 && ph > 1023,
        "remainder high {rh}, spare high {ph}"
    );
    let (reference_codes, _) = reference(&product, 8);
    assert_eq!(&case.column(c.codes)[..8], &reference_codes[..]);
}

/// Helper: grouped gated conversion case with `Policy::Grouped(group)`.
fn grouped_case(product: &[i64], tokens: usize, hidden: usize, group_size: u32) -> Case {
    let mut relation = Relation::default();
    let n = log2_ceil(tokens) + log2_ceil(hidden);
    let group = relation.add_group("L0/gated/test", n);
    let (high, low, h_hi, h_lo) = add_product_limbs(&mut relation, group, n);
    let mut module =
        GatedConversion::new(0, high, low, tokens, hidden, Policy::Grouped(group_size))
            .expect("plan");
    module.declare(&mut relation);
    let mut values = Values::new(&relation);
    let plan = module.plan(product);
    assign_product_limbs(&relation, &mut values, h_hi, h_lo, low, &plan.product);
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

/// Reference grouped gated conversion: one dynamic scale per group of `group_size` lanes.
fn reference_grouped(product: &[i64], hidden: usize, group_size: usize) -> (Vec<i64>, Vec<i64>) {
    let mut codes = Vec::new();
    let mut scales = Vec::new();
    for row in product.chunks(hidden) {
        for chunk in row.chunks(group_size) {
            let scale = (chunk.iter().map(|v| v.abs()).max().unwrap_or(0) + 126) / 127;
            scales.push(scale);
            for &v in chunk {
                let q = if scale == 0 {
                    0
                } else {
                    (2 * v.abs() + scale) / (2 * scale)
                };
                codes.push(v.signum() * q);
            }
        }
    }
    (codes, scales)
}

#[test]
fn matches_reference_grouped_rows() {
    let mut rng = Rng(0x0e22_0301);
    for extreme in [false, true] {
        for (tokens, hidden, group_size) in [(1, 8, 4), (3, 12, 4), (4, 16, 4), (2, 100, 4)] {
            let mut product: Vec<i64> =
                (0..tokens * hidden).map(|_| rng.product(extreme)).collect();
            // Zero out one group within a non-zero row to exercise per-group zero branch.
            product[..group_size as usize]
                .iter_mut()
                .for_each(|v| *v = 0);
            let case = grouped_case(&product, tokens, hidden, group_size);
            check(&case.relation, &case.values).expect("honest grouped values pass");
            let (codes, scales) = reference_grouped(&product, hidden, group_size as usize);
            let out = case.module.output().expect("declared");
            assert_eq!(out.log_group, group_size.trailing_zeros() as u8);
            let d = out.log_dimension;
            let got_codes = case.column(out.codes);
            let got_scales = case.column(out.scale);
            let groups_per_row = hidden / group_size as usize;
            let padded_groups = 1usize << (d - out.log_group);
            for t in 0..tokens {
                for j in 0..hidden {
                    assert_eq!(
                        got_codes[(t << d) | j],
                        codes[t * hidden + j],
                        "code ({t}, {j})"
                    );
                }
                for g in 0..groups_per_row {
                    assert_eq!(
                        got_scales[t * padded_groups + g],
                        scales[t * groups_per_row + g],
                        "scale ({t}, {g})"
                    );
                }
                for g in groups_per_row..padded_groups {
                    assert_eq!(got_scales[t * padded_groups + g], 0, "padded scale");
                }
            }
        }
    }
}

#[test]
fn rejects_grouped_near_misses_and_other_rounding_direction() {
    // Row 0 group 0: max = 508 (s = 4), tie 6/4 -> 2 at lane 0; group 1: all zeros.
    // Row 1 group 0: large values (s = 32768); group 1: small negative tie -6/4 -> -2 at lane 12.
    let product = vec![
        6, -508, 300, -45, 0, 0, 0, 0, // row 0
        4_161_536, -32_668, 100, 0, -6, 508, -7, 2, // row 1
    ];
    let case = grouped_case(&product, 2, 8, 4);
    check(&case.relation, &case.values).expect("honest");
    assert_eq!(case.plan.quotient[0], 2, "positive tie 6/4 rounds to 2");
    assert_eq!(case.plan.quotient[12], 2, "negative tie -6/4 rounds to -2");
    // Code ±1 (including opposite rounding direction at lanes 0 and 12).
    for lane in [0, 1, 2, 4, 8, 9, 12, 13] {
        for delta in [1, -1] {
            let mut plan = case.plan.clone();
            plan.quotient[lane] += delta;
            assert!(
                check(&case.relation, &case.attack(&plan, &[])).is_err(),
                "lane {lane} delta {delta}"
            );
        }
    }
    // Scale ±1 and bogus zero branch on non-zero groups.
    for group in [0, 2, 3] {
        for delta in [1, -1] {
            let mut plan = case.plan.clone();
            plan.scale[group] += delta;
            plan.slack[group] = 127 * plan.scale[group] - plan.maximum[group];
            plan.quotient = recomputed(&plan);
            assert!(check(&case.relation, &case.attack(&plan, &[])).is_err());
        }
        let mut plan = case.plan.clone();
        plan.zero[group] = 1;
        plan.quotient = recomputed(&plan);
        assert!(check(&case.relation, &case.attack(&plan, &[])).is_err());
    }
}

/// Llama-3.1-8B G7 gated down-projection shape: T = 64, hidden = 14336, g = 128,
/// wide int24 output (d = 4096), int8 weights, row-blocked by RFC-0026 A6.
#[test]
fn validates_llama31_8b_grouped_gated_down_shape() {
    let (tokens, hidden, outputs) = (64, 14336, 4096);
    let mut relation = Relation::default();
    let n = log2_ceil(tokens) + log2_ceil(hidden);
    let group = relation.add_group("L0/gated/test", n);
    let (high, low, _, _) = add_product_limbs(&mut relation, group, n);
    let mut conv =
        GatedConversion::new(0, high, low, tokens, hidden, Policy::Grouped(128)).expect("plan");
    conv.declare(&mut relation);
    let output = conv.output().expect("declared");
    assert_eq!(output.log_group, 7);
    assert_eq!(output.scale_bound, GATED_SCALE);
    let plan = ProjectionPlan {
        rows: tokens,
        inner: hidden,
        outputs,
        weight_bits: 8,
        mantissas: vec![65535; outputs],
        shift: -20,
        output_bits: 24,
    };
    let mut down = Projection::new("L0/down", output, None, plan).expect("accepted");
    down.declare(&mut relation);
    relation.validate().expect("Llama-3.1-8B down validates");
}

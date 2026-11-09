//! RoPE module tests: executor-equivalent honest values, near misses, static shapes.

use super::*;
use stele_ir::relation::check;

/// Encode a Rotation descriptor (RFC-0025 encoding §4) for a fixture configuration.
fn rotation(
    width: u16,
    length: u32,
    family: u8,
    layout: u8,
    original: u32,
    r: [(u64, u64); 4],
) -> Rotation {
    let mut raw = b"stele/v0.1/cqis/rotation".to_vec();
    raw.extend(width.to_le_bytes());
    raw.extend(length.to_le_bytes());
    raw.extend([family, layout]);
    raw.extend(original.to_le_bytes());
    for (n, d) in r {
        raw.extend(n.to_le_bytes());
        raw.extend(d.to_le_bytes());
    }
    Rotation::decode(&raw).expect("rotation fixture")
}

/// Llama-2 (base theta 10000), linear scaling, and Llama-3.1 (llama3 scaling) rotations.
fn fixtures(width: u16, layout: u8) -> Vec<Rotation> {
    vec![
        rotation(
            width,
            4096,
            0,
            layout,
            0,
            [(10000, 1), (1, 1), (0, 1), (0, 1)],
        ),
        rotation(
            width,
            4096,
            1,
            layout,
            0,
            [(500000, 1), (4, 1), (0, 1), (0, 1)],
        ),
        rotation(
            width,
            131072,
            2,
            layout,
            8192,
            [(500000, 1), (8, 1), (1, 1), (4, 1)],
        ),
    ]
}

/// The executor's `rotate` (stele-cqis execution/attention.rs) restated: `None` on
/// int16 overflow, where the executor returns `Error::Range`.
fn reference(
    r: Option<&Rotation>,
    input: &[i16],
    tokens: usize,
    heads: usize,
    width: usize,
) -> Option<Vec<i16>> {
    let round = |n: i64| {
        let (q, rem) = (n.unsigned_abs() / 16384, n.unsigned_abs() % 16384);
        let v = (q + u64::from(rem >= 16384 - rem)) as i64;
        i16::try_from(if n < 0 { -v } else { v }).ok()
    };
    let mut out = input.to_vec();
    let Some(r) = r else { return Some(out) };
    for t in 0..tokens {
        for j in 0..r.width() / 2 {
            let (c, s) = r.coefficient(t as u32, j).expect("coefficient");
            let (c, s) = (i64::from(c), i64::from(s));
            for h in 0..heads {
                let base = (t * heads + h) * width;
                let left = base
                    + if r.layout() == 0 {
                        2 * usize::from(j)
                    } else {
                        usize::from(j)
                    };
                let right = left
                    + if r.layout() == 0 {
                        1
                    } else {
                        usize::from(r.width() / 2)
                    };
                let (x, y) = (i64::from(input[left]), i64::from(input[right]));
                out[left] = round(x * c - y * s)?;
                out[right] = round(x * s + y * c)?;
            }
        }
    }
    Some(out)
}

struct Case {
    relation: Relation,
    values: Values,
    rope: Rope,
}

impl Case {
    fn column(&self, id: ColumnId) -> &[i64] {
        self.values.get(&self.relation, id).expect("column")
    }
}

/// Declare an int16 input column (padding 0, as its producer pins it), the module, and
/// assign both from `input`.
fn case(
    r: Option<&Rotation>,
    input: &[i16],
    tokens: usize,
    heads: u16,
    width: u16,
) -> Result<Case, Violation> {
    let mut relation = Relation::default();
    let mut rope = Rope::new(0, "q", ColumnId(0), tokens, heads, width, r).expect("plan");
    let n = rope.log_len();
    let group = relation.add_group("L0/projection/test", n);
    let x = relation.add_column("x", Kind::Witness(group), Width::signed(16), n);
    relation.ranges.push(Range {
        name: "x".into(),
        column: x,
        width: Width::signed(16),
    });
    rope.declare(&mut relation);
    let mut values = Values::new(&relation);
    let mut padded = vec![0; 1 << n];
    for (index, v) in padded.iter_mut().enumerate() {
        if let Some((t, h, i)) = rope.entry(index) {
            *v = i64::from(input[rope.offset(t, h, i)]);
        }
    }
    values.set(&relation, x, padded).expect("input");
    rope.assign(&relation, input, &mut values)?;
    Ok(Case {
        relation,
        values,
        rope,
    })
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn input(&mut self, len: usize, extreme: bool) -> Vec<i16> {
        (0..len)
            .map(|_| match (extreme, self.next() % 4) {
                (true, 0) => i16::MIN,
                (true, 1) => i16::MAX,
                (true, 2) => -1 - (self.next() % 4) as i16,
                // Below 2^14 a rotated pair stays int16; extremes also exercise overflow.
                _ => (self.next() as i16) >> 2,
            })
            .collect()
    }
}

/// Every shape and fixture rotation: the module output equals the reference, and the
/// plain checker accepts; overflowing references (executor `Range`) fail in `assign`.
fn accepts(extreme: bool) {
    let mut rng = Rng(0x0e16_0006 + u64::from(extreme));
    let (mut accepted, mut overflowed) = (0, 0);
    // (tokens, heads, head width, rotary width): full, partial, odd head count, unpadded width.
    for (tokens, heads, width, rotary) in [(4, 2, 8, 8), (3, 3, 8, 4), (2, 1, 6, 4), (4, 2, 16, 12)]
    {
        for layout in [0, 1] {
            let mut rotations: Vec<_> = fixtures(rotary, layout).into_iter().map(Some).collect();
            rotations.push(None);
            for r in &rotations {
                for _ in 0..4 {
                    let len = tokens * usize::from(heads) * usize::from(width);
                    let input = rng.input(len, extreme);
                    let expected =
                        reference(r.as_ref(), &input, tokens, heads.into(), width.into());
                    let Ok(case) = case(r.as_ref(), &input, tokens, heads, width) else {
                        assert!(expected.is_none(), "assign fails only on executor overflow");
                        overflowed += 1;
                        continue;
                    };
                    let expected = expected.expect("assign succeeds only without overflow");
                    check(&case.relation, &case.values).expect("honest values pass");
                    let out = case.column(case.rope.columns().expect("declared").output);
                    for (index, v) in out.iter().enumerate() {
                        let want = case.rope.entry(index).map_or(0, |(t, h, i)| {
                            i64::from(expected[case.rope.offset(t, h, i)])
                        });
                        assert_eq!(*v, want, "output {index}");
                    }
                    accepted += 1;
                }
            }
        }
    }
    assert!(accepted > 0 && (overflowed > 0) == extreme);
}

#[test]
fn matches_reference_random_rows() {
    accepts(false);
}

#[test]
fn matches_reference_extreme_rows() {
    accepts(true);
}

/// Replace output entry `index` by `out` and re-solve every auxiliary column that the
/// identities determine, for each of the four `(β, ν)` choices: the strongest
/// assignment with that output. The checker must reject all of them.
fn rejects_output(case: &Case, index: usize, out: i64) {
    let c = case.rope.columns().expect("declared");
    let get = |id| case.column(id)[index];
    let numerator = (get(c.output) - get(c.half)) * DIVISOR + get(c.low);
    for half in 0..2 {
        for negative in 0..2 {
            let low = numerator - (out - half) * DIVISOR;
            let row = [
                (c.output, out),
                (c.half, half),
                (c.negative, negative),
                (c.low, low),
                (c.twos, out - half + (negative << 16)),
                (c.tie, (2 * half - 1) * (low - HALF - negative) - (1 - half)),
            ];
            let mut values = case.values.clone();
            for (id, v) in row {
                let mut column = case.column(id).to_vec();
                column[index] = v;
                values.set(&case.relation, id, column).expect("set");
            }
            assert!(
                matches!(check(&case.relation, &values), Err(Violation::Range { .. })),
                "accepted output {out} at {index} with β={half} ν={negative}"
            );
        }
    }
}

fn tie_case(negative: bool) -> (Case, usize) {
    let r = fixtures(8, 0).remove(0);
    // Position 1, pair 0: left = R((x·c − y·s)/2^14) with y = 0 is a tie when x·c ≡ 2^13.
    let (c, _) = r.coefficient(1, 0).expect("coefficient");
    let c = i64::from(c);
    let x = (-DIVISOR..DIVISOR)
        .find(|x| (x * c).rem_euclid(DIVISOR) == HALF && (x * c < 0) == negative)
        .expect("a tie input");
    let mut input = vec![0i16; 2 * 8];
    input[8] = x as i16;
    let case = case(Some(&r), &input, 2, 1, 8).expect("honest");
    check(&case.relation, &case.values).expect("honest tie");
    // Output index of (t = 1, head 0, channel 0).
    let index = 1 << case.rope.bits().0;
    (case, index)
}

#[test]
fn rejects_output_off_by_one() {
    let mut rng = Rng(77);
    for r in fixtures(8, 1) {
        let input = rng.input(4 * 2 * 8, false);
        let case = case(Some(&r), &input, 4, 2, 8).expect("honest");
        let output = case.rope.columns().expect("declared").output;
        for index in [0, 5, 17, 40, 63] {
            let out = case.column(output)[index];
            rejects_output(&case, index, out + 1);
            rejects_output(&case, index, out - 1);
        }
    }
}

#[test]
fn rejects_other_rounding_direction_at_ties() {
    for negative in [false, true] {
        let (case, index) = tie_case(negative);
        let c = case.rope.columns().expect("declared");
        let out = case.column(c.output)[index];
        assert_eq!(case.column(c.low)[index], HALF, "the fixture is a tie");
        // Away from zero is honest; toward zero is the other direction.
        assert_eq!(out.signum(), if negative { -1 } else { 1 });
        assert_eq!(case.column(c.half)[index], i64::from(!negative));
        rejects_output(&case, index, out - out.signum());
    }
}

#[test]
fn rejects_tampered_partner() {
    let mut rng = Rng(5);
    let r = fixtures(8, 0).remove(2);
    let case = case(Some(&r), &rng.input(64, false), 4, 2, 8).expect("honest");
    let id = case.rope.columns().expect("declared").partner;
    let mut values = case.values.clone();
    let mut partner = case.column(id).to_vec();
    partner[9] += 1;
    values.set(&case.relation, id, partner).expect("set");
    assert!(matches!(
        check(&case.relation, &values),
        Err(Violation::Matmul { .. })
    ));
}

/// Honest outputs of the other layout, or of every row shifted by one position, are
/// rejected under the honest plan.
#[test]
fn rejects_wrong_pairing_and_position() {
    let mut rng = Rng(11);
    let input = rng.input(4 * 2 * 8, false);
    let honest = case(Some(&fixtures(8, 0)[0]), &input, 4, 2, 8).expect("honest");
    let other = case(Some(&fixtures(8, 1)[0]), &input, 4, 2, 8).expect("other layout");
    let mut shifted = vec![0; 5 * 2 * 8];
    shifted[16..].copy_from_slice(&input);
    let shifted = case(Some(&fixtures(8, 0)[0]), &shifted, 5, 2, 8).expect("shifted");
    let row = 1 << h_bits(&honest);
    // Rows 1..5 of `shifted` are positions 1..5 applied to the honest rows 0..4.
    for (wrong, offset) in [(&other, 0), (&shifted, row)] {
        let mut values = honest.values.clone();
        let (h, w) = (
            honest.rope.columns().expect("declared"),
            wrong.rope.columns().expect("declared"),
        );
        let pairs = [
            (h.output, w.output),
            (h.partner, w.partner),
            (h.low, w.low),
            (h.half, w.half),
            (h.negative, w.negative),
            (h.twos, w.twos),
            (h.tie, w.tie),
        ];
        for (a, b) in pairs {
            let len = 1 << honest.rope.log_len();
            let column = wrong.column(b)[offset..offset + len].to_vec();
            values.set(&honest.relation, a, column).expect("set");
        }
        assert!(check(&honest.relation, &values).is_err());
    }
}

/// Bits of one row `(head, channel)`.
fn h_bits(case: &Case) -> u8 {
    let (d, h, _) = case.rope.bits();
    d + h
}

#[test]
fn rejects_nonzero_padding() {
    let mut rng = Rng(3);
    let input = rng.input(2 * 3 * 6, false);
    let case = case(Some(&fixtures(4, 0)[0]), &input, 2, 3, 6).expect("honest");
    let padding = (0..1 << case.rope.log_len())
        .filter(|&i| case.rope.entry(i).is_none())
        .collect::<Vec<_>>();
    for index in [padding[0], padding[padding.len() - 1]] {
        rejects_output(&case, index, 1);
        rejects_output(&case, index, -1);
    }
}

/// Realistic shapes validate (RFC-0026 §3.6): the Llama-3.1-8B fixture's Q (32 heads)
/// and K (8 groups) at head width 128, and a head width 64 model with adjacent pairs;
/// Q and K share one layer group.
#[test]
fn accepts_static_validity_realistic_shapes() {
    let model = llama();
    let shape = model.shape();
    let llama = model.blocks()[0].rotation().copied().expect("rotation");
    let small = fixtures(64, 0).remove(0);
    for (heads, groups, width, tokens, r) in [
        (
            shape.heads(),
            shape.groups(),
            shape.head_width(),
            64usize,
            llama,
        ),
        (16, 16, 64, 64, small),
    ] {
        let mut relation = Relation::default();
        for (role, count) in [("q", heads), ("k", groups)] {
            let n = log2_ceil(tokens) + log2_ceil(count.into()) + log2_ceil(width.into());
            let group = relation.add_group(&format!("L0/projection/{role}"), n);
            let x = relation.add_column(role, Kind::Witness(group), Width::signed(16), n);
            relation.ranges.push(Range {
                name: role.into(),
                column: x,
                width: Width::signed(16),
            });
            let mut rope = Rope::new(0, role, x, tokens, count, width, Some(&r)).expect("plan");
            rope.declare(&mut relation);
        }
        relation.validate().expect("valid");
    }
}

/// The Llama-3.1-8B Model of the rotation reference evidence (stele-cqis fixtures):
/// its block-0 rotation over 32 query heads and 8 key groups of width 128.
fn llama() -> stele_cqis::model::Model {
    stele_cqis::model::Model::decode(include_bytes!(
        "../../../stele-cqis/tests/fixtures/original-llama-rotation-reference/model.bin"
    ))
    .expect("fixture Model")
}

#[test]
fn matches_reference_llama_fixture() {
    let model = llama();
    let (shape, r) = (model.shape(), model.blocks()[0].rotation().copied());
    let mut rng = Rng(31);
    for count in [shape.heads(), shape.groups()] {
        let input = rng.input(
            4 * usize::from(count) * usize::from(shape.head_width()),
            false,
        );
        let case = case(r.as_ref(), &input, 4, count, shape.head_width()).expect("honest");
        check(&case.relation, &case.values).expect("honest values pass");
        let expected = reference(
            r.as_ref(),
            &input,
            4,
            count.into(),
            shape.head_width().into(),
        )
        .expect("no overflow");
        let out = case.column(case.rope.columns().expect("declared").output);
        let honest = (0..out.len()).all(|index| {
            out[index]
                == case.rope.entry(index).map_or(0, |(t, h, i)| {
                    i64::from(expected[case.rope.offset(t, h, i)])
                })
        });
        assert!(honest);
    }
}

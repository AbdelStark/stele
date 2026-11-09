//! SiLU gated product tests: executor-equivalent honest values, near misses, shapes.

use super::*;
use stele_cqis::tables::Descriptor;
use stele_ir::relation::check;

fn silu(fraction: u8, output: u8) -> CqisTable {
    let descriptor = Descriptor::new("silu_q", 1, &[fraction, output]).expect("descriptor");
    CqisTable::generate(descriptor).expect("silu_q table")
}

struct Case {
    relation: Relation,
    values: Values,
    module: GatedProduct,
}

impl Case {
    fn column(&self, id: ColumnId) -> &[i64] {
        self.values.get(&self.relation, id).expect("column")
    }

    /// `T = 2^15·high + low` at every padded index.
    fn product(&self) -> Vec<i64> {
        let c = self.module.columns().expect("declared");
        let (high, low) = (self.column(c.high), self.column(c.low));
        high.iter()
            .zip(low)
            .map(|(h, l)| (h << LOW_BITS) + l)
            .collect()
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

/// Declare int16 gate/up input columns (padding 0, as their producer pins it), the
/// module, and assign both.
fn case(table: &CqisTable, capture: &GatedCapture, tokens: usize, hidden: usize) -> Case {
    let mut relation = Relation::default();
    let n = log2_ceil(tokens) + log2_ceil(hidden);
    let group = relation.add_group("L0/projection/test", n);
    let mut inputs = [ColumnId(0); 2];
    for (slot, name) in inputs.iter_mut().zip(["gate", "up"]) {
        *slot = relation.add_column(name, Kind::Witness(group), Width::signed(16), n);
        relation.ranges.push(Range {
            name: name.into(),
            column: *slot,
            width: Width::signed(16),
        });
    }
    let mut module =
        GatedProduct::new(0, inputs[0], inputs[1], tokens, hidden, table).expect("plan");
    module.declare(&mut relation);
    let mut values = Values::new(&relation);
    for (id, raw) in inputs.into_iter().zip([&capture.gate, &capture.up]) {
        let padded = (0..1usize << n)
            .map(|x| {
                module
                    .entry(x)
                    .map_or(0, |(t, j)| i64::from(raw[t * hidden + j]))
            })
            .collect();
        values.set(&relation, id, padded).expect("input");
    }
    module
        .assign(&relation, capture, &mut values)
        .expect("honest");
    Case {
        relation,
        values,
        module,
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
    fn row(&mut self, len: usize, extreme: bool) -> Vec<i16> {
        (0..len)
            .map(|_| match (extreme, self.next() % 4) {
                (true, 0) => i16::MIN,
                (true, 1) => i16::MAX,
                (true, 2) => (self.next() % 5) as i16 - 2,
                _ => self.next() as i16,
            })
            .collect()
    }
    fn capture(&mut self, len: usize, extreme: bool) -> GatedCapture {
        GatedCapture {
            gate: self.row(len, extreme),
            up: self.row(len, extreme),
        }
    }
}

/// The executor's gated product (stele-cqis execution/forward.rs): `U·silu_q[G]` as
/// int32, with `silu_q` from the generated component table.
fn reference(table: &CqisTable, capture: &GatedCapture) -> Vec<i64> {
    let entries = table.entries();
    capture
        .gate
        .iter()
        .zip(&capture.up)
        .map(|(&g, &u)| i64::from(u) * i64::from(entries[2 * (i64::from(g) + 32768) as usize + 1]))
        .collect()
}

fn accepts(extreme: bool) {
    let mut rng = Rng(0x0e16_0008 + u64::from(extreme));
    for (fraction, output) in [(8, 8), (12, 4), (14, 14)] {
        let table = silu(fraction, output);
        for (tokens, hidden) in [(1, 1), (3, 5), (4, 8), (2, 100)] {
            let capture = rng.capture(tokens * hidden, extreme);
            let case = case(&table, &capture, tokens, hidden);
            check(&case.relation, &case.values).expect("honest values pass");
            let expected = reference(&table, &capture);
            for (index, v) in case.product().into_iter().enumerate() {
                let want = case
                    .module
                    .entry(index)
                    .map_or(0, |(t, j)| expected[t * hidden + j]);
                assert_eq!(v, want, "product {index}");
            }
        }
    }
}

#[test]
fn matches_reference_random_rows() {
    accepts(false);
}

#[test]
fn matches_reference_extreme_rows() {
    accepts(true);
}

/// The Llama-3.1-8B fixture's block-0 SiLU component, at its real hidden width.
fn llama() -> (CqisTable, usize) {
    let model = stele_cqis::model::Model::decode(include_bytes!(
        "../../../stele-cqis/tests/fixtures/original-llama-rotation-reference/model.bin"
    ))
    .expect("fixture Model");
    let component = model.blocks()[0].activation().components()[0];
    let table = CqisTable::generate(component).expect("silu_q table");
    (table, usize::from(model.shape().hidden()))
}

#[test]
fn matches_reference_llama_fixture() {
    let (table, hidden) = llama();
    let mut rng = Rng(9);
    let capture = rng.capture(2 * hidden, false);
    let case = case(&table, &capture, 2, hidden);
    check(&case.relation, &case.values).expect("honest values pass");
    let expected = reference(&table, &capture);
    let product = case.product();
    assert!((0..2 * hidden).all(|k| product[((k / hidden) << 14) | (k % hidden)] == expected[k]));
}

/// Every limb downstream of `(Ul, Uh, a)` recomputed honestly at `index`.
fn limbs(case: &Case, index: usize, ul: i64, uh: i64, a: i64) -> Vec<(ColumnId, usize, i64)> {
    let c = case.module.columns().expect("declared");
    let low = ul * a;
    let middle = uh * a + (low >> 8);
    vec![
        (c.up_low, index, ul),
        (c.up_high, index, uh),
        (c.activation, index, a),
        (c.carry, index, low >> 8),
        (c.byte, index, low & 0xff),
        (c.middle, index, middle & 0x7f),
        (c.high, index, middle >> 7),
        (c.low, index, ((middle & 0x7f) << 8) | (low & 0xff)),
    ]
}

/// Strongest near misses at `index`, each failing one constraint:
/// - `T ± 1` through `Tl` alone (the `low` Compose);
/// - `T ± 1` through `d` with `c` honest (`low_product`), and with the carry chosen to
///   satisfy `low_product` (`high_product`);
/// - `T ± 2^8` and `T ± 2^15` with `c`, `d` honest and `Th`, `w`, `Tl` recomputed
///   (`high_product`, and the high limb E16-05 consumes);
/// - a forged split `Ul ± 1` with every downstream limb recomputed (the `up` Compose);
/// - `a ± 1` with every limb recomputed (the lookup).
fn near_misses(case: &Case, index: usize) -> Vec<Values> {
    let c = case.module.columns().expect("declared");
    let get = |id| case.column(id)[index];
    let (ul, uh, a, carry, byte) = (
        get(c.up_low),
        get(c.up_high),
        get(c.activation),
        get(c.carry),
        get(c.byte),
    );
    let product = (get(c.high) << LOW_BITS) + get(c.low);
    let mut all = Vec::new();
    for sign in [1, -1] {
        let low = get(c.low) + sign;
        if (0..1 << LOW_BITS).contains(&low) {
            all.push(case.with(&[(c.low, index, low)]));
        }
        let wrong = product + sign;
        let (d, w) = (wrong & 0xff, (wrong >> 8) & 0x7f);
        for carry in [carry, (ul * a - d).div_euclid(256)] {
            all.push(case.with(&[
                (c.high, index, wrong >> LOW_BITS),
                (c.low, index, wrong & 0x7fff),
                (c.byte, index, d),
                (c.middle, index, w),
                (c.carry, index, carry),
            ]));
        }
        for shift in [8, 15] {
            let wrong = product + sign * (1 << shift);
            assert_eq!(wrong & 0xff, byte, "the byte is unchanged");
            all.push(case.with(&[
                (c.high, index, wrong >> LOW_BITS),
                (c.low, index, wrong & 0x7fff),
                (c.middle, index, (wrong >> 8) & 0x7f),
            ]));
        }
        let forged = ul + sign;
        if (0..256).contains(&forged) {
            all.push(case.with(&limbs(case, index, forged, uh, a)));
        }
        all.push(case.with(&limbs(case, index, ul, uh, a + sign)));
    }
    all
}

#[test]
fn rejects_product_near_misses() {
    let mut rng = Rng(21);
    let table = silu(8, 8);
    let case = case(&table, &rng.capture(4 * 8, false), 4, 8);
    for index in 0..32 {
        for values in near_misses(&case, index) {
            assert!(
                check(&case.relation, &values).is_err(),
                "accepted at {index}"
            );
        }
    }
}

/// A neighbouring table output with every limb recomputed honestly from it.
#[test]
fn rejects_wrong_table_entry() {
    let mut rng = Rng(22);
    let table = silu(8, 8);
    let case = case(&table, &rng.capture(4 * 8, false), 4, 8);
    let c = case.module.columns().expect("declared");
    for index in [0, 9, 30] {
        let a = case.column(c.activation)[index] + 1;
        let (ul, uh) = (case.column(c.up_low)[index], case.column(c.up_high)[index]);
        let low = ul * a;
        let middle = uh * a + (low >> 8);
        let values = case.with(&[
            (c.activation, index, a),
            (c.carry, index, low >> 8),
            (c.byte, index, low & 0xff),
            (c.middle, index, middle & 0x7f),
            (c.high, index, middle >> 7),
            (c.low, index, ((middle & 0x7f) << 8) | (low & 0xff)),
        ]);
        assert!(matches!(
            check(&case.relation, &values),
            Err(Violation::Lookup { .. })
        ));
    }
}

/// Moving one radix unit between adjacent limbs keeps every identity and composed value
/// and must fail a range.
#[test]
fn rejects_wrong_limb() {
    let mut rng = Rng(23);
    let table = silu(12, 4);
    let case = case(&table, &rng.capture(4 * 8, false), 4, 8);
    let c = case.module.columns().expect("declared");
    let index = 5;
    let get = |id| case.column(id)[index];
    let tampers = [
        // Th carries 2^15 into Tl, through w.
        vec![
            (c.high, index, get(c.high) + 1),
            (c.middle, index, get(c.middle) - 128),
            (c.low, index, get(c.low) - (1 << 15)),
        ],
        // c carries 2^8 into d.
        vec![
            (c.carry, index, get(c.carry) + 1),
            (c.byte, index, get(c.byte) - 256),
            (c.middle, index, get(c.middle) + 1),
        ],
        // Uh carries 2^8 into Ul.
        vec![
            (c.up_high, index, get(c.up_high) + 1),
            (c.up_low, index, get(c.up_low) - 256),
        ],
    ];
    for tamper in tampers {
        assert!(matches!(
            check(&case.relation, &case.with(&tamper)),
            Err(Violation::Range { .. })
        ));
    }
}

#[test]
fn rejects_nonzero_padding() {
    let mut rng = Rng(24);
    let table = silu(8, 8);
    let case = case(&table, &rng.capture(3 * 5, true), 3, 5);
    let c = case.module.columns().expect("declared");
    let padding = (0..32)
        .find(|&i| case.module.entry(i).is_none())
        .expect("padding");
    for tamper in [
        (c.high, padding, 1),
        (c.low, padding, 1),
        (c.byte, padding, 1),
    ] {
        assert!(check(&case.relation, &case.with(&[tamper])).is_err());
    }
}

/// Realistic shapes validate (RFC-0026 §3.6): the Llama-3.1-8B fixture at its hidden
/// width 14336 and T = 64, two layers sharing the one silu_q table.
#[test]
fn accepts_static_validity_realistic_shapes() {
    let (table, hidden) = llama();
    let mut relation = Relation::default();
    let n = 6 + log2_ceil(hidden);
    let group = relation.add_group("L0/projection/test", n);
    for layer in 0..2 {
        let mut inputs = [ColumnId(0); 2];
        for (slot, name) in inputs.iter_mut().zip(["gate", "up"]) {
            *slot = relation.add_column(name, Kind::Witness(group), Width::signed(16), n);
            relation.ranges.push(Range {
                name: name.into(),
                column: *slot,
                width: Width::signed(16),
            });
        }
        let mut module =
            GatedProduct::new(layer, inputs[0], inputs[1], 64, hidden, &table).expect("plan");
        module.declare(&mut relation);
    }
    assert_eq!(relation.tables.len(), 1);
    relation.validate().expect("valid");
}

#[test]
fn rejects_table_with_minimum_output() {
    let table = silu(8, 8);
    let mut entries = table.entries().to_vec();
    assert!(silu_outputs(&entries).is_ok());
    // A row reaching −2^15 would allow T = 2^30, which has no signed-16 high limb.
    entries[1] = -32768;
    assert_eq!(silu_outputs(&entries), Err(TableError::Shape));
    entries.pop();
    assert_eq!(silu_outputs(&entries), Err(TableError::Parameters));
}

type Mutation = (&'static str, fn(&mut Relation));

/// Mutation table (RFC-0026 §5.2): deleting each identity, Compose or the lookup lets
/// at least one near miss of `near_misses` through.
#[test]
fn rejects_relation_without_each_constraint() {
    let mut rng = Rng(25);
    let table = silu(12, 4);
    let case = case(&table, &rng.capture(4 * 8, false), 4, 8);
    let attacks: Vec<Values> = (0..32).flat_map(|i| near_misses(&case, i)).collect();
    assert!(attacks.iter().all(|v| check(&case.relation, v).is_err()));
    let mutations: [Mutation; 5] = [
        ("low_product", |r| {
            r.identities.retain(|i| !i.name.ends_with("/low_product"))
        }),
        ("high_product", |r| {
            r.identities.retain(|i| !i.name.ends_with("/high_product"))
        }),
        ("up", |r| r.composes.retain(|c| !c.name.ends_with("/up"))),
        ("low", |r| r.composes.retain(|c| !c.name.ends_with("/low"))),
        ("silu", |r| r.lookups.retain(|l| !l.name.ends_with("/silu"))),
    ];
    for (name, mutate) in mutations {
        let mut relation = case.relation.clone();
        mutate(&mut relation);
        assert!(relation != case.relation, "{name} changed nothing");
        // Deleting a disciplining relation also needs its column ranged to stay valid.
        for id in [
            case.module.columns().expect("declared").activation,
            case.module.columns().expect("declared").low,
        ] {
            let width = relation.columns[id.0 as usize].width;
            relation.ranges.push(Range {
                name: "mutation".into(),
                column: id,
                width,
            });
        }
        assert!(
            attacks.iter().any(|v| check(&relation, v).is_ok()),
            "no near miss needs {name}"
        );
    }
}

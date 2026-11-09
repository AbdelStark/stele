//! Plain-checker tests: one honest relation of every kind and one tamper per kind.

use super::*;
use alloc::string::ToString;
use alloc::vec;

struct Fixture {
    relation: Relation,
    values: Values,
    a: ColumnId,
    b: ColumnId,
    c: ColumnId,
    square: ColumnId,
    y: ColumnId,
    z: ColumnId,
}

fn r(column: ColumnId, vars: &[u8]) -> Ref {
    Ref {
        column,
        vars: vars.to_vec(),
    }
}

fn range(relation: &mut Relation, column: ColumnId, width: Width) {
    let name = relation.columns[column.0 as usize].name.clone();
    relation.ranges.push(Range {
        name,
        column,
        width,
    });
}

/// a = b*c, (b, b^2) in squares, c in {4,5,-6} where selected, Y = X·W, Z[i,j] = Y[i,j]*s[i].
fn fixture() -> Fixture {
    let mut rel = Relation::default();
    let g = Kind::Witness(rel.add_group("L0/test/2", 2));
    let rows = Kind::Witness(rel.add_group("L0/test/1", 1));
    let b = rel.add_column("b", g.clone(), Width::signed(8), 2);
    let c = rel.add_column("c", g.clone(), Width::signed(8), 2);
    let a = rel.add_column("a", g.clone(), Width::signed(16), 2);
    let square = rel.add_column("square", g.clone(), Width::unsigned(15), 2);
    let x = rel.add_column("x", g.clone(), Width::signed(4), 2);
    let w = rel.add_column("w", Kind::Weight, Width::signed(8), 2);
    let y = rel.add_column("y", g.clone(), Width::signed(13), 2);
    let s = rel.add_column("s", rows, Width::unsigned(2), 1);
    let z = rel.add_column("z", g, Width::signed(16), 2);
    let selector = rel.add_column(
        "selector",
        Kind::Public(vec![1, 1, 1, 0]),
        Width::unsigned(1),
        2,
    );
    for (column, width) in [(b, 8), (c, 8), (a, 16), (x, 4), (w, 8), (y, 13), (z, 16)] {
        range(&mut rel, column, Width::signed(width));
    }
    range(&mut rel, s, Width::unsigned(2));
    let squares = rel.add_table(Table {
        name: "squares".to_string(),
        widths: vec![Width::signed(8), Width::unsigned(15)],
        rows: (-128..128).map(|v| vec![v, v * v]).collect(),
    });
    let allowed = rel.add_table(Table {
        name: "allowed".to_string(),
        widths: vec![Width::signed(8)],
        rows: vec![vec![4], vec![5], vec![-6]],
    });
    rel.identities.push(Identity {
        name: "product".to_string(),
        vars: 2,
        terms: vec![
            Term {
                coeff: 1,
                factors: vec![r(a, &[0, 1])],
            },
            Term {
                coeff: -1,
                factors: vec![r(b, &[0, 1]), r(c, &[0, 1])],
            },
        ],
    });
    // Broadcast: s has one entry per row i (domain bit 1).
    rel.identities.push(Identity {
        name: "scale".to_string(),
        vars: 2,
        terms: vec![
            Term {
                coeff: 1,
                factors: vec![r(z, &[0, 1])],
            },
            Term {
                coeff: -1,
                factors: vec![r(y, &[0, 1]), r(s, &[1])],
            },
        ],
    });
    rel.lookups.push(Lookup {
        name: "squares".to_string(),
        vars: 2,
        selector: None,
        tuple: vec![r(b, &[0, 1]), r(square, &[0, 1])],
        table: squares,
    });
    rel.lookups.push(Lookup {
        name: "allowed".to_string(),
        vars: 2,
        selector: Some(r(selector, &[0, 1])),
        tuple: vec![r(c, &[0, 1])],
        table: allowed,
    });
    // Domain bits: 0 = j, 1 = i (free), 2 = k (summed); row-major X[i,k], W[k,j], Y[i,j].
    rel.matmuls.push(Matmul {
        name: "xw".to_string(),
        free: 2,
        summed: 1,
        out: r(y, &[0, 1]),
        lhs: r(x, &[2, 1]),
        rhs: r(w, &[0, 2]),
    });

    let mut values = Values::new(&rel);
    let xv = vec![1, -2, 7, 3];
    let wv = vec![100, -128, 5, 127];
    let yv: Vec<i64> = (0..4)
        .map(|n| {
            (0..2)
                .map(|k| xv[(n / 2) * 2 + k] * wv[k * 2 + n % 2])
                .sum()
        })
        .collect();
    let sv = vec![3, 2];
    let zv: Vec<i64> = (0..4).map(|n| yv[n] * sv[n / 2]).collect();
    for (id, column) in [
        (b, vec![1, -2, 3, 0]),
        (c, vec![4, 5, -6, 0]),
        (a, vec![4, -10, -18, 0]),
        (square, vec![1, 4, 9, 0]),
        (x, xv),
        (w, wv),
        (y, yv),
        (s, sv),
        (z, zv),
    ] {
        values.set(&rel, id, column).expect("fixture column");
    }
    Fixture {
        relation: rel,
        values,
        a,
        b,
        c,
        square,
        y,
        z,
    }
}

fn tamper(f: &mut Fixture, id: ColumnId, index: usize, delta: i64) {
    let mut column = f.values.get(&f.relation, id).expect("assigned").to_vec();
    column[index] += delta;
    f.values.set(&f.relation, id, column).expect("same length");
}

#[test]
fn accepts_honest_relation_of_every_kind() {
    let f = fixture();
    assert_eq!(check(&f.relation, &f.values), Ok(()));
}

#[test]
fn rejects_identity_tamper() {
    let mut f = fixture();
    let a = f.a;
    tamper(&mut f, a, 1, 1);
    assert_eq!(
        check(&f.relation, &f.values),
        Err(Violation::Identity {
            relation: "product".to_string(),
            point: 1
        })
    );
}

#[test]
fn rejects_out_of_range_value() {
    let mut f = fixture();
    let b = f.b;
    tamper(&mut f, b, 0, 200);
    assert_eq!(
        check(&f.relation, &f.values),
        Err(Violation::Range {
            relation: "b".to_string(),
            index: 0
        })
    );
}

#[test]
fn rejects_lookup_tamper() {
    let mut f = fixture();
    let square = f.square;
    tamper(&mut f, square, 2, 1);
    assert_eq!(
        check(&f.relation, &f.values),
        Err(Violation::Lookup {
            relation: "squares".to_string(),
            point: 2
        })
    );
}

#[test]
fn rejects_selected_lookup_tamper_and_skips_unselected_rows() {
    let mut f = fixture();
    let (a, c) = (f.a, f.c);
    // Row 3 is unselected: c = 9 is outside {4,5,-6} yet accepted there (b = a = 0).
    tamper(&mut f, c, 3, 9);
    assert_eq!(check(&f.relation, &f.values), Ok(()));
    tamper(&mut f, c, 3, -9);
    // c[0] = 6 is not allowed; a[0] = b[0]*c[0] keeps the identity true.
    tamper(&mut f, c, 0, 2);
    tamper(&mut f, a, 0, 2);
    assert_eq!(
        check(&f.relation, &f.values),
        Err(Violation::Lookup {
            relation: "allowed".to_string(),
            point: 0
        })
    );
}

#[test]
fn rejects_matmul_tamper() {
    let mut f = fixture();
    let (y, z) = (f.y, f.z);
    // Keep the broadcast identity consistent so only the matmul can fail (s[1] = 2).
    tamper(&mut f, y, 3, 1);
    tamper(&mut f, z, 3, 2);
    assert_eq!(
        check(&f.relation, &f.values),
        Err(Violation::Matmul {
            relation: "xw".to_string(),
            point: 3
        })
    );
}

#[test]
fn rejects_wrapping_identity() {
    let mut f = fixture();
    let wide = f
        .relation
        .add_column("wide", Kind::Witness(GroupId(0)), Width::signed(16), 2);
    range(&mut f.relation, wide, Width::signed(16));
    f.relation.identities.push(Identity {
        name: "wraps".to_string(),
        vars: 2,
        terms: vec![Term {
            coeff: 1,
            factors: vec![r(wide, &[0, 1]), r(wide, &[0, 1]), r(wide, &[0, 1])],
        }],
    });
    assert!(
        matches!(f.relation.validate(), Err(Invalid::Bound { relation, .. }) if relation == "wraps")
    );
}

#[test]
fn rejects_wrapping_matmul() {
    let mut f = fixture();
    // 2 * 2^15 * 2^15 + 2^12 >= p: two int16 products already wrap.
    f.relation.columns[f.relation.matmuls[0].lhs.column.0 as usize].width = Width::signed(16);
    f.relation.columns[f.relation.matmuls[0].rhs.column.0 as usize].width = Width::signed(16);
    assert!(
        matches!(f.relation.validate(), Err(Invalid::Bound { relation, .. }) if relation == "xw")
    );
}

#[test]
fn rejects_undisciplined_column() {
    let mut f = fixture();
    let a = f.a;
    f.relation.ranges.retain(|range| range.column != a);
    assert_eq!(f.relation.validate(), Err(Invalid::Undisciplined(a)));
}

#[test]
fn rejects_selected_lookup_as_discipline() {
    let mut f = fixture();
    let c = f.c;
    f.relation.ranges.retain(|range| range.column != c);
    assert_eq!(f.relation.validate(), Err(Invalid::Undisciplined(c)));
}

#[test]
fn rejects_narrower_declared_width_than_range() {
    let mut f = fixture();
    let a = f.a;
    f.relation
        .ranges
        .iter_mut()
        .filter(|range| range.column == a)
        .for_each(|range| range.width = Width::signed(16));
    f.relation.columns[a.0 as usize].width = Width::signed(12);
    assert_eq!(f.relation.validate(), Err(Invalid::Undisciplined(a)));
}

#[test]
fn rejects_malformed_refs_and_missing_values() {
    let mut f = fixture();
    f.relation.identities[0].terms[0].factors[0].vars = vec![0, 0];
    assert!(matches!(f.relation.validate(), Err(Invalid::Ref { .. })));
    let f = fixture();
    let mut values = Values::new(&f.relation);
    values
        .set(&f.relation, f.b, vec![0; 4])
        .expect("one column");
    assert!(matches!(
        check(&f.relation, &values),
        Err(Violation::Missing(_))
    ));
    assert_eq!(
        values.set(&f.relation, f.b, vec![0; 3]),
        Err(Invalid::Column(f.b))
    );
}

#[test]
fn rejects_witness_selector() {
    let mut f = fixture();
    let b = f.b;
    f.relation.lookups[1].selector = Some(r(b, &[0, 1]));
    assert!(
        matches!(f.relation.validate(), Err(Invalid::Shape { relation }) if relation == "allowed")
    );
}

/// wide = lo + 2^8 * hi with only the limbs ranged; `wide` is disciplined by Compose.
fn composed() -> (Relation, Values, ColumnId, ColumnId) {
    let mut rel = Relation::default();
    let g = Kind::Witness(rel.add_group("L0/limbs/1", 1));
    let lo = rel.add_column("lo", g.clone(), Width::unsigned(8), 1);
    let hi = rel.add_column("hi", g.clone(), Width::signed(16), 1);
    let wide = rel.add_column("wide", g, Width::signed(24), 1);
    range(&mut rel, lo, Width::unsigned(8));
    range(&mut rel, hi, Width::signed(16));
    rel.composes.push(Compose {
        name: "wide".to_string(),
        column: wide,
        limbs: vec![(lo, 0), (hi, 8)],
    });
    let mut values = Values::new(&rel);
    values.set(&rel, lo, vec![255, 3]).expect("lo");
    values.set(&rel, hi, vec![-32768, 32767]).expect("hi");
    values
        .set(&rel, wide, vec![255 - (32768 << 8), 3 + (32767 << 8)])
        .expect("wide");
    (rel, values, lo, wide)
}

#[test]
fn accepts_composed_wide_column_and_rejects_tampered_limb() {
    let (rel, mut values, lo, _) = composed();
    assert_eq!(check(&rel, &values), Ok(()));
    values.set(&rel, lo, vec![254, 3]).expect("lo");
    assert_eq!(
        check(&rel, &values),
        Err(Violation::Compose {
            relation: "wide".to_string(),
            index: 0
        })
    );
}

#[test]
fn rejects_composition_wider_than_its_column() {
    let (mut rel, _, _, wide) = composed();
    rel.columns[wide.0 as usize].width = Width::signed(23);
    assert_eq!(rel.validate(), Err(Invalid::Undisciplined(wide)));
}

#[test]
fn accepts_wide_matmul_out_without_range() {
    let mut f = fixture();
    let (x, y) = (f.relation.matmuls[0].lhs.column, f.y);
    f.relation.columns[x.0 as usize].width = Width::signed(8);
    f.relation
        .ranges
        .retain(|range| range.column != y && range.column != x);
    range(&mut f.relation, x, Width::signed(8));
    // 2 * 128 * 128 = 2^15 fits signed 17; out is exact without a Range.
    f.relation.columns[y.0 as usize].width = Width::signed(17);
    assert_eq!(check(&f.relation, &f.values), Ok(()));
    // 2^15 exceeds the signed-16 maximum 2^15 - 1.
    f.relation.columns[y.0 as usize].width = Width::signed(16);
    assert_eq!(f.relation.validate(), Err(Invalid::Undisciplined(y)));
}

#[test]
fn rejects_three_column_lookup() {
    let mut f = fixture();
    let (a, b, c) = (f.a, f.b, f.c);
    let triples = f.relation.add_table(Table {
        name: "triples".to_string(),
        widths: vec![Width::signed(8); 3],
        rows: vec![vec![0, 0, 0]],
    });
    f.relation.lookups.push(Lookup {
        name: "triples".to_string(),
        vars: 2,
        selector: None,
        tuple: vec![r(a, &[0, 1]), r(b, &[0, 1]), r(c, &[0, 1])],
        table: triples,
    });
    assert!(
        matches!(f.relation.validate(), Err(Invalid::Shape { relation }) if relation == "triples")
    );
}

#[test]
fn rejects_group_length_mismatch_and_duplicate_group() {
    let mut f = fixture();
    f.relation.columns[f.a.0 as usize].kind = Kind::Witness(GroupId(1));
    assert_eq!(f.relation.validate(), Err(Invalid::Column(f.a)));
    let mut f = fixture();
    f.relation.add_group("L0/test/2", 2);
    assert!(
        matches!(f.relation.validate(), Err(Invalid::Shape { relation }) if relation == "L0/test/2")
    );
}

#[test]
fn accepts_only_the_skipped_violation_with_check_except() {
    let mut f = fixture();
    let a = f.a;
    tamper(&mut f, a, 1, 1);
    assert!(check(&f.relation, &f.values).is_err());
    assert_eq!(check_except(&f.relation, &f.values, &["product"]), Ok(()));
    assert!(check_except(&f.relation, &f.values, &["scale"]).is_err());
}

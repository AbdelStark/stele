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

/// E16-22: with several failures the checker reports the first in sequential order,
/// both sequentially and on the pool (`std`): category order (the identity before the
/// matmul), then the least failing point (2 before 3).
#[test]
fn reports_the_sequential_first_failure() {
    let mut f = fixture();
    let (a, y, z) = (f.a, f.y, f.z);
    tamper(&mut f, y, 3, 1);
    tamper(&mut f, z, 3, 2);
    tamper(&mut f, a, 3, 1);
    tamper(&mut f, a, 2, 1);
    assert_eq!(
        check(&f.relation, &f.values),
        Err(Violation::Identity {
            relation: "product".to_string(),
            point: 2
        })
    );
}

/// Review of #362: constraint order beats point order. The identity fails at point 2
/// and the matmul at point 0; the identity, earlier in check order, is reported.
#[test]
fn reports_constraint_order_before_point_order() {
    let mut f = fixture();
    let (a, z) = (f.a, f.z);
    tamper(&mut f, a, 2, 1);
    tamper(&mut f, z, 0, 1);
    assert_eq!(
        check(&f.relation, &f.values),
        Err(Violation::Identity {
            relation: "product".to_string(),
            point: 2
        })
    );
}

/// Review of #362: the least failing point of a long range column (2^16 entries,
/// failures at every i ≥ 1000 with i % 7 = 0), stable across repeats on the pool.
#[test]
fn reports_the_least_failing_point_of_a_long_column() {
    let mut rel = Relation::default();
    let g = Kind::Witness(rel.add_group("L0/test/16", 16));
    let v = rel.add_column("v", g, Width::unsigned(10), 16);
    range(&mut rel, v, Width::unsigned(10));
    let mut values = Values::new(&rel);
    let column = (0..1i64 << 16)
        .map(|i| {
            if i >= 1000 && i % 7 == 0 {
                5000
            } else {
                i % 1000
            }
        })
        .collect();
    values.set(&rel, v, column).expect("length");
    for _ in 0..20 {
        assert_eq!(
            check(&rel, &values),
            Err(Violation::Range {
                relation: "v".to_string(),
                index: 1001
            })
        );
    }
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

/// RFC-0026 A31: a weight column without a range is undisciplined, and disciplined once the
/// relation says its passport carries the weight widths. A witness column gains nothing.
#[test]
fn accepts_weight_width_carried_by_the_passport_only_for_weights() {
    let mut rel = Relation::default();
    let w = rel.add_column("w", Kind::Weight, Width::signed(8), 1);
    assert_eq!(rel.validate(), Err(Invalid::Undisciplined(w)));
    rel.passport_weights = true;
    assert_eq!(rel.validate(), Ok(()));
    let g = Kind::Witness(rel.add_group("G/x/1", 1));
    let x = rel.add_column("x", g, Width::signed(8), 1);
    assert_eq!(rel.validate(), Err(Invalid::Undisciplined(x)));
    range(&mut rel, x, Width::signed(8));
    assert_eq!(rel.validate(), Ok(()));
    rel.passport_weights = false;
    assert_eq!(rel.validate(), Err(Invalid::Undisciplined(w)));
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
fn accepts_values_joined_from_disjoint_parts_and_rejects_an_overlap() {
    let (rel, whole, lo, wide) = composed();
    let hi = ColumnId(lo.0 + 1);
    let part = |ids: &[ColumnId]| {
        let mut values = Values::new(&rel);
        for &id in ids {
            let column = whole.get(&rel, id).expect("assigned").to_vec();
            values.set(&rel, id, column).expect("part");
        }
        values
    };
    // Joined in either order the parts are the whole assignment.
    for order in [[&[lo][..], &[hi, wide][..]], [&[hi, wide][..], &[lo][..]]] {
        let mut joined = Values::default();
        for ids in order {
            joined.absorb(part(ids)).expect("disjoint");
        }
        assert_eq!(joined, whole);
        assert_eq!(check(&rel, &joined), Ok(()));
    }
    // Parts that start as clones of the same past share its columns and still join.
    let past = part(&[lo]);
    let (mut a, mut b) = (past.clone(), past.clone());
    a.set(&rel, hi, whole.get(&rel, hi).expect("hi").to_vec())
        .expect("a");
    b.set(&rel, wide, whole.get(&rel, wide).expect("wide").to_vec())
        .expect("b");
    let mut joined = past;
    joined.absorb(a).expect("shared past");
    joined.absorb(b).expect("shared past");
    assert_eq!(joined, whole);
    // A column assigned in two parts is refused, even with equal entries, and the first
    // value stays.
    for entries in [vec![0, 0], whole.get(&rel, hi).expect("hi").to_vec()] {
        let mut joined = part(&[lo, hi]);
        let mut other = part(&[wide]);
        other.set(&rel, hi, entries).expect("overlap");
        assert_eq!(joined.absorb(other), Err(Invalid::Column(hi)));
        assert_eq!(joined.get(&rel, hi), whole.get(&rel, hi));
    }
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

/// The fixture's `xw` split once into row blocks of W (RFC-0026 A6), with `y` disciplined
/// by the blocks alone (2 * 8 * 128 fits its signed 13).
fn split() -> Fixture {
    let mut f = fixture();
    let xw = f.relation.matmuls.remove(0);
    f.relation.add_matmul_within(xw, 2);
    let y = f.y;
    f.relation.ranges.retain(|range| range.column != y);
    f
}

#[test]
fn accepts_matmul_split_into_row_blocks() {
    let f = split();
    let blocks = &f.relation.matmuls;
    let y = f.y;
    assert_eq!(blocks.len(), 2);
    for (k, (block, fixed)) in blocks.iter().zip([Ref::FIXED_0, Ref::FIXED_1]).enumerate() {
        assert_eq!(block.name, alloc::format!("xw/block{k}"));
        assert_eq!((block.free, block.summed), (1, 1));
        // The split bit is j (bit 0), the free bit W reads; i and k move down.
        assert_eq!(block.out.vars, [fixed, 0]);
        assert_eq!(block.lhs.vars, [1, 0]);
        assert_eq!(block.rhs.vars, [fixed, 1]);
    }
    assert_eq!(check(&f.relation, &f.values), Ok(()));
    // A domain that fits is pushed unchanged.
    let mut fits = fixture();
    let xw = fits.relation.matmuls.remove(0);
    fits.relation.add_matmul(xw.clone());
    assert_eq!(fits.relation.matmuls, [xw]);
    // y[1][1] is block 1 (j = 1) alone; z follows it (z = y * s with s = 2).
    let mut f = split();
    let z = f.z;
    tamper(&mut f, y, 3, 1);
    tamper(&mut f, z, 3, 2);
    assert!(
        matches!(check(&f.relation, &f.values), Err(Violation::Matmul { relation, .. }) if relation == "xw/block1")
    );
    assert_eq!(check_except(&f.relation, &f.values, &["xw/block1"]), Ok(()));
}

#[test]
fn rejects_out_covered_by_one_row_block() {
    // Without block 1 the column j = 1 of y has no discipline.
    let mut f = split();
    f.relation.matmuls.truncate(1);
    assert_eq!(f.relation.validate(), Err(Invalid::Undisciplined(f.y)));
    // Two copies of block 0 still leave that column uncovered.
    let mut f = split();
    f.relation.matmuls[1] = f.relation.matmuls[0].clone();
    assert_eq!(f.relation.validate(), Err(Invalid::Undisciplined(f.y)));
}

#[test]
fn rejects_fixed_bits_outside_matmuls() {
    let mut f = fixture();
    f.relation.identities[0].terms[0].factors[0].vars = vec![0, Ref::FIXED_1];
    assert!(matches!(f.relation.validate(), Err(Invalid::Ref { .. })));
    // A sentinel that is neither fixed value is out of every domain.
    let mut f = split();
    f.relation.matmuls[0].out.vars = vec![0, 0xFD];
    assert!(matches!(f.relation.validate(), Err(Invalid::Ref { .. })));
}

/// #379 review: a tamper at the last domain point is found (identity and lookup), so a
/// gather that skipped the last row would fail here.
#[test]
fn rejects_tamper_at_the_last_point() {
    let mut f = fixture();
    let a = f.a;
    tamper(&mut f, a, 3, 1);
    assert_eq!(
        check(&f.relation, &f.values),
        Err(Violation::Identity {
            relation: "product".to_string(),
            point: 3
        })
    );
    let mut f = fixture();
    let square = f.square;
    tamper(&mut f, square, 3, 1);
    assert_eq!(
        check(&f.relation, &f.values),
        Err(Violation::Lookup {
            relation: "squares".to_string(),
            point: 3
        })
    );
}

/// The matmul's per-entry path (no summed-index table) gives the same results as the
/// table path: accept the honest fixture, and report the same tampered point.
#[test]
fn matmul_without_the_summed_table_matches() {
    let f = fixture();
    assert_eq!(check::check_with(&f.relation, &f.values, &[], 0), Ok(()));
    let mut f = fixture();
    let (y, z) = (f.y, f.z);
    tamper(&mut f, y, 3, 1);
    tamper(&mut f, z, 3, 2);
    let expected = Err(Violation::Matmul {
        relation: "xw".to_string(),
        point: 3,
    });
    assert_eq!(check::check_with(&f.relation, &f.values, &[], 0), expected);
    assert_eq!(check(&f.relation, &f.values), expected);
}

fn segmented_fixture() -> (Relation, ColumnId, ColumnId, ColumnId) {
    let mut rel = Relation::default();
    let g0 = Kind::Witness(rel.add_group_in("L0/main/2", 2, 0));
    let g1 = Kind::Witness(rel.add_group_in("L1/main/2", 2, 1));
    let s0_private = rel.add_column("s0_priv", g0.clone(), Width::signed(8), 2);
    let s0_carried = rel.add_column("s0_out", g0, Width::signed(8), 2);
    rel.mark_carried(s0_carried);
    let s1_out = rel.add_column("s1_out", g1, Width::signed(8), 2);
    range(&mut rel, s0_private, Width::signed(8));
    range(&mut rel, s0_carried, Width::signed(8));
    range(&mut rel, s1_out, Width::signed(8));
    rel.identities.push(Identity {
        name: "s0_step".to_string(),
        vars: 2,
        terms: vec![
            Term {
                coeff: 1,
                factors: vec![r(s0_carried, &[0, 1])],
            },
            Term {
                coeff: -1,
                factors: vec![r(s0_private, &[0, 1])],
            },
            Term {
                coeff: -1,
                factors: vec![],
            },
        ],
    });
    rel.identities.push(Identity {
        name: "s1_step".to_string(),
        vars: 2,
        terms: vec![
            Term {
                coeff: 1,
                factors: vec![r(s1_out, &[0, 1])],
            },
            Term {
                coeff: -1,
                factors: vec![r(s0_carried, &[0, 1])],
            },
            Term {
                coeff: -2,
                factors: vec![],
            },
        ],
    });
    (rel, s0_private, s0_carried, s1_out)
}

#[test]
fn accepts_segmented_relation_and_per_segment_plain_check() {
    let (rel, s0_priv, s0_out, s1_out) = segmented_fixture();
    assert!(rel.is_segmented());
    assert_eq!(rel.segments(), 2);
    assert_eq!(rel.validate(), Ok(()));

    let mut v0 = Values::new(&rel);
    v0.set(&rel, s0_priv, vec![1, 2, 3, 4]).expect("s0_priv");
    v0.set(&rel, s0_out, vec![2, 3, 4, 5]).expect("s0_out");
    // Segment 0 check succeeds without segment 1 columns assigned.
    assert_eq!(check_segment(&rel, 0, &v0), Ok(()));

    let mut v1 = Values::new(&rel);
    v1.set(&rel, s0_out, vec![2, 3, 4, 5]).expect("carried");
    v1.set(&rel, s1_out, vec![4, 5, 6, 7]).expect("s1_out");
    // Segment 1 check succeeds without segment 0's non-carried column assigned.
    assert_eq!(check_segment(&rel, 1, &v1), Ok(()));

    // Tampering segment 1 fails check_segment(1) with exact Violation.
    v1.set(&rel, s1_out, vec![4, 5, 99, 7]).expect("tamper");
    assert_eq!(
        check_segment(&rel, 1, &v1),
        Err(Violation::Identity {
            relation: "s1_step".to_string(),
            point: 2
        })
    );
}

#[test]
fn rejects_segment_boundary_and_carried_violations() {
    // 1. Reading a non-carried column of segment 0 from segment 1 rejects (NC-1335 rule).
    let (mut rel, s0_priv, s0_out, s1_out) = segmented_fixture();
    rel.identities[1].terms[1].factors[0] = r(s0_priv, &[0, 1]);
    assert_eq!(
        rel.validate(),
        Err(Invalid::Segment {
            relation: "s1_step".to_string()
        })
    );

    // 2. Removing the carried flag on s0_out rejects.
    let (mut rel, _, _, _) = segmented_fixture();
    rel.columns[s0_out.0 as usize].carried = false;
    assert_eq!(
        rel.validate(),
        Err(Invalid::Segment {
            relation: "s1_step".to_string()
        })
    );

    // 3. Reading a carried column from two segments back (seg 0 from seg 2) rejects.
    let (mut rel, _, s0_out, _) = segmented_fixture();
    let g2 = Kind::Witness(rel.add_group_in("L2/main/2", 2, 2));
    let s2_out = rel.add_column("s2_out", g2, Width::signed(8), 2);
    range(&mut rel, s2_out, Width::signed(8));
    rel.identities.push(Identity {
        name: "s2_skip".to_string(),
        vars: 2,
        terms: vec![
            Term {
                coeff: 1,
                factors: vec![r(s2_out, &[0, 1])],
            },
            Term {
                coeff: -1,
                factors: vec![r(s0_out, &[0, 1])],
            },
        ],
    });
    assert_eq!(
        rel.validate(),
        Err(Invalid::Segment {
            relation: "s2_skip".to_string()
        })
    );

    // 4. Carried flag on non-witness column (Weight or Public) rejects.
    let (mut rel, _, _, _) = segmented_fixture();
    let w = rel.add_column("w", Kind::Weight, Width::signed(8), 2);
    range(&mut rel, w, Width::signed(8));
    rel.mark_carried(w);
    assert_eq!(
        rel.validate(),
        Err(Invalid::Segment {
            relation: "w".to_string()
        })
    );
    let (mut rel, _, _, _) = segmented_fixture();
    let p = rel.add_column("p", Kind::Public(vec![0; 4]), Width::signed(8), 2);
    rel.mark_carried(p);
    assert_eq!(
        rel.validate(),
        Err(Invalid::Segment {
            relation: "p".to_string()
        })
    );

    // 5. Non-contiguous or decreasing group segments reject.
    let (mut rel, _, _, _) = segmented_fixture();
    rel.groups[0].segment = 1;
    assert_eq!(
        rel.validate(),
        Err(Invalid::Segment {
            relation: "L0/main/2".to_string()
        })
    );
    let (mut rel, _, _, _) = segmented_fixture();
    rel.groups[1].segment = 2;
    assert_eq!(
        rel.validate(),
        Err(Invalid::Segment {
            relation: "L1/main/2".to_string()
        })
    );
    let (mut rel, _, _, _) = segmented_fixture();
    let _g2 = rel.add_group_in("L2/back/2", 2, 0);
    assert_eq!(
        rel.validate(),
        Err(Invalid::Segment {
            relation: "L2/back/2".to_string()
        })
    );
    let _ = s1_out;
}

/// A computed column is held as `i32` entries when all fit and in the checked form
/// otherwise (RFC-0028 §2.1): both read back as the definition's values.
#[test]
fn matches_reference_virtual_values_in_the_narrow_and_the_checked_form() {
    let mut rel = Relation::default();
    let g = Kind::Witness(rel.add_group("G/form/2", 2));
    let acc = rel.add_column("acc", g.clone(), Width::signed(8), 2);
    let y = rel.add_column("y", g, Width::signed(4), 2);
    range(&mut rel, acc, Width::signed(8));
    range(&mut rel, y, Width::signed(4));
    let rem = rel.add_virtual(
        "rem",
        Def::Linear {
            constant: 0,
            terms: vec![(1, Ref::identity(acc, 2)), (-16, Ref::identity(y, 2))],
        },
        2,
    );
    let ys = vec![1, -1, 1, 0];
    for accs in [
        vec![19, -13, 31, 0],
        vec![1 << 40, -(1 << 33), i64::from(i32::MAX) + 17, 0],
    ] {
        let mut vals = Values::new(&rel);
        vals.set(&rel, acc, accs.clone()).expect("set");
        vals.set(&rel, y, ys.clone()).expect("set");
        let expected: Vec<i64> = accs.iter().zip(&ys).map(|(a, y)| a - 16 * y).collect();
        assert_eq!(eval_column(&rel, &vals, rem), Ok(expected));
    }
}

/// A column whose entries the caller holds is read from there: its operands need not be
/// assigned, a column defined from it follows the held entries, and with nothing held the
/// evaluation is the definition's (the plain checker's path, which never takes `given`).
#[test]
fn matches_reference_column_evaluation_with_held_entries() {
    let mut rel = Relation::default();
    let g = Kind::Witness(rel.add_group("G/held/2", 2));
    let acc = rel.add_column("acc", g.clone(), Width::signed(8), 2);
    let y = rel.add_column("y", g, Width::signed(4), 2);
    let rem = rel.add_virtual(
        "rem",
        Def::Linear {
            constant: 0,
            terms: vec![(1, Ref::identity(acc, 2)), (-16, Ref::identity(y, 2))],
        },
        2,
    );
    let twice = rel.add_virtual(
        "twice",
        Def::Linear {
            constant: 1,
            terms: vec![(2, Ref::identity(rem, 2))],
        },
        2,
    );
    let mut vals = Values::new(&rel);
    vals.set(&rel, acc, vec![19, -13, 31, 0]).expect("set");
    vals.set(&rel, y, vec![1, -1, 1, 0]).expect("set");
    let honest = eval_column(&rel, &vals, rem).expect("rem");
    assert_eq!(honest, vec![3, 3, 15, 0]);
    let reference = eval_column(&rel, &vals, twice).expect("twice");
    for target in [acc, rem, twice] {
        assert_eq!(
            eval_column_given(&rel, &vals, target, &[]),
            eval_column(&rel, &vals, target)
        );
    }
    // Held honest entries give the definition's values with no operand assigned.
    let empty = Values::new(&rel);
    assert_eq!(
        eval_column(&rel, &empty, twice),
        Err(Violation::Missing(acc))
    );
    assert_eq!(
        eval_column_given(&rel, &empty, twice, &[(rem, &honest)]),
        Ok(reference)
    );
    assert_eq!(
        eval_column_given(&rel, &empty, rem, &[(rem, &honest)]),
        Ok(honest.clone())
    );
    // The held entries are what is read, for a virtual and for a committed column.
    assert_eq!(
        eval_column_given(&rel, &vals, twice, &[(rem, &[0, 1, 2, 3])]),
        Ok(vec![1, 3, 5, 7])
    );
    assert_eq!(
        eval_column_given(&rel, &vals, rem, &[(y, &[0, 0, 0, 0])]),
        Ok(vec![19, -13, 31, 0])
    );
    // Held entries of another length are refused, as an operand and as the target.
    for target in [twice, rem] {
        assert_eq!(
            eval_column_given(&rel, &vals, target, &[(rem, &[0, 1])]),
            Err(Violation::Missing(rem))
        );
    }
}

/// RFC-0028 §2.1–2.2 (E18-01): honest relations for Linear, Pointwise and Contraction
/// virtual columns pass validation and plain checking without supplying virtual values,
/// ignore garbage values supplied for virtual columns, and reject one tamper per kind.
#[test]
fn accepts_virtual_defs_ignores_supplied_and_rejects_tampers() {
    // 1. Linear: rounding `acc = 16 * y + rem` where `rem = acc - 16 * y` is virtual and range-checked.
    let mut lin = Relation::default();
    let g = Kind::Witness(lin.add_group("G/lin/2", 2));
    let acc = lin.add_column("acc", g.clone(), Width::signed(8), 2);
    let y = lin.add_column("y", g, Width::signed(4), 2);
    range(&mut lin, acc, Width::signed(8));
    range(&mut lin, y, Width::signed(4));
    let rem = lin.add_virtual(
        "rem",
        Def::Linear {
            constant: 0,
            terms: vec![(1, Ref::identity(acc, 2)), (-16, Ref::identity(y, 2))],
        },
        2,
    );
    range(&mut lin, rem, Width::unsigned(4));
    let mut vals = Values::new(&lin);
    // acc = [19, -13, 31, 0], y = [1, -1, 1, 0] => rem = [3, 3, 15, 0] in [0, 16).
    vals.set(&lin, acc, vec![19, -13, 31, 0]).expect("set");
    vals.set(&lin, y, vec![1, -1, 1, 0]).expect("set");
    assert_eq!(check(&lin, &vals), Ok(()));
    // Supplying garbage values for the virtual column is completely ignored.
    let mut vals_garbage = vals.clone();
    vals_garbage
        .set(&lin, rem, vec![9999, -9999, 1234, 5678])
        .expect("set");
    assert_eq!(check(&lin, &vals_garbage), Ok(()));
    // Tampering `y[1]` by +1 makes true `rem[1] = -13` (out of unsigned(4)), rejected even
    // if honest `rem` values are supplied in `Values`.
    let mut vals_bad = vals.clone();
    vals_bad.set(&lin, y, vec![1, 0, 1, 0]).expect("set");
    vals_bad.set(&lin, rem, vec![3, 3, 15, 0]).expect("set");
    assert_eq!(
        check(&lin, &vals_bad),
        Err(Violation::Range {
            relation: "rem".to_string(),
            index: 1,
        })
    );

    // 2. Pointwise: sign-magnitude `mag = (1 - 2 * sigma) * x`, checked by a lookup table on virtual `mag`.
    let mut pw = Relation::default();
    let g = Kind::Witness(pw.add_group("G/pw/2", 2));
    let x = pw.add_column("x", g.clone(), Width::signed(4), 2);
    let sigma = pw.add_column("sigma", g, Width::unsigned(1), 2);
    range(&mut pw, x, Width::signed(4));
    range(&mut pw, sigma, Width::unsigned(1));
    let mag = pw.add_virtual(
        "mag",
        Def::Pointwise {
            terms: vec![
                Term {
                    coeff: 1,
                    factors: vec![Ref::identity(x, 2)],
                },
                Term {
                    coeff: -2,
                    factors: vec![Ref::identity(sigma, 2), Ref::identity(x, 2)],
                },
            ],
        },
        2,
    );
    let tbl = pw.add_table(Table {
        name: "nonneg4".into(),
        widths: vec![Width::unsigned(4)],
        rows: (0..=8).map(|v| vec![v]).collect(),
    });
    pw.lookups.push(Lookup {
        name: "mag_nonneg".into(),
        vars: 2,
        selector: None,
        tuple: vec![Ref::identity(mag, 2)],
        table: tbl,
    });
    let mut vals = Values::new(&pw);
    vals.set(&pw, x, vec![5, -7, 0, -8]).expect("set");
    vals.set(&pw, sigma, vec![0, 1, 0, 1]).expect("set");
    assert_eq!(check(&pw, &vals), Ok(()));
    let mut vals_garbage = vals.clone();
    vals_garbage
        .set(&pw, mag, vec![-1, -2, -3, -4])
        .expect("set");
    assert_eq!(check(&pw, &vals_garbage), Ok(()));
    // Tampering `sigma[1]` to 0 gives `mag[1] = -7`, rejected by the lookup on virtual `mag`.
    let mut vals_bad = vals.clone();
    vals_bad.set(&pw, sigma, vec![0, 0, 0, 1]).expect("set");
    vals_bad.set(&pw, mag, vec![5, 7, 0, 8]).expect("set");
    assert_eq!(
        check(&pw, &vals_bad),
        Err(Violation::Lookup {
            relation: "mag_nonneg".to_string(),
            point: 1,
        })
    );

    // 3. Contraction: 2x2 * 2x2 virtual matmul `c(i, j) = sum_k a(i, k) * b(j, k)` with no committed accumulator,
    //    checked against a committed `y` via an identity reading virtual `c`.
    let mut con = Relation::default();
    let g = Kind::Witness(con.add_group("G/con/2", 2));
    let a = con.add_column("a", g.clone(), Width::signed(4), 2);
    let b = con.add_column("b", Kind::Weight, Width::signed(4), 2);
    let y = con.add_column("y", g, Width::signed(8), 2);
    range(&mut con, a, Width::signed(4));
    range(&mut con, b, Width::signed(4));
    range(&mut con, y, Width::signed(8));
    // Domain bits: free bit 0 = j, free bit 1 = i, summed bit 2 = k.
    let c = con.add_virtual(
        "c",
        Def::Contraction {
            free: 2,
            summed: 1,
            lhs: Ref {
                column: a,
                vars: vec![2, 1],
            },
            rhs: Ref {
                column: b,
                vars: vec![2, 0],
            },
        },
        2,
    );
    con.identities.push(Identity {
        name: "y_eq_c".into(),
        vars: 2,
        terms: vec![
            Term {
                coeff: 1,
                factors: vec![Ref::identity(y, 2)],
            },
            Term {
                coeff: -1,
                factors: vec![Ref::identity(c, 2)],
            },
        ],
    });
    // a = [[2, -1], [3, 4]], b = [[1, 2], [-3, 1]]
    // c[0,0]=2*1+(-1)*2=0, c[0,1]=2*(-3)+(-1)*1=-7, c[1,0]=3*1+4*2=11, c[1,1]=3*(-3)+4*1=-5
    let mut vals = Values::new(&con);
    vals.set(&con, a, vec![2, -1, 3, 4]).expect("set");
    vals.set(&con, b, vec![1, 2, -3, 1]).expect("set");
    vals.set(&con, y, vec![0, -7, 11, -5]).expect("set");
    assert_eq!(check(&con, &vals), Ok(()));
    let mut vals_garbage = vals.clone();
    vals_garbage
        .set(&con, c, vec![100, 100, 100, 100])
        .expect("set");
    assert_eq!(check(&con, &vals_garbage), Ok(()));
    // Tampering `y[2]` by +1 rejects at point 2, even with forged `c`.
    let mut vals_bad = vals.clone();
    vals_bad.set(&con, y, vec![0, -7, 12, -5]).expect("set");
    vals_bad.set(&con, c, vec![0, -7, 12, -5]).expect("set");
    assert_eq!(
        check(&con, &vals_bad),
        Err(Violation::Identity {
            relation: "y_eq_c".to_string(),
            point: 2,
        })
    );
}

/// RFC-0028 §2.1 (E18-01): virtual column definitions may read only strictly smaller ColumnIds.
#[test]
fn rejects_virtual_forward_and_self_references() {
    // Forward reference in Linear.
    let mut rel = Relation::default();
    let g = Kind::Witness(rel.add_group("G/0/1", 1));
    let _v = rel.add_virtual(
        "fwd_lin",
        Def::Linear {
            constant: 0,
            terms: vec![(1, Ref::identity(ColumnId(1), 1))],
        },
        1,
    );
    let x = rel.add_column("x", g, Width::signed(4), 1);
    range(&mut rel, x, Width::signed(4));
    assert_eq!(
        rel.validate(),
        Err(Invalid::Ref {
            relation: "fwd_lin".to_string(),
        })
    );

    // Self reference in Pointwise.
    let mut rel = Relation::default();
    let _v = rel.add_virtual(
        "self_pw",
        Def::Pointwise {
            terms: vec![Term {
                coeff: 1,
                factors: vec![Ref::identity(ColumnId(0), 1)],
            }],
        },
        1,
    );
    assert_eq!(
        rel.validate(),
        Err(Invalid::Ref {
            relation: "self_pw".to_string(),
        })
    );

    // Forward reference in Contraction.
    let mut rel = Relation::default();
    let g = Kind::Witness(rel.add_group("G/0/1", 1));
    let a = rel.add_column("a", g.clone(), Width::signed(4), 1);
    range(&mut rel, a, Width::signed(4));
    let _v = rel.add_virtual(
        "fwd_con",
        Def::Contraction {
            free: 1,
            summed: 0,
            lhs: Ref::identity(a, 1),
            rhs: Ref::identity(ColumnId(2), 1),
        },
        1,
    );
    let b = rel.add_column("b", g, Width::signed(4), 1);
    range(&mut rel, b, Width::signed(4));
    assert_eq!(
        rel.validate(),
        Err(Invalid::Ref {
            relation: "fwd_con".to_string(),
        })
    );
}

/// RFC-0028 §2.2 (E18-01): derived magnitude must be strictly below `p / 2` (`<= HALF_MODULUS`).
/// Includes the NC-1340 field-inverse attack and exact boundary checks for all three Def kinds.
#[test]
fn rejects_virtual_over_wide_derived_magnitude() {
    // Exact boundary on Linear: HALF_MODULUS accepted, HALF_MODULUS + 1 rejected.
    let mut ok = Relation::default();
    let _c_ok = ok.add_virtual(
        "exact_half",
        Def::Linear {
            constant: HALF_MODULUS as i64,
            terms: vec![],
        },
        0,
    );
    assert_eq!(ok.validate(), Ok(()));

    let mut bad = Relation::default();
    let _c_bad = bad.add_virtual(
        "over_half",
        Def::Linear {
            constant: (HALF_MODULUS + 1) as i64,
            terms: vec![],
        },
        0,
    );
    assert_eq!(
        bad.validate(),
        Err(Invalid::Bound {
            relation: "over_half".to_string(),
            bound: HALF_MODULUS + 1,
        })
    );

    // NC-1340 pattern: declaring a rounding output as Linear with the field inverse of 2^1 (`2^30`).
    let mut inv = Relation::default();
    let g = Kind::Witness(inv.add_group("G/inv/1", 1));
    let acc = inv.add_column("acc", g.clone(), Width::signed(8), 1);
    let rem = inv.add_column("rem", g, Width::unsigned(1), 1);
    range(&mut inv, acc, Width::signed(8));
    range(&mut inv, rem, Width::unsigned(1));
    let inv2: i64 = 1 << 30;
    let _y = inv.add_virtual(
        "forged_round",
        Def::Linear {
            constant: 0,
            terms: vec![
                (inv2, Ref::identity(acc, 1)),
                (-inv2, Ref::identity(rem, 1)),
            ],
        },
        1,
    );
    assert!(matches!(
        inv.validate(),
        Err(Invalid::Bound { relation, .. }) if relation == "forged_round"
    ));

    // Over-wide Pointwise: signed(16) * signed(16) = 2^15 * 2^15 = 2^30 > HALF_MODULUS.
    let mut pw = Relation::default();
    let g = Kind::Witness(pw.add_group("G/pw/1", 1));
    let a = pw.add_column("a", g.clone(), Width::signed(16), 1);
    let b = pw.add_column("b", g, Width::signed(16), 1);
    range(&mut pw, a, Width::signed(16));
    range(&mut pw, b, Width::signed(16));
    let _p = pw.add_virtual(
        "wide_pw",
        Def::Pointwise {
            terms: vec![Term {
                coeff: 1,
                factors: vec![Ref::identity(a, 1), Ref::identity(b, 1)],
            }],
        },
        1,
    );
    assert_eq!(
        pw.validate(),
        Err(Invalid::Bound {
            relation: "wide_pw".to_string(),
            bound: 1u128 << 30,
        })
    );

    // Over-wide Contraction: 2^16 * signed(8) * signed(8) = 2^16 * 2^7 * 2^7 = 2^30 > HALF_MODULUS.
    let mut con = Relation::default();
    let g = Kind::Witness(con.add_group("G/con/16", 16));
    let a = con.add_column("a", g.clone(), Width::signed(8), 16);
    let b = con.add_column("b", g, Width::signed(8), 16);
    range(&mut con, a, Width::signed(8));
    range(&mut con, b, Width::signed(8));
    let _c = con.add_virtual(
        "wide_con",
        Def::Contraction {
            free: 0,
            summed: 16,
            lhs: Ref::identity(a, 16),
            rhs: Ref::identity(b, 16),
        },
        0,
    );
    assert_eq!(
        con.validate(),
        Err(Invalid::Bound {
            relation: "wide_con".to_string(),
            bound: 1u128 << 30,
        })
    );
}

/// RFC-0028 §2.2–2.3 (E18-01): committed columns cannot self-discipline through virtual wrappers,
/// and virtual columns obey segment boundary rules in both `validate` and `check_segment`.
#[test]
fn rejects_cyclic_discipline_and_enforces_virtual_segments() {
    // 1. Undisciplined witness cannot be disciplined via a virtual Linear copy in Compose.
    let mut cyc = Relation::default();
    let g = Kind::Witness(cyc.add_group("G/cyc/1", 1));
    let w = cyc.add_column("w", g, Width::signed(8), 1);
    let v = cyc.add_virtual(
        "v_copy",
        Def::Linear {
            constant: 0,
            terms: vec![(1, Ref::identity(w, 1))],
        },
        1,
    );
    cyc.composes.push(Compose {
        name: "self_disc".into(),
        column: w,
        limbs: vec![(v, 0)],
    });
    assert_eq!(cyc.validate(), Err(Invalid::Undisciplined(w)));

    // 2. Segmented virtual columns: segment 1 reads carried seg-0 witness + seg-1 witness,
    //    passes `check_segment(..., 1, ...)` without non-carried seg-0 columns assigned.
    let mut rel = Relation::default();
    let g0 = Kind::Witness(rel.add_group_in("L0/main/2", 2, 0));
    let g1 = Kind::Witness(rel.add_group_in("L1/main/2", 2, 1));
    let s0_priv = rel.add_column("s0_priv", g0.clone(), Width::signed(8), 2);
    let s0_carry = rel.add_column("s0_carry", g0, Width::signed(8), 2);
    rel.mark_carried(s0_carry);
    let s1_delta = rel.add_column("s1_delta", g1.clone(), Width::signed(8), 2);
    let s1_out = rel.add_column("s1_out", g1, Width::signed(9), 2);
    range(&mut rel, s0_priv, Width::signed(8));
    range(&mut rel, s0_carry, Width::signed(8));
    range(&mut rel, s1_delta, Width::signed(8));
    range(&mut rel, s1_out, Width::signed(9));
    let v_sum = rel.add_virtual(
        "v_sum",
        Def::Linear {
            constant: 0,
            terms: vec![
                (1, Ref::identity(s0_carry, 2)),
                (1, Ref::identity(s1_delta, 2)),
            ],
        },
        2,
    );
    assert_eq!(rel.column_segment(v_sum), Some(1));
    rel.identities.push(Identity {
        name: "s1_eq".into(),
        vars: 2,
        terms: vec![
            Term {
                coeff: 1,
                factors: vec![Ref::identity(s1_out, 2)],
            },
            Term {
                coeff: -1,
                factors: vec![Ref::identity(v_sum, 2)],
            },
        ],
    });
    assert_eq!(rel.validate(), Ok(()));
    let mut vals_s1 = Values::new(&rel);
    vals_s1
        .set(&rel, s0_carry, vec![10, -5, 3, 7])
        .expect("set");
    vals_s1.set(&rel, s1_delta, vec![1, 2, -3, 4]).expect("set");
    vals_s1.set(&rel, s1_out, vec![11, -3, 0, 11]).expect("set");
    // Notice `s0_priv` is NOT assigned, yet `check_segment` for segment 1 passes.
    assert_eq!(check_segment(&rel, 1, &vals_s1), Ok(()));

    // 3. Virtual in segment 1 reading non-carried witness of segment 0 rejects with Invalid::Segment.
    let mut bad_noncarry = rel.clone();
    bad_noncarry.columns[s0_carry.0 as usize].carried = false;
    assert_eq!(
        bad_noncarry.validate(),
        Err(Invalid::Segment {
            relation: "v_sum".to_string(),
        })
    );

    // 4. Virtual column of segment 0 cannot be read from segment 1 (virtual columns cannot be carried).
    let mut bad_vcarry = Relation::default();
    let g0 = Kind::Witness(bad_vcarry.add_group_in("L0/m/2", 2, 0));
    let g1 = Kind::Witness(bad_vcarry.add_group_in("L1/m/2", 2, 1));
    let a0 = bad_vcarry.add_column("a0", g0, Width::signed(8), 2);
    let a1 = bad_vcarry.add_column("a1", g1, Width::signed(8), 2);
    range(&mut bad_vcarry, a0, Width::signed(8));
    range(&mut bad_vcarry, a1, Width::signed(8));
    let v0 = bad_vcarry.add_virtual(
        "v0",
        Def::Linear {
            constant: 0,
            terms: vec![(1, Ref::identity(a0, 2))],
        },
        2,
    );
    bad_vcarry.identities.push(Identity {
        name: "cross_v".into(),
        vars: 2,
        terms: vec![
            Term {
                coeff: 1,
                factors: vec![Ref::identity(a1, 2)],
            },
            Term {
                coeff: -1,
                factors: vec![Ref::identity(v0, 2)],
            },
        ],
    });
    assert_eq!(
        bad_vcarry.validate(),
        Err(Invalid::Segment {
            relation: "cross_v".to_string(),
        })
    );

    // 5. Weight-only virtual with explicit segment assigns weight range to that segment and rejects out-of-range segment.
    let mut wrel = Relation::default();
    let _g0 = wrel.add_group_in("L0/w/2", 2, 0);
    let _g1 = wrel.add_group_in("L1/w/2", 2, 1);
    let wt = wrel.add_column("wt", Kind::Weight, Width::signed(8), 2);
    range(&mut wrel, wt, Width::signed(8));
    let vw = wrel.add_virtual_in(
        "vw",
        Def::Linear {
            constant: 0,
            terms: vec![(1, Ref::identity(wt, 2))],
        },
        2,
        1,
    );
    assert_eq!(wrel.column_segment(vw), Some(1));
    assert_eq!(wrel.range_segment(&wrel.ranges[0]), 1);
    assert_eq!(wrel.validate(), Ok(()));
    wrel.columns[vw.0 as usize].segment = Some(2);
    assert_eq!(
        wrel.validate(),
        Err(Invalid::Segment {
            relation: "vw".to_string(),
        })
    );
    // Non-zero width or `carried = true` on a virtual column rejects.
    let mut bad_meta = wrel.clone();
    bad_meta.columns[vw.0 as usize].segment = Some(1);
    bad_meta.columns[vw.0 as usize].width = Width::signed(8);
    assert_eq!(bad_meta.validate(), Err(Invalid::Column(vw)));
    let mut bad_carry = wrel.clone();
    bad_carry.columns[vw.0 as usize].segment = Some(1);
    bad_carry.columns[vw.0 as usize].carried = true;
    assert_eq!(
        bad_carry.validate(),
        Err(Invalid::Segment {
            relation: "vw".to_string(),
        })
    );

    // 6. Explicit segment on an operand-bearing virtual column rejects (RFC-0028 §2.3, F4).
    let mut bad_explicit = rel.clone();
    bad_explicit.columns[v_sum.0 as usize].segment = Some(1);
    assert_eq!(
        bad_explicit.validate(),
        Err(Invalid::Segment {
            relation: "v_sum".to_string(),
        })
    );
}

/// Regression tests for E18-01 soundness audit findings F1, F2, and F5:
/// - F1: depth-64 diamond virtual DAG validates in O(N + E) without exponential blowup.
/// - F2: overflowing virtual limb shift in `Compose` under `check_segment` rejects (no wrap).
/// - F5: `i64::MIN` constant/coeff rejects with `Invalid::Bound` without panic; split
///   `Def::Contraction` (`free + summed > MAX_VARS`) validates; `check_with(..., summed_table = 0)`
///   matches the precomputed path on `Def::Contraction`.
#[test]
fn rejects_audit_edge_cases_and_validates_diamond_and_split_contraction() {
    // F1: depth-64 diamond virtual DAG (`v_k = v_{k-1} + v_{k-1}`? keep mag bounded with `+1 - 1` or `1*x` + `0`?
    // Wait: to keep derived magnitude <= HALF_MODULUS at depth 64, build `v_k = Pointwise(v_{k-1} * v_{k-1})`
    // over a 1-bit `{0, 1}` witness `x`: `mag(x) = 1`, so `mag(v_k) = 1 * 1 = 1` at every depth 0..64,
    // while each node reads `v_{k-1}` twice -> 2^64 recursive paths if unmemoized!).
    let mut diamond = Relation::default();
    let g = Kind::Witness(diamond.add_group("G/dia/1", 1));
    let mut prev = diamond.add_column("x", g, Width::unsigned(1), 1);
    range(&mut diamond, prev, Width::unsigned(1));
    for depth in 0..64u32 {
        prev = diamond.add_virtual(
            &format!("d_{depth}"),
            Def::Pointwise {
                terms: vec![Term {
                    coeff: 1,
                    factors: vec![Ref::identity(prev, 1), Ref::identity(prev, 1)],
                }],
            },
            1,
        );
    }
    assert_eq!(diamond.validate(), Ok(()));
    assert_eq!(diamond.column_segment(prev), Some(0));
    let mut vals = Values::new(&diamond);
    vals.set(&diamond, ColumnId(0), vec![0, 1]).expect("set");
    assert_eq!(check(&diamond, &vals), Ok(()));

    // F2: overflowing virtual `i128` limb shifted in `Compose` under `check_segment` must reject.
    let mut ovf = Relation::default();
    let g0 = Kind::Witness(ovf.add_group_in("L0/ovf/1", 1, 0));
    let g1 = Kind::Witness(ovf.add_group_in("L1/ovf/1", 1, 1));
    let x = ovf.add_column("x", g0, Width::signed(4), 1);
    ovf.mark_carried(x);
    let target = ovf.add_column("target", g1, Width::signed(24), 1);
    range(&mut ovf, x, Width::signed(4));
    range(&mut ovf, target, Width::signed(16));
    let v_cube = ovf.add_virtual(
        "v_cube",
        Def::Pointwise {
            terms: vec![Term {
                coeff: 1,
                factors: vec![
                    Ref::identity(x, 1),
                    Ref::identity(x, 1),
                    Ref::identity(x, 1),
                ],
            }],
        },
        1,
    );
    // `v_cube` belongs to segment 0 (`x`), so bring it into segment 1 via a seg-1 zero term.
    let z1 = ovf.add_column("z1", Kind::Witness(GroupId(1)), Width::unsigned(1), 1);
    range(&mut ovf, z1, Width::unsigned(1));
    let v_s1 = ovf.add_virtual(
        "v_s1",
        Def::Pointwise {
            terms: vec![
                Term {
                    coeff: 1,
                    factors: vec![
                        Ref::identity(x, 1),
                        Ref::identity(x, 1),
                        Ref::identity(x, 1),
                    ],
                },
                Term {
                    coeff: 1,
                    factors: vec![Ref::identity(z1, 1)],
                },
            ],
        },
        1,
    );
    let _ = v_cube;
    ovf.composes.push(Compose {
        name: "ovf_comp".into(),
        column: target,
        limbs: vec![(v_s1, 8)],
    });
    assert_eq!(ovf.validate(), Ok(()));
    // Supply a tampered carried `x = 1 << 40` (not range-checked in segment 1):
    // `v_s1 = (1 << 40)^3 = 1i128 << 120`, and `(1i128 << 120) * (1 << 8)` overflows `i128`
    // (whereas `checked_shl(8)` would have silently wrapped to `0 == target[0]`).
    let mut vals_ovf = Values::new(&ovf);
    vals_ovf.set(&ovf, x, vec![1i64 << 40, 0]).expect("set");
    vals_ovf.set(&ovf, z1, vec![0, 0]).expect("set");
    vals_ovf.set(&ovf, target, vec![0, 0]).expect("set");
    assert_eq!(
        check_segment(&ovf, 1, &vals_ovf),
        Err(Violation::Compose {
            relation: "ovf_comp".to_string(),
            index: 0,
        })
    );

    // F5a: `i64::MIN` constant and coeff reject with `Invalid::Bound` without panic.
    let mut min_lin = Relation::default();
    let _c = min_lin.add_virtual(
        "min_const",
        Def::Linear {
            constant: i64::MIN,
            terms: vec![],
        },
        0,
    );
    assert_eq!(
        min_lin.validate(),
        Err(Invalid::Bound {
            relation: "min_const".to_string(),
            bound: i64::MIN.unsigned_abs() as u128,
        })
    );
    let mut min_pw = Relation::default();
    let gp = Kind::Witness(min_pw.add_group("G/min/1", 1));
    let a = min_pw.add_column("a", gp, Width::unsigned(1), 1);
    range(&mut min_pw, a, Width::unsigned(1));
    let _p = min_pw.add_virtual(
        "min_coeff",
        Def::Pointwise {
            terms: vec![Term {
                coeff: i64::MIN,
                factors: vec![Ref::identity(a, 1)],
            }],
        },
        1,
    );
    assert_eq!(
        min_pw.validate(),
        Err(Invalid::Bound {
            relation: "min_coeff".to_string(),
            bound: i64::MIN.unsigned_abs() as u128,
        })
    );

    // F5b: split `Def::Contraction` (`free = 20, summed = 15`, domain = 35 > MAX_VARS = 30)
    // validates cleanly when derived magnitude `2^15 * 2^7 * 2^7 = 2^29 <= HALF_MODULUS`.
    let mut split = Relation::default();
    let gs = Kind::Witness(split.add_group("G/split/20", 20));
    let lhs = split.add_column("lhs", gs, Width::signed(8), 20);
    let rhs = split.add_column("rhs", Kind::Weight, Width::signed(8), 25);
    range(&mut split, lhs, Width::signed(8));
    range(&mut split, rhs, Width::signed(8));
    // free bits 0..20 (say 5 batch bits 0..5 + 15 output-row bits 5..20), summed bits 20..35.
    let mut lhs_vars: Vec<u8> = (20..35).collect();
    lhs_vars.extend(0..5);
    let mut rhs_vars: Vec<u8> = (20..35).collect();
    rhs_vars.extend(5..15);
    let _out = split.add_virtual(
        "split_con",
        Def::Contraction {
            free: 20,
            summed: 15,
            lhs: Ref {
                column: lhs,
                vars: lhs_vars,
            },
            rhs: Ref {
                column: rhs,
                vars: rhs_vars,
            },
        },
        20,
    );
    assert_eq!(split.validate(), Ok(()));

    // F5b: `check_with(..., summed_table = 0)` on a `Def::Contraction` matches the precomputed path.
    let mut small = Relation::default();
    let g = Kind::Witness(small.add_group("G/sm/2", 2));
    let a = small.add_column("a", g.clone(), Width::signed(4), 2);
    let b = small.add_column("b", Kind::Weight, Width::signed(4), 2);
    let y = small.add_column("y", g, Width::signed(8), 2);
    range(&mut small, a, Width::signed(4));
    range(&mut small, b, Width::signed(4));
    range(&mut small, y, Width::signed(8));
    let c = small.add_virtual(
        "c",
        Def::Contraction {
            free: 2,
            summed: 1,
            lhs: Ref {
                column: a,
                vars: vec![2, 1],
            },
            rhs: Ref {
                column: b,
                vars: vec![2, 0],
            },
        },
        2,
    );
    small.identities.push(Identity {
        name: "eq".into(),
        vars: 2,
        terms: vec![
            Term {
                coeff: 1,
                factors: vec![Ref::identity(y, 2)],
            },
            Term {
                coeff: -1,
                factors: vec![Ref::identity(c, 2)],
            },
        ],
    });
    let mut vals = Values::new(&small);
    vals.set(&small, a, vec![2, -1, 3, 4]).expect("set");
    vals.set(&small, b, vec![1, 2, -3, 1]).expect("set");
    vals.set(&small, y, vec![0, -7, 11, -5]).expect("set");
    assert_eq!(super::check::check_with(&small, &vals, &[], 0), Ok(()));
    vals.set(&small, y, vec![0, -7, 12, -5]).expect("set");
    assert_eq!(
        super::check::check_with(&small, &vals, &[], 0),
        Err(Violation::Identity {
            relation: "eq".to_string(),
            point: 2,
        })
    );
}

#[test]
fn accepts_range_tightened_virtual_downstream_magnitude() {
    // RFC-0028 A1: `v_lo = a - 65536 * hi` has raw magnitude `2^27 + 2^27 = 2^28 <= HALF_MODULUS`.
    // Adding `Range(v_lo, u16)` tightens its downstream magnitude to `65535`, allowing `v_lo * m`
    // (`65535 * 255 = 16,711,425 <= HALF_MODULUS`), which would fail at the raw bound (`2^28 * 255`).
    let mut r = Relation::default();
    let g = r.add_group("g", 1);
    let a = r.add_column("a", Kind::Witness(g), Width::unsigned(16), 1);
    let b = r.add_column("b", Kind::Witness(g), Width::unsigned(12), 1);
    let hi = r.add_column("hi", Kind::Witness(g), Width::unsigned(12), 1);
    let m = r.add_column("m", Kind::Public(vec![255, 255]), Width::unsigned(8), 1);
    range(&mut r, a, Width::unsigned(16));
    range(&mut r, b, Width::unsigned(12));
    range(&mut r, hi, Width::unsigned(12));
    // `wide = a + 4096 * b` has raw magnitude `65535 + 4096 * 4095 = 16,838,655`.
    let wide = r.add_virtual(
        "wide",
        Def::Linear {
            constant: 0,
            terms: vec![(1, Ref::identity(a, 1)), (4096, Ref::identity(b, 1))],
        },
        1,
    );
    // `v_lo = wide - 65536 * hi`: raw magnitude `16,838,655 + 65536 * 4095 = 285,208,575 <= HALF_MODULUS`.
    let v_lo = r.add_virtual(
        "v_lo",
        Def::Linear {
            constant: 0,
            terms: vec![(1, Ref::identity(wide, 1)), (-65536, Ref::identity(hi, 1))],
        },
        1,
    );
    // Without Range(u16), `v_lo * m` has bound `285,208,575 * 255 > HALF_MODULUS` -> Invalid::Bound.
    let mut without_range = r.clone();
    without_range.add_virtual(
        "prod",
        Def::Pointwise {
            terms: vec![Term {
                coeff: 1,
                factors: vec![Ref::identity(v_lo, 1), Ref::identity(m, 1)],
            }],
        },
        1,
    );
    assert!(matches!(
        without_range.validate(),
        Err(Invalid::Bound { .. })
    ));

    // With Range(v_lo, u16), downstream magnitude tightens to `65535` -> `prod` validates.
    range(&mut r, v_lo, Width::unsigned(16));
    let prod = r.add_virtual(
        "prod",
        Def::Pointwise {
            terms: vec![Term {
                coeff: 1,
                factors: vec![Ref::identity(v_lo, 1), Ref::identity(m, 1)],
            }],
        },
        1,
    );
    assert_eq!(r.validate(), Ok(()));
    assert_eq!(r.column_magnitude(v_lo), Some(65535));
    assert_eq!(r.column_magnitude(prod), Some(65535 * 255));
}

#[test]
fn rejects_over_wide_virtual_even_with_narrow_range() {
    // RFC-0028 A1 + NC-1340: if the defining formula itself exceeds `HALF_MODULUS`, a narrow
    // `Range` on the virtual column MUST NOT bypass the wrap-free bound check.
    let mut r = Relation::default();
    let g = r.add_group("g", 1);
    let x = r.add_column("x", Kind::Witness(g), Width::unsigned(16), 1);
    range(&mut r, x, Width::unsigned(16));
    let bad = r.add_virtual(
        "bad",
        Def::Linear {
            constant: 0,
            terms: vec![(1 << 16, Ref::identity(x, 1))],
        },
        1,
    );
    range(&mut r, bad, Width::unsigned(8));
    assert!(matches!(r.validate(), Err(Invalid::Bound { .. })));
}

/// Every honest column (`MAX_WIDTH_BITS = 30`) is stored at its declared native width
/// (1, 2 or 4 bytes per element); an out-of-range test value falls back without truncation.
#[test]
fn accepts_width_typed_values_storage() {
    let mut rel = Relation::default();
    let g = rel.add_group("L0/g/2", 2);
    let cases = [
        ("s8", Width::signed(8), vec![-128, -1, 0, 127], 1usize),
        ("u8", Width::unsigned(8), vec![0, 1, 128, 255], 1),
        ("s16", Width::signed(16), vec![-32768, -129, 128, 32767], 2),
        ("u16", Width::unsigned(16), vec![0, 256, 32768, 65535], 2),
        (
            "s24",
            Width::signed(24),
            vec![-(1 << 23), -32769, 32768, (1 << 23) - 1],
            4,
        ),
        (
            "u30",
            Width::unsigned(30),
            vec![0, 65536, 1 << 29, (1 << 30) - 1],
            4,
        ),
    ];
    let mut ids = Vec::new();
    for (name, width, _, _) in &cases {
        ids.push(rel.add_column(name, Kind::Witness(g), *width, 2));
    }
    let mut values = Values::new(&rel);
    let mut expected_bytes = 0usize;
    for (&id, (_, _, data, elem_bytes)) in ids.iter().zip(&cases) {
        values.set(&rel, id, data.clone()).expect("set");
        let slice = values.get(&rel, id).expect("get");
        assert_eq!(slice.elem_bytes(), *elem_bytes);
        assert_eq!(slice.byte_len(), 4 * *elem_bytes);
        assert_eq!(slice.to_vec(), *data);
        for (i, &v) in data.iter().enumerate() {
            assert_eq!(slice.at(i), v);
        }
        expected_bytes += 4 * *elem_bytes;
    }
    assert_eq!(values.storage_bytes(), expected_bytes);
    // Out-of-range test value retains exact integer without truncation.
    values
        .set(&rel, ids[0], vec![-128, 0, 127, 200])
        .expect("out-of-range fallback");
    let slice = values.get(&rel, ids[0]).expect("fallback get");
    assert_eq!(slice.at(3), 200);
    assert_eq!(slice.elem_bytes(), 8);
}

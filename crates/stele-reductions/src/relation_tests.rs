//! Malicious-prover controls for the A5 checks the verifier repeats (RFC-0008 A5 §5).
use super::*;
use alloc::string::ToString;
use stele_ir::relation::{Lookup, Range, Table, Width};

const PUBLIC: &[u8] = b"stele/test/relation-engine";

/// x, sq looked up in a squares table; x[0] = 7 with sq[0] = 50, which no row has.
fn squares() -> (Relation, Values) {
    let mut rel = Relation::default();
    let g = Kind::Witness(rel.add_group("G/squares/2", 2));
    let x = rel.add_column("x", g.clone(), Width::signed(4), 2);
    let sq = rel.add_column("sq", g, Width::unsigned(7), 2);
    let table = rel.add_table(Table {
        name: "squares".to_string(),
        widths: vec![Width::signed(4), Width::unsigned(7)],
        rows: (-8..8).map(|v| vec![v, v * v]).collect(),
    });
    rel.lookups.push(Lookup {
        name: "squares".to_string(),
        vars: 2,
        selector: None,
        tuple: vec![Ref::identity(x, 2), Ref::identity(sq, 2)],
        table,
    });
    rel.ranges.push(Range {
        name: "sq".to_string(),
        column: sq,
        width: Width::unsigned(7),
    });
    let mut values = Values::new(&rel);
    values.set(&rel, x, vec![7, -2, 3, 0]).expect("x");
    values.set(&rel, sq, vec![49, 4, 9, 0]).expect("sq");
    (rel, values)
}

fn attempt(rel: &Relation, values: &Values, plan: &Plan) -> Result<Ledger, Error> {
    let mut t = Transcript::new(PUBLIC).expect("transcript");
    let proof = prove_plan(&mut t, rel, plan, values, values, None)?;
    let mut t = Transcript::new(PUBLIC).expect("transcript");
    verify(&mut t, rel, None, &proof)
}

#[test]
fn accepts_honest_squares() {
    let (rel, values) = squares();
    assert!(attempt(&rel, &values, &plan(&rel).expect("plan")).is_ok());
}

#[test]
fn rejects_prover_table_differing_from_the_relation() {
    // The prover runs A5 against a table whose row 7 reads (7, 50); the roots then
    // balance and only the verifier's own table evaluation rejects.
    let (rel, mut values) = squares();
    values
        .set(&rel, ColumnId(1), vec![50, 4, 9, 0])
        .expect("sq");
    let mut forged = plan(&rel).expect("plan");
    forged.checks[0].entries[2 * 15 + 1] = 50;
    assert_eq!(
        attempt(&rel, &values, &forged).err(),
        Some(Error::Lookup(
            crate::lookup::Error::TableDenominatorMismatch
        ))
    );
}

#[test]
fn rejects_committed_multiplicities_differing_from_the_tree() {
    let (rel, values) = squares();
    let mut forged = plan(&rel).expect("plan");
    forged.checks[0].skew = 1;
    assert_eq!(
        attempt(&rel, &values, &forged).err(),
        Some(Error::Lookup(crate::lookup::Error::PieceSumMismatch))
    );
}

// Lying prover: commit `committed` (step 2), prove every later message from `values`
// (the true witness). Only the openings can tie claims to the commitment.
fn lie(rel: &Relation, committed: &Values, values: &Values) -> Result<Ledger, Error> {
    let plan = plan(rel).expect("plan");
    let mut t = Transcript::new(PUBLIC).expect("transcript");
    let proof = prove_plan(&mut t, rel, &plan, committed, values, None)
        .expect("a lying prover still produces bytes");
    let mut t = Transcript::new(PUBLIC).expect("transcript");
    verify(&mut t, rel, None, &proof)
}
const VALUE: Option<Error> = Some(Error::Pcs(stele_pcs::Error::ValueMismatch));

/// v = lo + 2^12·hi is bound only by its Compose identity, y = Σ_k x² only as a
/// matmul out (disciplined by its worst case, no range).
fn composed() -> (Relation, Values) {
    let mut rel = Relation::default();
    let g = Kind::Witness(rel.add_group("G/compose/2", 2));
    let g1 = Kind::Witness(rel.add_group("G/compose/1", 1));
    let lo = rel.add_column("lo", g.clone(), Width::unsigned(12), 2);
    let hi = rel.add_column("hi", g.clone(), Width::signed(12), 2);
    let v = rel.add_column("v", g.clone(), Width::signed(24), 2);
    let x = rel.add_column("x", g, Width::signed(8), 2);
    let y = rel.add_column("y", g1, Width::signed(17), 1);
    for (column, width) in [
        (lo, Width::unsigned(12)),
        (hi, Width::signed(12)),
        (x, Width::signed(8)),
    ] {
        rel.ranges.push(Range {
            name: alloc::format!("r{}", column.0),
            column,
            width,
        });
    }
    rel.composes.push(stele_ir::relation::Compose {
        name: "v".to_string(),
        column: v,
        limbs: vec![(lo, 0), (hi, 12)],
    });
    rel.matmuls.push(stele_ir::relation::Matmul {
        name: "xx".to_string(),
        free: 1,
        summed: 1,
        out: Ref::identity(y, 1),
        lhs: Ref::identity(x, 2),
        rhs: Ref::identity(x, 2),
    });
    let mut values = Values::new(&rel);
    let (l, h) = ([0, 4095, 17, 2048], [-2048, 2047, -1, 0]);
    values.set(&rel, lo, l.to_vec()).expect("lo");
    values.set(&rel, hi, h.to_vec()).expect("hi");
    values
        .set(&rel, v, (0..4).map(|i| l[i] + (h[i] << 12)).collect())
        .expect("v");
    values.set(&rel, x, vec![-128, 127, 5, -3]).expect("x");
    values
        .set(&rel, y, vec![128 * 128 + 25, 127 * 127 + 9])
        .expect("y");
    (rel, values)
}

fn tampered(rel: &Relation, values: &Values, column: ColumnId, index: usize) -> Values {
    let mut out = values.clone();
    let mut v = values.get(rel, column).expect("set").to_vec();
    v[index] += 1;
    out.set(rel, column, v).expect("shape");
    out
}

#[test]
fn accepts_honest_composed() {
    let (rel, values) = composed();
    assert!(stele_ir::relation::check(&rel, &values).is_ok());
    assert!(lie(&rel, &values, &values).is_ok());
}

#[test]
fn rejects_identity_column_claim_on_a_false_commitment() {
    // (a) v is committed +1 but the Compose zerocheck is proven from the true v.
    let (rel, values) = composed();
    let committed = tampered(&rel, &values, ColumnId(2), 1);
    assert_eq!(lie(&rel, &committed, &values).err(), VALUE);
}

#[test]
fn rejects_lookup_tuple_claim_on_a_false_commitment() {
    // (b) sq[0] = 50 is committed; the lookup is proven from the true sq[0] = 49.
    let (rel, values) = squares();
    let committed = tampered(&rel, &values, ColumnId(1), 0);
    assert_eq!(lie(&rel, &committed, &values).err(), VALUE);
}

#[test]
fn rejects_matmul_out_claim_on_a_false_commitment() {
    // (c) NC-1307 binding: y is committed +1; out~(ρ) is sent from the true y.
    let (rel, values) = composed();
    let committed = tampered(&rel, &values, ColumnId(4), 0);
    assert_eq!(lie(&rel, &committed, &values).err(), VALUE);
}

#[test]
fn rejects_weight_claim_on_a_different_weight_source() {
    // (d) The model commits W; the prover proves the matmul with W'.
    let mut rel = Relation::default();
    let g = Kind::Witness(rel.add_group("G/w/2", 2));
    let g1 = Kind::Witness(rel.add_group("G/w/1", 1));
    let x = rel.add_column("x", g, Width::signed(4), 2);
    let w = rel.add_column("w", Kind::Weight, Width::signed(4), 2);
    let y = rel.add_column("y", g1, Width::signed(9), 1);
    for column in [x, w] {
        rel.ranges.push(Range {
            name: alloc::format!("r{}", column.0),
            column,
            width: Width::signed(4),
        });
    }
    // y[i] = sum_k x[i,k] w[i,k] (bit 0 = i, bit 1 = k): worst case 128 fits signed 9.
    rel.matmuls.push(stele_ir::relation::Matmul {
        name: "xw".to_string(),
        free: 1,
        summed: 1,
        out: Ref::identity(y, 1),
        lhs: Ref::identity(x, 2),
        rhs: Ref::identity(w, 2),
    });
    let model = [1i64, -2, 3, 4];
    let forged = [1i64, -2, 3, 5];
    let xv = [2i64, 1, -3, 2];
    let mut values = Values::new(&rel);
    values.set(&rel, x, xv.to_vec()).expect("x");
    values.set(&rel, w, forged.to_vec()).expect("w");
    let y_of = |w: &[i64]| vec![xv[0] * w[0] + xv[2] * w[2], xv[1] * w[1] + xv[3] * w[3]];
    values.set(&rel, y, y_of(&forged)).expect("y");
    let mut owner = values.clone();
    owner.set(&rel, w, model.to_vec()).expect("w");
    let message = model_message(&rel, &owner).expect("model message");
    let layout = model_layout(&rel).expect("layout").expect("weights");
    let prepared = PreparedSource::<K>::from_code_id(
        layout.id,
        layout.ell,
        &layout.code,
        &message,
        &mut HashUsage::default(),
    )
    .expect("w");
    let (bytes, _) = prepared.certificate().expect("certificate");
    let (certificate, _) = verify_certificate(*prepared.source(), &bytes).expect("certificate");
    let plan = plan(&rel).expect("plan");
    let mut t = Transcript::new(PUBLIC).expect("transcript");
    let proof = prove_plan(
        &mut t,
        &rel,
        &plan,
        &values,
        &values,
        Some((&prepared, &certificate)),
    )
    .expect("a lying prover still produces bytes");
    let mut t = Transcript::new(PUBLIC).expect("transcript");
    assert_eq!(
        verify(&mut t, &rel, Some(&certificate), &proof).err(),
        VALUE
    );
}

#[test]
fn rejects_zero_tuple_that_is_only_table_padding() {
    // A 3-row table pads to 4 rows of zeros; (0, 0) is not a real row. Padded rows
    // carry numerator 0 and denominator 1 and lie outside the prefix multiplicity
    // functional, so padding admits no tuple (RFC-0008 A5 §2).
    let mut rel = Relation::default();
    let g = Kind::Witness(rel.add_group("G/pad/2", 2));
    let x = rel.add_column("x", g.clone(), Width::signed(4), 2);
    let y = rel.add_column("y", g, Width::signed(4), 2);
    let table = rel.add_table(Table {
        name: "pairs".to_string(),
        widths: vec![Width::signed(4), Width::signed(4)],
        rows: vec![vec![1, 2], vec![3, 4], vec![5, 6]],
    });
    rel.lookups.push(Lookup {
        name: "pairs".to_string(),
        vars: 2,
        selector: None,
        tuple: vec![Ref::identity(x, 2), Ref::identity(y, 2)],
        table,
    });
    let mut values = Values::new(&rel);
    values.set(&rel, x, vec![1, 3, 5, 0]).expect("x");
    values.set(&rel, y, vec![2, 4, 6, 0]).expect("y");
    assert!(stele_ir::relation::check(&rel, &values).is_err());
    assert_eq!(
        lie(&rel, &values, &values).err(),
        Some(Error::Fraction(stele_lookup::fraction::Error::RootMismatch))
    );
    values.set(&rel, x, vec![1, 3, 5, 5]).expect("x");
    values.set(&rel, y, vec![2, 4, 6, 6]).expect("y");
    assert!(lie(&rel, &values, &values).is_ok());
}

/// RFC-0026 A3: lookups of different domain sizes into one table (one with a selector
/// and a broadcast read) and ranges of one width over columns of three lengths and
/// both signednesses each batch into a single A5 statement.
fn batched() -> (Relation, Values) {
    let mut rel = Relation::default();
    let g3 = Kind::Witness(rel.add_group("G/batch/3", 3));
    let g2 = Kind::Witness(rel.add_group("G/batch/2", 2));
    let g1 = Kind::Witness(rel.add_group("G/batch/1", 1));
    let a = rel.add_column("a", g3.clone(), Width::signed(8), 3);
    let b = rel.add_column("b", g2.clone(), Width::unsigned(8), 2);
    let c = rel.add_column("c", g1, Width::signed(8), 1);
    let x = rel.add_column("x", g3, Width::signed(4), 3);
    let y = rel.add_column("y", g2, Width::signed(4), 2);
    let sel = rel.add_column(
        "sel",
        Kind::Public(vec![1, 0, 1, 1, 0, 1, 1, 0]),
        Width::unsigned(1),
        3,
    );
    for (column, width) in [
        (a, Width::signed(8)),
        (b, Width::unsigned(8)),
        (c, Width::signed(8)),
        (x, Width::signed(4)),
        (y, Width::signed(4)),
    ] {
        rel.ranges.push(Range {
            name: alloc::format!("r{}", column.0),
            column,
            width,
        });
    }
    let table = rel.add_table(Table {
        name: "small".to_string(),
        widths: vec![Width::signed(4)],
        rows: vec![vec![-3], vec![0], vec![2], vec![5], vec![7]],
    });
    rel.lookups.push(Lookup {
        name: "x".to_string(),
        vars: 3,
        selector: Some(Ref::identity(sel, 3)),
        tuple: vec![Ref::identity(x, 3)],
        table,
    });
    // y broadcast over a 3-bit domain (read on bits 1, 2).
    rel.lookups.push(Lookup {
        name: "y".to_string(),
        vars: 3,
        selector: None,
        tuple: vec![Ref {
            column: y,
            vars: vec![1, 2],
        }],
        table,
    });
    let mut values = Values::new(&rel);
    values
        .set(&rel, a, vec![-128, 127, 0, 5, -7, 9, 100, -1])
        .expect("a");
    values.set(&rel, b, vec![0, 255, 17, 3]).expect("b");
    values.set(&rel, c, vec![-128, 127]).expect("c");
    values
        .set(&rel, x, vec![2, -8, 5, 7, 6, 0, -3, 1])
        .expect("x");
    values.set(&rel, y, vec![0, 2, 5, -3]).expect("y");
    (rel, values)
}

#[test]
fn accepts_batched_lookups_and_ranges_per_table() {
    let (rel, values) = batched();
    assert!(stele_ir::relation::check(&rel, &values).is_ok());
    let plan = plan(&rel).expect("plan");
    // One check for the table, one for 8-bit ranges, one for 4-bit ranges.
    assert_eq!(plan.checks.len(), 3);
    assert_eq!(
        plan.checks
            .iter()
            .map(|c| (c.members.len(), c.m))
            .collect::<Vec<_>>(),
        [(2, 4), (3, 4), (2, 4)]
    );
    assert!(lie(&rel, &values, &values).is_ok());
}

#[test]
fn rejects_batched_tuple_outside_the_table() {
    // y[3] = 6 is in no row; the shared statement still rejects it.
    let (rel, mut values) = batched();
    values.set(&rel, ColumnId(4), vec![0, 2, 5, 6]).expect("y");
    assert!(stele_ir::relation::check(&rel, &values).is_err());
    assert_eq!(
        lie(&rel, &values, &values).err(),
        Some(Error::Fraction(stele_lookup::fraction::Error::RootMismatch))
    );
}

#[test]
fn rejects_member_values_that_do_not_sum_to_the_batched_claim() {
    // Two-column lookup only (no range on sq): the prover commits sq[0] = 50 (tuple
    // column 1), runs the lookup on the true 49 and reports the member evaluation of
    // what it committed. Only the A3 member sum over column 1 can reject.
    let (mut rel, values) = squares();
    rel.ranges.clear();
    let committed = tampered(&rel, &values, ColumnId(1), 0);
    let mut forged = plan(&rel).expect("plan");
    assert_eq!(forged.checks.len(), 1);
    forged.checks[0].split = Some(committed.clone());
    let mut t = Transcript::new(PUBLIC).expect("transcript");
    let proof = prove_plan(&mut t, &rel, &forged, &committed, &values, None)
        .expect("a lying prover still produces bytes");
    let mut t = Transcript::new(PUBLIC).expect("transcript");
    assert_eq!(
        verify(&mut t, &rel, None, &proof).err(),
        Some(Error::MemberSumMismatch)
    );
}

#[test]
fn rejects_false_commitment_in_a_later_smaller_member() {
    // c (length 2) is the last, smallest member of the batched 8-bit range check; its
    // committed c[1] is +1 while every message is proven from the true value.
    let (rel, values) = batched();
    let committed = tampered(&rel, &values, ColumnId(2), 1);
    assert_eq!(lie(&rel, &committed, &values).err(), VALUE);
}

/// Groups with the given (log_len, column count), every column range-checked.
fn groups(shapes: &[(u8, usize)]) -> Relation {
    let mut rel = Relation::default();
    for (g, &(n, count)) in shapes.iter().enumerate() {
        let kind = Kind::Witness(rel.add_group(&alloc::format!("G/layout/{g}"), n));
        for i in 0..count {
            let column = rel.add_column(
                &alloc::format!("g{g}/c{i}"),
                kind.clone(),
                Width::signed(8),
                n,
            );
            rel.ranges.push(Range {
                name: alloc::format!("g{g}/r{i}"),
                column,
                width: Width::signed(8),
            });
        }
    }
    rel
}

#[test]
fn matches_reference_stacked_layout_with_ties_and_mixed_sizes() {
    // Block sizes 2^(n+c): g0 = 2^(2+1), g1 = 2^3, g2 = 2^1, g3 = 2^(4+1).
    // Largest first, ties (g0, g1) in GroupId order: g3 @0, g0 @32, g1 @40, g2 @48.
    let first = plan(&groups(&[(2, 2), (3, 1), (1, 1), (4, 2)])).expect("plan");
    let offsets: Vec<usize> = first.groups.iter().map(|g| g.offset).collect();
    assert_eq!(offsets, [32, 40, 48, 0]);
    assert_eq!(first.stack.as_ref().map(|s| s.bits), Some(6));
    // A tie in the other declaration order keeps GroupId order too.
    let other = plan(&groups(&[(3, 1), (2, 2)])).expect("plan");
    let offsets: Vec<usize> = other.groups.iter().map(|g| g.offset).collect();
    assert_eq!(offsets, [0, 8]);
}

#[test]
fn rejects_a_group_wider_than_a_source_before_shifting() {
    // n = 30 with two columns needs 2^31 entries: rejected, never shifted or summed.
    assert_eq!(plan(&groups(&[(30, 2)])).err(), Some(Error::Unsupported));
}

/// Weight columns of the given lengths, each range-checked.
fn weights(lengths: &[u8]) -> Relation {
    let mut rel = Relation::default();
    for (i, &n) in lengths.iter().enumerate() {
        let column = rel.add_column(&alloc::format!("w{i}"), Kind::Weight, Width::signed(8), n);
        rel.ranges.push(Range {
            name: alloc::format!("w{i}/r"),
            column,
            width: Width::signed(8),
        });
    }
    rel
}

#[test]
fn matches_reference_model_layout_with_ties_and_mixed_sizes() {
    // Blocks 2^n: w0 = 2^3, w1 = 2^5, w2 = 2^3, w3 = 2^1. Largest first, ties (w0, w2)
    // in ColumnId order: w1 @0, w0 @32, w2 @40, w3 @48; 50 entries, so 2^6.
    let first = plan(&weights(&[3, 5, 3, 1])).expect("plan");
    let offsets: Vec<usize> = first.weights.iter().map(|w| w.offset).collect();
    assert_eq!(offsets, [32, 0, 40, 48]);
    assert_eq!(
        first.model.as_ref().map(|m| (m.id, m.bits)),
        Some((MODEL, 6))
    );
    let layout = model_layout(&weights(&[3, 5, 3, 1]))
        .expect("layout")
        .expect("weights");
    assert_eq!((layout.id, layout.bits), (MODEL, 6));
    assert_eq!(model_layout(&squares().0).expect("layout"), None);
}

#[test]
fn rejects_a_model_wider_than_a_source() {
    // Two 2^30 weights need 2^31 entries.
    assert_eq!(plan(&weights(&[30, 30])).err(), Some(Error::Unsupported));
}

#[test]
fn rejects_a_missing_or_foreign_model_certificate() {
    let rel = weights(&[2]);
    let mut values = Values::new(&rel);
    values.set(&rel, ColumnId(0), vec![1, -2, 3, 4]).expect("w");
    let plan = plan(&rel).expect("plan");
    let proof = Proof::default();
    let mut t = Transcript::new(PUBLIC).expect("transcript");
    assert_eq!(
        verify(&mut t, &rel, None, &proof).err(),
        Some(Error::Weights)
    );
    // A Circle source of the right size is not the derived v2 layout.
    let message: Vec<M31> = [1, -2, 3, 4].iter().map(|v| M31::from_i64(*v)).collect();
    let prepared =
        PreparedSource::<K>::new(MODEL, 0, 2, 1, &message, &mut HashUsage::default()).expect("w");
    let (bytes, _) = prepared.certificate().expect("certificate");
    let (foreign, _) = verify_certificate(*prepared.source(), &bytes).expect("certificate");
    let mut t = Transcript::new(PUBLIC).expect("transcript");
    assert_eq!(
        verify(&mut t, &rel, Some(&foreign), &proof).err(),
        Some(Error::Weights)
    );
    let mut t = Transcript::new(PUBLIC).expect("transcript");
    assert_eq!(
        prove_plan(&mut t, &rel, &plan, &values, &values, None).err(),
        Some(Error::Weights)
    );
}

#[test]
fn accepts_several_weights_in_one_model_source() {
    // Three weights of different sizes, each range-checked: every claim must land in
    // its own block of the model source (RFC-0026 A5).
    let rel = weights(&[1, 3, 2]);
    let mut values = Values::new(&rel);
    values.set(&rel, ColumnId(0), vec![-128, 127]).expect("w0");
    values
        .set(&rel, ColumnId(1), vec![1, -2, 3, -4, 5, -6, 7, -8])
        .expect("w1");
    values
        .set(&rel, ColumnId(2), vec![9, 10, -11, 12])
        .expect("w2");
    let message = model_message(&rel, &values).expect("message");
    let layout = model_layout(&rel).expect("layout").expect("weights");
    let prepared = PreparedSource::<K>::from_code_id(
        layout.id,
        layout.ell,
        &layout.code,
        &message,
        &mut HashUsage::default(),
    )
    .expect("model");
    let (bytes, _) = prepared.certificate().expect("certificate");
    let (certificate, _) = verify_certificate(*prepared.source(), &bytes).expect("certificate");
    let mut t = Transcript::new(PUBLIC).expect("transcript");
    let proof =
        prove(&mut t, &rel, &values, Some((&prepared, &certificate))).expect("honest proof");
    let mut t = Transcript::new(PUBLIC).expect("transcript");
    assert!(verify(&mut t, &rel, Some(&certificate), &proof).is_ok());
}

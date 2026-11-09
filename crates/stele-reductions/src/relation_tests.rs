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
    let proof = prove_plan(&mut t, rel, plan, values, values, &[], &[])?;
    let mut t = Transcript::new(PUBLIC).expect("transcript");
    verify(&mut t, rel, &[], &proof)
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
    let proof = prove_plan(&mut t, rel, &plan, committed, values, &[], &[])
        .expect("a lying prover still produces bytes");
    let mut t = Transcript::new(PUBLIC).expect("transcript");
    verify(&mut t, rel, &[], &proof)
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
    let message: Vec<M31> = model.iter().map(|v| M31::from_i64(*v)).collect();
    let prepared =
        PreparedSource::<K>::new(1000, 0, 2, 1, &message, &mut HashUsage::default()).expect("w");
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
        &[&prepared],
        &[&certificate],
    )
    .expect("a lying prover still produces bytes");
    let mut t = Transcript::new(PUBLIC).expect("transcript");
    assert_eq!(verify(&mut t, &rel, &[&certificate], &proof).err(), VALUE);
}

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
    let proof = prove_plan(&mut t, rel, plan, values, &[], &[])?;
    let mut t = Transcript::new(PUBLIC).expect("transcript");
    verify(&mut t, rel, &[], &proof.encode())
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

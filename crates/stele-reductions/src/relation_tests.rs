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
    let proof = prove_plan(&mut t, rel, plan, values, values, &[])?;
    let mut t = Transcript::new(PUBLIC).expect("transcript");
    verify(&mut t, rel, &[], &proof, Sources::Expander)
}

#[test]
fn accepts_honest_squares() {
    let (rel, values) = squares();
    assert!(attempt(&rel, &values, &plan(&rel, Sources::Expander).expect("plan")).is_ok());
}

#[test]
fn rejects_prover_table_differing_from_the_relation() {
    // The prover runs A5 against a table whose row 7 reads (7, 50); the roots then
    // balance and only the verifier's own table evaluation rejects.
    let (rel, mut values) = squares();
    values
        .set(&rel, ColumnId(1), vec![50, 4, 9, 0])
        .expect("sq");
    let mut forged = plan(&rel, Sources::Expander).expect("plan");
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
    let mut forged = plan(&rel, Sources::Expander).expect("plan");
    forged.checks[0].skew = 1;
    assert_eq!(
        attempt(&rel, &values, &forged).err(),
        Some(Error::Lookup(crate::lookup::Error::PieceSumMismatch))
    );
}

// Lying prover: commit `committed` (step 2), prove every later message from `values`
// (the true witness). Only the openings can tie claims to the commitment.
fn lie(rel: &Relation, committed: &Values, values: &Values) -> Result<Ledger, Error> {
    let plan = plan(rel, Sources::Expander).expect("plan");
    let mut t = Transcript::new(PUBLIC).expect("transcript");
    let proof = prove_plan(&mut t, rel, &plan, committed, values, &[])
        .expect("a lying prover still produces bytes");
    let mut t = Transcript::new(PUBLIC).expect("transcript");
    verify(&mut t, rel, &[], &proof, Sources::Expander)
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
    let plan = plan(&rel, Sources::Expander).expect("plan");
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
    let mut forged = plan(&rel, Sources::Expander).expect("plan");
    assert_eq!(forged.checks.len(), 1);
    forged.checks[0].split = Some(committed.clone());
    let mut t = Transcript::new(PUBLIC).expect("transcript");
    let proof = prove_plan(&mut t, &rel, &forged, &committed, &values, &[])
        .expect("a lying prover still produces bytes");
    let mut t = Transcript::new(PUBLIC).expect("transcript");
    assert_eq!(
        verify(&mut t, &rel, &[], &proof, Sources::Expander).err(),
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
    let first = plan(
        &groups(&[(2, 2), (3, 1), (1, 1), (4, 2)]),
        Sources::Expander,
    )
    .expect("plan");
    let offsets: Vec<usize> = first.groups.iter().map(|g| g.offset).collect();
    assert_eq!(offsets, [32, 40, 48, 0]);
    assert_eq!(first.stack.as_ref().map(|s| s.bits), Some(6));
    // A tie in the other declaration order keeps GroupId order too.
    let other = plan(&groups(&[(3, 1), (2, 2)]), Sources::Expander).expect("plan");
    let offsets: Vec<usize> = other.groups.iter().map(|g| g.offset).collect();
    assert_eq!(offsets, [0, 8]);
}

#[test]
fn rejects_a_group_wider_than_a_source_before_shifting() {
    // n = 30 with two columns needs 2^31 entries: rejected, never shifted or summed.
    assert_eq!(
        plan(&groups(&[(30, 2)]), Sources::Expander).err(),
        Some(Error::Unsupported)
    );
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

/// Deterministic in-range weight values for `weights(lengths)`.
fn weight_values(rel: &Relation, lengths: &[u8]) -> Values {
    let mut values = Values::new(rel);
    for (i, &n) in lengths.iter().enumerate() {
        let v = (0..1i64 << n)
            .map(|x| (x * 37 + i as i64 * 11) % 251 - 125)
            .collect();
        values.set(rel, ColumnId(i as u32), v).expect("w");
    }
    values
}

/// Prepare and certify every model source of `messages`.
fn certify_model<'a>(
    rel: &Relation,
    messages: &'a [Vec<M31>],
) -> (Vec<PreparedSource<'a, K>>, Vec<VerifiedCertificate<K>>) {
    let layouts = model_layout(rel, Sources::Expander).expect("layout");
    let prepared: Vec<_> = layouts
        .iter()
        .zip(messages)
        .map(|(l, m)| {
            PreparedSource::<K>::from_code_id(l.id, l.ell, &l.code, m, &mut HashUsage::default())
                .expect("model")
        })
        .collect();
    let certificates = prepared
        .iter()
        .map(|p| {
            let (bytes, _) = p.certificate().expect("certificate");
            verify_certificate(*p.source(), &bytes)
                .expect("certificate")
                .0
        })
        .collect();
    (prepared, certificates)
}

#[test]
fn matches_reference_model_layout_with_ties_and_mixed_sizes() {
    // Blocks 2^n: w0 = 2^3, w1 = 2^5, w2 = 2^3, w3 = 2^1. Largest first, ties (w0, w2)
    // in ColumnId order: w1 @0, w0 @32, w2 @40, w3 @48; 50 entries, so 2^6.
    let first = plan(&weights(&[3, 5, 3, 1]), Sources::Expander).expect("plan");
    let offsets: Vec<usize> = first.weights.iter().map(|w| w.offset).collect();
    assert_eq!(offsets, [32, 0, 40, 48]);
    assert_eq!(
        first
            .model
            .iter()
            .map(|m| (m.id, m.bits))
            .collect::<Vec<_>>(),
        [(MODEL, 6)]
    );
    assert!(model_layout(&squares().0, Sources::Expander)
        .expect("layout")
        .is_empty());
}

#[test]
fn matches_reference_model_split_into_capped_sources() {
    // 2^30 + 2^29 + 2^29 + 2^2 entries in ColumnId order: the first weight fills
    // source 0, the next two fill source 1, the last starts source 2 (RFC-0026 A5).
    // Distinct range widths keep each weight's range check in its own A3 check.
    let mut rel = weights(&[30, 29, 29, 2]);
    for (i, range) in rel.ranges.iter_mut().enumerate() {
        range.width = Width::signed(5 + i as u8);
        rel.columns[i].width = Width::signed(5 + i as u8);
    }
    let plan = plan(&rel, Sources::Expander).expect("plan");
    let layout: Vec<(usize, usize)> = plan.weights.iter().map(|w| (w.source, w.offset)).collect();
    assert_eq!(layout, [(0, 0), (1, 0), (1, 1 << 29), (2, 0)]);
    assert_eq!(
        plan.model
            .iter()
            .map(|m| (m.id, m.bits))
            .collect::<Vec<_>>(),
        [(MODEL, 30), (MODEL + 1, 30), (MODEL + 2, 6)]
    );
}

#[test]
fn rejects_a_weight_wider_than_a_source() {
    let mut rel = weights(&[2]);
    // Bypass validation's MAX_VARS for the guard itself: plan() checks n <= 30.
    rel.columns[0].log_len = 31;
    assert!(plan(&rel, Sources::Expander).is_err());
}

#[test]
fn rejects_a_missing_or_foreign_model_certificate() {
    let rel = weights(&[2]);
    let values = weight_values(&rel, &[2]);
    let plan = plan(&rel, Sources::Expander).expect("plan");
    let proof = Proof::default();
    let mut t = Transcript::new(PUBLIC).expect("transcript");
    assert_eq!(
        verify(&mut t, &rel, &[], &proof, Sources::Expander).err(),
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
        verify(&mut t, &rel, &[&foreign], &proof, Sources::Expander).err(),
        Some(Error::Weights)
    );
    let mut t = Transcript::new(PUBLIC).expect("transcript");
    assert_eq!(
        prove_plan(&mut t, &rel, &plan, &values, &values, &[]).err(),
        Some(Error::Weights)
    );
}

#[test]
fn accepts_several_weights_in_one_model_source() {
    // Three weights of different sizes: every claim must land in its own block.
    let lengths = [1, 3, 2];
    let rel = weights(&lengths);
    let values = weight_values(&rel, &lengths);
    let messages = model_messages(&rel, &values).expect("messages");
    let (prepared, certificates) = certify_model(&rel, &messages);
    let model: Vec<_> = prepared.iter().zip(&certificates).collect();
    let mut t = Transcript::new(PUBLIC).expect("transcript");
    let proof = prove(&mut t, &rel, &values, &model, Sources::Expander).expect("honest proof");
    let mut t = Transcript::new(PUBLIC).expect("transcript");
    let certificates: Vec<_> = certificates.iter().collect();
    assert!(verify(&mut t, &rel, &certificates, &proof, Sources::Expander).is_ok());
}

#[test]
fn rejects_any_forged_weight_among_several() {
    // (d) The model commits W; the prover proves with W' differing in one weight. Each
    // weight is forged in turn: the first, a middle one that is neither first nor
    // largest, and the last.
    let lengths = [1, 3, 2];
    let rel = weights(&lengths);
    let owner = weight_values(&rel, &lengths);
    let messages = model_messages(&rel, &owner).expect("messages");
    let (prepared, certificates) = certify_model(&rel, &messages);
    let model: Vec<_> = prepared.iter().zip(&certificates).collect();
    let refs: Vec<_> = certificates.iter().collect();
    let plan = plan(&rel, Sources::Expander).expect("plan");
    for forged in 0..lengths.len() {
        let values = tampered(&rel, &owner, ColumnId(forged as u32), 1);
        let mut t = Transcript::new(PUBLIC).expect("transcript");
        let proof = prove_plan(&mut t, &rel, &plan, &values, &values, &model)
            .expect("a lying prover still produces bytes");
        let mut t = Transcript::new(PUBLIC).expect("transcript");
        assert_eq!(
            verify(&mut t, &rel, &refs, &proof, Sources::Expander).err(),
            VALUE,
            "forged weight {forged}"
        );
    }
}

#[test]
fn binds_the_model_root_without_it_in_the_public_input() {
    // PUBLIC carries no model root; the engine absorbs it after the statement, so a
    // proof made under one model never verifies under another of the same layout.
    let lengths = [2, 1];
    let rel = weights(&lengths);
    let first = weight_values(&rel, &lengths);
    let second = tampered(&rel, &first, ColumnId(0), 0);
    let messages = model_messages(&rel, &first).expect("messages");
    let (prepared, certificates) = certify_model(&rel, &messages);
    let model: Vec<_> = prepared.iter().zip(&certificates).collect();
    let mut t = Transcript::new(PUBLIC).expect("transcript");
    let proof = prove(&mut t, &rel, &first, &model, Sources::Expander).expect("honest proof");
    let other_messages = model_messages(&rel, &second).expect("messages");
    let (_, other) = certify_model(&rel, &other_messages);
    let mut t = Transcript::new(PUBLIC).expect("transcript");
    let other: Vec<_> = other.iter().collect();
    assert!(verify(&mut t, &rel, &other, &proof, Sources::Expander).is_err());
    let mut t = Transcript::new(PUBLIC).expect("transcript");
    let mine: Vec<_> = certificates.iter().collect();
    assert!(verify(&mut t, &rel, &mine, &proof, Sources::Expander).is_ok());
}

/// RFC-0026 A11: under `Sources::Circle` the stacked and model sources are Circle
/// rate-1/4 with policy byte 2 and the same bits as the expander plan; an honest proof
/// verifies, and one verified under the other set rejects.
#[test]
fn accepts_circle_policy2_sources_and_rejects_the_other_set() {
    let (expander, circle) = (
        plan(&squares().0, Sources::Expander).expect("plan"),
        plan(&squares().0, Sources::Circle).expect("plan"),
    );
    let (e, c) = (
        expander.stack.as_ref().expect("stack"),
        circle.stack.as_ref().expect("stack"),
    );
    assert_eq!(e.bits, c.bits);
    let source = c.source([0; 32]).expect("source");
    assert_eq!(source.code_id().len(), 21); // Circle identity (A9).
    assert_eq!(source.code_id()[20], CIRCLE_BLOWUP);
    // Policy byte 2 (A14 item 1): k_q = 16 grinding on every column round.
    assert_eq!(source.grind_bits(ProofKind::Certificate).1, 16);

    let lengths = [1, 3, 2];
    let rel = weights(&lengths);
    let values = weight_values(&rel, &lengths);
    let messages = model_messages(&rel, &values).expect("messages");
    let layouts = model_layout(&rel, Sources::Circle).expect("layout");
    let prepared: Vec<_> = layouts
        .iter()
        .zip(&messages)
        .map(|(l, m)| l.sources.prepare(l.id, l.ell, &l.code, m).expect("model"))
        .collect();
    let certificates: Vec<_> = prepared
        .iter()
        .map(|p| {
            let (bytes, _) = p.certificate().expect("certificate");
            verify_certificate(*p.source(), &bytes)
                .expect("certificate")
                .0
        })
        .collect();
    let model: Vec<_> = prepared.iter().zip(&certificates).collect();
    let mut t = Transcript::new(PUBLIC).expect("transcript");
    let proof = prove(&mut t, &rel, &values, &model, Sources::Circle).expect("honest proof");
    let refs: Vec<_> = certificates.iter().collect();
    let mut t = Transcript::new(PUBLIC).expect("transcript");
    assert!(verify(&mut t, &rel, &refs, &proof, Sources::Circle).is_ok());
    // The expander plan derives other model sources than the certified ones.
    let mut t = Transcript::new(PUBLIC).expect("transcript");
    assert_eq!(
        verify(&mut t, &rel, &refs, &proof, Sources::Expander).err(),
        Some(Error::Weights)
    );
}

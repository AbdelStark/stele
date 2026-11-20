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
    let proof = prove_plan(&mut t, rel, plan, values, values, &[], None)?;
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
    let proof = prove_plan(&mut t, rel, &plan, committed, values, &[], None)
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

#[cfg(feature = "controls")]
#[test]
fn rejects_forged_identity_finals_after_honest_recommitment() {
    let (rel, values) = composed();
    let changed = tampered(&rel, &values, ColumnId(2), 0);
    assert_eq!(stele_ir::relation::check(&rel, &values), Ok(()));
    assert_eq!(
        stele_ir::relation::check(&rel, &changed),
        Err(stele_ir::relation::Violation::Compose {
            relation: "v".to_string(),
            index: 0,
        })
    );
    let saved = values.clone();
    for set in [
        Sources::Expander,
        Sources::CircleAll,
        Sources::CircleAllGrind,
    ] {
        let ordinary = prove(
            &mut Transcript::new(PUBLIC).expect("public input"),
            &rel,
            &values,
            &[],
            set,
        )
        .expect("honest proof");
        let restored = prove_forged(
            &mut Transcript::new(PUBLIC).expect("public input"),
            &rel,
            &values,
            &[],
            set,
            &Forge::default(),
        )
        .expect("restored witness proof");
        assert_eq!(
            restored, ordinary,
            "default forgery retains every proof byte"
        );
        verify(
            &mut Transcript::new(PUBLIC).expect("public input"),
            &rel,
            &[],
            &restored,
            set,
        )
        .expect("honest acceptance");
        let forge = Forge {
            witness: Some((ColumnId(2), 0)),
            ..Forge::default()
        };
        let false_proof = prove_forged(
            &mut Transcript::new(PUBLIC).expect("public input"),
            &rel,
            &values,
            &[],
            set,
            &forge,
        )
        .expect("producer must emit the false witness proof");
        assert_eq!(values, saved, "the reference witness stays unchanged");
        assert_ne!(
            &false_proof.groups[0][..32],
            &ordinary.groups[0][..32],
            "changed witness must be recommitted"
        );
        assert_eq!(
            verify(
                &mut Transcript::new(PUBLIC).expect("public input"),
                &rel,
                &[],
                &false_proof,
                set
            )
            .err(),
            Some(Error::Sumcheck(
                stele_sumcheck::Error::FinalEvaluationMismatch
            ))
        );
    }
}

#[cfg(feature = "controls")]
#[test]
fn rejects_invalid_forged_witness_selectors() {
    let (mut rel, values) = composed();
    let public = rel.add_column("public", Kind::Public(vec![0; 4]), Width::unsigned(1), 2);
    for selector in [
        (ColumnId(u32::MAX), 0),
        (ColumnId(2), 4),
        (ColumnId(2), 1),
        (ColumnId(3), 0),
        (public, 0),
    ] {
        let mut t = Transcript::new(PUBLIC).expect("public input");
        assert_eq!(
            prove_forged(
                &mut t,
                &rel,
                &values,
                &[],
                Sources::Expander,
                &Forge {
                    witness: Some(selector),
                    ..Forge::default()
                }
            )
            .err(),
            Some(Error::Unsupported),
            "missing column/entry, out-of-range increment, non-identity or public column"
        );
        assert_eq!(
            t.usage(),
            Transcript::<K>::new(PUBLIC).expect("public input").usage()
        );
    }
}

#[cfg(feature = "controls")]
#[test]
fn rejects_forged_column_claim_with_unchanged_sources() {
    let (rel, mut values) = composed();
    let limbs = vec![0, 1, 17, 1024];
    values.set(&rel, ColumnId(0), limbs.clone()).expect("lo");
    values.set(&rel, ColumnId(1), limbs.clone()).expect("hi");
    values
        .set(
            &rel,
            ColumnId(2),
            limbs.iter().map(|v| v + (v << 12)).collect(),
        )
        .expect("v");
    assert_eq!(stele_ir::relation::check(&rel, &values), Ok(()));
    let saved = values.clone();
    for extra in [
        Forge {
            table: Some(0),
            ..Forge::default()
        },
        Forge {
            public: Some((ColumnId(0), 0)),
            ..Forge::default()
        },
        Forge {
            witness: Some((ColumnId(2), 0)),
            ..Forge::default()
        },
    ] {
        let mut t = Transcript::new(PUBLIC).expect("public input");
        assert_eq!(
            prove_forged(
                &mut t,
                &rel,
                &values,
                &[],
                Sources::CircleAll,
                &Forge {
                    column_claim: Some(ColumnId(0)),
                    ..extra
                }
            )
            .err(),
            Some(Error::Unsupported),
            "column routing must be the only mutation",
        );
        assert_eq!(
            t.usage(),
            Transcript::<K>::new(PUBLIC).expect("public input").usage()
        );
    }
    for set in [Sources::CircleAll, Sources::CircleAllGrind] {
        let ordinary = prove(
            &mut Transcript::new(PUBLIC).expect("public input"),
            &rel,
            &values,
            &[],
            set,
        )
        .expect("honest proof");
        let restored = prove_forged(
            &mut Transcript::new(PUBLIC).expect("public input"),
            &rel,
            &values,
            &[],
            set,
            &Forge::default(),
        )
        .expect("unchanged selector");
        assert_eq!(restored, ordinary, "every ordinary proof byte is retained");
        verify(
            &mut Transcript::new(PUBLIC).expect("public input"),
            &rel,
            &[],
            &ordinary,
            set,
        )
        .expect("honest acceptance");
        let routed = prove_forged(
            &mut Transcript::new(PUBLIC).expect("public input"),
            &rel,
            &values,
            &[],
            set,
            &Forge {
                column_claim: Some(ColumnId(0)),
                ..Forge::default()
            },
        )
        .expect("genuine dependent batch and opening");
        assert_eq!(values, saved, "witness and sources stay unchanged");
        assert_eq!(routed.groups, ordinary.groups);
        assert_eq!(routed.multiplicities, ordinary.multiplicities);
        assert_eq!(routed.identities, ordinary.identities);
        assert_eq!(routed.lookups, ordinary.lookups);
        assert_eq!(routed.matmuls, ordinary.matmuls);
        assert_ne!(routed.openings, ordinary.openings);
        assert_eq!(
            verify(
                &mut Transcript::new(PUBLIC).expect("public input"),
                &rel,
                &[],
                &routed,
                set,
            )
            .err(),
            Some(Error::Sumcheck(stele_sumcheck::Error::RoundSumMismatch)),
        );
    }
}

#[cfg(feature = "controls")]
#[test]
fn rejects_invalid_forged_column_claim_selectors() {
    let (mut rel, values) = composed();
    let public = rel.add_column("public", Kind::Public(vec![0; 4]), Width::unsigned(1), 2);
    let weight = rel.add_column("weight", Kind::Weight, Width::signed(8), 2);
    rel.ranges.push(Range {
        name: "weight".to_string(),
        column: weight,
        width: Width::signed(8),
    });
    for selector in [
        ColumnId(u32::MAX),
        ColumnId(0),
        ColumnId(3),
        ColumnId(4),
        public,
        weight,
    ] {
        let mut t = Transcript::new(PUBLIC).expect("public input");
        assert_eq!(
            prove_forged(
                &mut t,
                &rel,
                &values,
                &[],
                Sources::CircleAll,
                &Forge {
                    column_claim: Some(selector),
                    ..Forge::default()
                }
            )
            .err(),
            Some(Error::Unsupported),
            "missing column, unequal neighbour, last column, public or weight selector",
        );
        assert_eq!(
            t.usage(),
            Transcript::<K>::new(PUBLIC).expect("public input").usage()
        );
    }
}

#[cfg(feature = "controls")]
#[test]
fn rejects_unused_forged_column_claim_selector() {
    let (rel, _) = composed();
    let plan = plan(&rel, Sources::CircleAll).expect("plan");
    let claims = Claims(vec![Vec::new(); rel.columns.len()]);
    assert_eq!(
        route_column_claim(
            &plan,
            plan.stack.as_ref().expect("stack"),
            &claims,
            ColumnId(0),
            &mut []
        )
        .err(),
        Some(Error::Unsupported),
    );
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
    let proof = prove_plan(&mut t, &rel, &forged, &committed, &values, &[], None)
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
        prove_plan(&mut t, &rel, &plan, &values, &values, &[], None).err(),
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
        let proof = prove_plan(&mut t, &rel, &plan, &values, &values, &model, None)
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

/// RFC-0026 A12: under `Sources::CircleAll` every multiplicity source is Circle rate
/// 1/4 (A5 blow-up 2) with policy byte 2, the stacked source is A11's, an honest proof
/// verifies, and one verified under A11's set rejects.
#[test]
fn accepts_rate_quarter_multiplicity_sources_and_rejects_the_a11_set() {
    let (rel, values) = batched();
    let (a11, all) = (
        plan(&rel, Sources::Circle).expect("plan"),
        plan(&rel, Sources::CircleAll).expect("plan"),
    );
    let (s, t) = (
        a11.stack.as_ref().expect("stack"),
        all.stack.as_ref().expect("stack"),
    );
    assert_eq!((s.ell, &s.code), (t.ell, &t.code));
    assert_eq!(a11.checks.len(), all.checks.len());
    for (a, b) in a11.checks.iter().zip(&all.checks) {
        assert_eq!((a.layout.blowup, b.layout.blowup), (1, CIRCLE_BLOWUP));
        let code = mu_code(b).expect("code");
        assert_eq!(code.code_id()[20], CIRCLE_BLOWUP);
        let l = b.layout;
        let source = Sources::CircleAll
            .source(l.id, l.ell, code.code_id(), [0; 32])
            .expect("source");
        assert_eq!(source.grind_bits(ProofKind::Certificate).1, 16);
    }
    let mut t = Transcript::new(PUBLIC).expect("transcript");
    let proof = prove(&mut t, &rel, &values, &[], Sources::CircleAll).expect("honest proof");
    let mut t = Transcript::new(PUBLIC).expect("transcript");
    assert!(verify(&mut t, &rel, &[], &proof, Sources::CircleAll).is_ok());
    let mut t = Transcript::new(PUBLIC).expect("transcript");
    assert_eq!(
        verify(&mut t, &rel, &[], &proof, Sources::Circle).err(),
        Some(Error::ProofShape)
    );
}

/// E17-01 (RFC-0018 A2): `prove_measured` emits byte-identical proofs to `prove`,
/// deterministic thread-count-independent counters, and `std`-gated nanosecond timers.
#[test]
fn accepts_measured_proof_with_identical_bytes_and_deterministic_counters() {
    let (rel, values) = batched();
    let mut t1 = Transcript::new(PUBLIC).expect("transcript");
    let plain = prove(&mut t1, &rel, &values, &[], Sources::CircleAll).expect("plain");
    let mut t2 = Transcript::new(PUBLIC).expect("transcript");
    let (measured, metrics) =
        prove_measured(&mut t2, &rel, &values, &[], Sources::CircleAll).expect("measured");
    assert_eq!(measured, plain);
    let expected_cells: u64 = rel
        .columns
        .iter()
        .filter(|c| matches!(c.kind, Kind::Witness(_)))
        .map(|c| 1u64 << c.log_len)
        .sum();
    assert_eq!(metrics.committed_cells, expected_cells);
    assert!(metrics.stacked_source_cells_padded >= expected_cells);
    let check_sum: u64 = metrics.lookup_checks.iter().map(|(_, n)| *n).sum();
    assert_eq!(metrics.lookup_positions, check_sum);
    assert!(metrics.lookup_positions > 0);
    assert_eq!(metrics.weight_reads, 0);
    assert_eq!(metrics.weight_elements_read, 0);
    let sum_len = |v: &[Vec<u8>]| -> u64 { v.iter().map(|s| s.len() as u64).sum() };
    assert_eq!(metrics.groups_bytes, sum_len(&measured.groups));
    assert_eq!(
        metrics.multiplicities_bytes,
        sum_len(&measured.multiplicities)
    );
    assert_eq!(metrics.identities_bytes, sum_len(&measured.identities));
    assert_eq!(metrics.lookups_bytes, sum_len(&measured.lookups));
    assert_eq!(metrics.matmuls_bytes, sum_len(&measured.matmuls));
    assert_eq!(metrics.openings_bytes, sum_len(&measured.openings));
    #[cfg(not(feature = "std"))]
    {
        assert_eq!(metrics.plan_ns, 0);
        assert_eq!(metrics.commitment_ns, 0);
        assert_eq!(metrics.multiplicities_ns, 0);
        assert_eq!(metrics.zerochecks_ns, 0);
        assert_eq!(metrics.lookups_ns, 0);
        assert_eq!(metrics.reductions_ns, 0);
        assert_eq!(metrics.openings_ns, 0);
    }

    // Weight-bearing relation with Range checks only: Step 3 counts + Step 5 originals +
    // Step 7 opening => 3 physical passes over each weight column (16 + 32 = 48 entries × 3 = 144).
    let lengths = [4u8, 5];
    let wrel = weights(&lengths);
    let wvalues = weight_values(&wrel, &lengths);
    let messages = model_messages(&wrel, &wvalues).expect("messages");
    let layouts = model_layout(&wrel, Sources::CircleAll).expect("layout");
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
    let mut t3 = Transcript::new(PUBLIC).expect("transcript");
    let (wproof, wmetrics) =
        prove_measured(&mut t3, &wrel, &wvalues, &model, Sources::CircleAll).expect("wproof");
    let mut t4 = Transcript::new(PUBLIC).expect("transcript");
    let wplain = prove(&mut t4, &wrel, &wvalues, &model, Sources::CircleAll).expect("wplain");
    assert_eq!(wproof, wplain);
    assert_eq!(wmetrics.weight_reads, 3);
    assert_eq!(
        wmetrics.weight_elements_read,
        3 * ((1u64 << 4) + (1u64 << 5))
    );
}

/// E17-01 review F1 & F2: `weight_reads` and `weight_elements_read` count actual physical
/// weight passes without a boolean cap, and RFC-0026 A6 row-blocked matmuls read
/// `2^(w.n) >> fixed_bits` elements per block so `2^f` blocks equal one pass in total.
#[test]
fn matches_reference_weight_reads_for_repeated_and_row_blocked_matmuls() {
    let build_and_measure = |split_max_vars: Option<u8>, repeat: usize| -> Metrics {
        let mut rel = Relation::default();
        let g = Kind::Witness(rel.add_group("G/wmm", 2));
        let x = rel.add_column("x", g.clone(), Width::signed(4), 2);
        let w = rel.add_column("w", Kind::Weight, Width::signed(4), 2);
        let mut outs = Vec::new();
        for r in 0..repeat {
            outs.push(rel.add_column(&alloc::format!("y{r}"), g.clone(), Width::signed(10), 2));
        }
        for (column, name) in [(x, "rx"), (w, "rw")] {
            rel.ranges.push(Range {
                name: name.into(),
                column,
                width: Width::signed(4),
            });
        }
        // Matrix multiply y[i, j] = sum_k x[i, k] * w[j, k] over 2x2 matrices (free=2, summed=1).
        for (r, &y) in outs.iter().enumerate() {
            let mm = stele_ir::relation::Matmul {
                name: alloc::format!("xw_{r}"),
                free: 2,
                summed: 1,
                out: Ref {
                    column: y,
                    vars: vec![0, 1],
                },
                lhs: Ref {
                    column: x,
                    vars: vec![2, 1],
                },
                rhs: Ref {
                    column: w,
                    vars: vec![2, 0],
                },
            };
            match split_max_vars {
                Some(cap) => rel.add_matmul_within(mm, cap),
                None => rel.add_matmul(mm),
            }
        }
        let mut values = Values::new(&rel);
        let xv = vec![1i64, 2, -1, 3];
        let wv = vec![2i64, -1, 1, 2];
        // index = k + 2*row for x and w; index = j + 2*i for y.
        let mut yv = vec![0i64; 4];
        for i in 0..2 {
            for j in 0..2 {
                yv[j + 2 * i] = xv[2 * i] * wv[2 * j] + xv[1 + 2 * i] * wv[1 + 2 * j];
            }
        }
        values.set(&rel, x, xv).expect("x");
        values.set(&rel, w, wv).expect("w");
        for &y in &outs {
            values.set(&rel, y, yv.clone()).expect("y");
        }
        assert_eq!(stele_ir::relation::check(&rel, &values), Ok(()));
        let messages = model_messages(&rel, &values).expect("messages");
        let layouts = model_layout(&rel, Sources::CircleAll).expect("layout");
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
        let (proof, metrics) =
            prove_measured(&mut t, &rel, &values, &model, Sources::CircleAll).expect("prove");
        let refs: Vec<_> = certificates.iter().collect();
        let mut tv = Transcript::new(PUBLIC).expect("transcript");
        assert!(verify(&mut tv, &rel, &refs, &proof, Sources::CircleAll).is_ok());
        metrics
    };

    // Weight `w` has a Range check (Step 3 counts + Step 5 originals = 2 passes) +
    // 1 unblocked matmul (1 pass) + Step 7 opening (1 pass) => 4 passes, 16 elements.
    let single = build_and_measure(None, 1);
    assert_eq!(single.weight_reads, 4);
    assert_eq!(single.weight_elements_read, 16);

    // 2 unblocked matmuls over the same weight column => 5 passes (not capped), 20 elements.
    let double = build_and_measure(None, 2);
    assert_eq!(double.weight_reads, 5);
    assert_eq!(double.weight_elements_read, 20);

    // 1 matmul split into 2 RFC-0026 A6 row blocks (cap = 2 vars): each block reads 4 >> 1 = 2
    // weight elements, summing to 1 matmul pass (4 elements) => 4 passes, 16 elements.
    let blocked = build_and_measure(Some(2), 1);
    assert_eq!(blocked.weight_reads, 4);
    assert_eq!(blocked.weight_elements_read, 16);
}

/// RFC-0026 A27: for a single-segment uncarried relation, `prove_segmented` emits the
/// exact same engine section bytes as RFC-0026 v1 `prove`, and `codec::encode` keeps v1.
#[test]
fn matches_reference_single_segment_messages_equal_v1() {
    let (rel, values) = batched();
    assert!(!rel.is_segmented());
    assert!(codec::encode(&rel).starts_with(b"stele/v0.1/relation/encoding/v1"));

    let mut t1 = Transcript::new(PUBLIC).expect("transcript");
    let v1 = prove(&mut t1, &rel, &values, &[], Sources::CircleAll).expect("v1 prove");
    let mut t2 = Transcript::new(PUBLIC).expect("transcript");
    let v2 = prove_segmented(
        &mut t2,
        &rel,
        |s| {
            assert_eq!(s, 0);
            Ok(values.clone())
        },
        &[],
        Sources::CircleAll,
    )
    .expect("v2 prove");

    assert_eq!(v2.segments.len(), 1);
    assert_eq!(v2.segments[0].groups, v1.groups);
    assert_eq!(v2.segments[0].multiplicities, v1.multiplicities);
    assert_eq!(v2.segments[0].identities, v1.identities);
    assert_eq!(v2.segments[0].lookups, v1.lookups);
    assert_eq!(v2.segments[0].matmuls, v1.matmuls);
    assert!(v2.segments[0].reductions.is_empty());
    assert_eq!(v2.segments[0].openings, v1.openings);
    assert!(v2.model_openings.is_empty());

    let mut tv = Transcript::new(PUBLIC).expect("transcript");
    assert!(verify_segmented(&mut tv, &rel, &[], &v2, Sources::CircleAll).is_ok());
}

fn three_segment_fixture() -> (Relation, Vec<Values>, Values) {
    let mut rel = Relation::default();
    let g0 = Kind::Witness(rel.add_group_in("L0/a/2", 2, 0));
    let g1 = Kind::Witness(rel.add_group_in("L1/a/2", 2, 1));
    let g2 = Kind::Witness(rel.add_group_in("L2/a/2", 2, 2));
    let w = rel.add_column("w", Kind::Weight, Width::signed(8), 2);
    let x0 = rel.add_column("x0", g0.clone(), Width::signed(8), 2);
    let y0 = rel.add_column("y0", g0, Width::signed(8), 2);
    rel.mark_carried(y0);
    let y1 = rel.add_column("y1", g1, Width::signed(8), 2);
    rel.mark_carried(y1);
    let y2 = rel.add_column("y2", g2, Width::signed(17), 2);

    for (c, bits) in [(w, 8), (x0, 8), (y0, 8), (y1, 8)] {
        rel.ranges.push(Range {
            name: alloc::format!("r_{}", c.0),
            column: c,
            width: Width::signed(bits),
        });
    }
    rel.identities.push(Identity {
        name: "s0_id".into(),
        vars: 2,
        terms: vec![
            IdentityTerm {
                coeff: 1,
                factors: vec![Ref::identity(y0, 2)],
            },
            IdentityTerm {
                coeff: -1,
                factors: vec![Ref::identity(x0, 2)],
            },
            IdentityTerm {
                coeff: -1,
                factors: vec![],
            },
        ],
    });
    rel.identities.push(Identity {
        name: "s1_id".into(),
        vars: 2,
        terms: vec![
            IdentityTerm {
                coeff: 1,
                factors: vec![Ref::identity(y1, 2)],
            },
            IdentityTerm {
                coeff: -1,
                factors: vec![Ref::identity(y0, 2)],
            },
            IdentityTerm {
                coeff: -2,
                factors: vec![],
            },
        ],
    });
    // Segment 2 matmul: y2(i, j) = sum_k y1(i, k) * w(j, k)
    rel.add_matmul(stele_ir::relation::Matmul {
        name: "s2_mm".into(),
        free: 2,
        summed: 1,
        out: Ref {
            column: y2,
            vars: vec![0, 1],
        },
        lhs: Ref {
            column: y1,
            vars: vec![2, 1],
        },
        rhs: Ref {
            column: w,
            vars: vec![2, 0],
        },
    });

    let wv = vec![1, 2, -1, 3];
    let x0v = vec![1, 2, 3, 4];
    let y0v = vec![2, 3, 4, 5];
    let y1v = vec![4, 5, 6, 7];
    let mut y2v = vec![0; 4];
    for i in 0..2 {
        for j in 0..2 {
            y2v[j + 2 * i] = y1v[2 * i] * wv[2 * j] + y1v[1 + 2 * i] * wv[1 + 2 * j];
        }
    }

    let mut full = Values::new(&rel);
    full.set(&rel, w, wv.clone()).expect("w");
    full.set(&rel, x0, x0v.clone()).expect("x0");
    full.set(&rel, y0, y0v.clone()).expect("y0");
    full.set(&rel, y1, y1v.clone()).expect("y1");
    full.set(&rel, y2, y2v.clone()).expect("y2");
    assert_eq!(stele_ir::relation::check(&rel, &full), Ok(()));

    let mut v0 = Values::new(&rel);
    v0.set(&rel, w, wv.clone()).expect("w");
    v0.set(&rel, x0, x0v).expect("x0");
    v0.set(&rel, y0, y0v.clone()).expect("y0");

    let mut v1 = Values::new(&rel);
    v1.set(&rel, y0, y0v).expect("y0 carried");
    v1.set(&rel, y1, y1v.clone()).expect("y1");

    let mut v2 = Values::new(&rel);
    v2.set(&rel, w, wv).expect("w");
    v2.set(&rel, y1, y1v).expect("y1 carried");
    v2.set(&rel, y2, y2v).expect("y2");

    for (s, sv) in [(&v0, 0u32), (&v1, 1), (&v2, 2)] {
        assert_eq!(stele_ir::relation::check_segment(&rel, sv, s), Ok(()));
    }
    (rel, vec![v0, v1, v2], full)
}

#[test]
fn accepts_three_segment_relation_and_rejects_root_reorder_and_non_carried() {
    let (rel, seg_vals, full) = three_segment_fixture();
    assert!(rel.is_segmented());
    assert!(codec::encode(&rel).starts_with(b"stele/v0.1/relation/encoding/v2"));
    let messages = model_messages(&rel, &full).expect("messages");

    for sources in [Sources::Expander, Sources::CircleAll] {
        let layouts = model_layout(&rel, sources).expect("layout");
        let prepared: Vec<_> = layouts
            .iter()
            .zip(&messages)
            .map(|(l, m)| l.sources.prepare(l.id, l.ell, &l.code, m).expect("model"))
            .collect();
        let certificates: Vec<_> = prepared
            .iter()
            .map(|p| {
                let (bytes, _) = p.certificate().expect("cert");
                verify_certificate(*p.source(), &bytes).expect("verify").0
            })
            .collect();
        let model: Vec<_> = prepared.iter().zip(&certificates).collect();
        let refs: Vec<_> = certificates.iter().collect();

        let mut t = Transcript::new(PUBLIC).expect("transcript");
        let (proof, metrics) = prove_segmented_measured(
            &mut t,
            &rel,
            |s| Ok(seg_vals[s as usize].clone()),
            &model,
            sources,
        )
        .expect("segmented prove");
        assert_eq!(proof.segments.len(), 3);
        assert_eq!(proof.model_openings.len(), 1);
        assert!(metrics.committed_cells > 0);
        assert!(metrics.weight_reads >= 2);

        // Honest verify succeeds.
        let mut tv = Transcript::new(PUBLIC).expect("transcript");
        assert!(verify_segmented(&mut tv, &rel, &refs, &proof, sources).is_ok());

        // Swapping only the 32-byte roots of segments 0 and 1 rejects with RootMismatch
        // (Policy 1 / Expander) or GrindMismatch (Policy 2 / CircleAll).
        let mut swapped_roots = proof.clone();
        let r0: [u8; 32] = swapped_roots.segments[0].groups[0][..32]
            .try_into()
            .expect("r0");
        let r1: [u8; 32] = swapped_roots.segments[1].groups[0][..32]
            .try_into()
            .expect("r1");
        assert_ne!(r0, r1);
        swapped_roots.segments[0].groups[0][..32].copy_from_slice(&r1);
        swapped_roots.segments[1].groups[0][..32].copy_from_slice(&r0);
        let mut tv = Transcript::new(PUBLIC).expect("transcript");
        let err = verify_segmented(&mut tv, &rel, &refs, &swapped_roots, sources)
            .expect_err("reordered segment roots must reject");
        match sources {
            Sources::Expander => assert_eq!(
                err,
                Error::Pcs(stele_pcs::Error::Merkle(
                    stele_hash::merkle::Error::RootMismatch
                ))
            ),
            _ => assert_eq!(
                err,
                Error::Pcs(stele_pcs::Error::Transcript(
                    stele_hash::Error::GrindMismatch
                ))
            ),
        }

        // Swapping entire (root, cert) group sections also rejects (segment source_id mismatch).
        let mut swapped_certs = proof.clone();
        let g0 = swapped_certs.segments[0].groups[0].clone();
        let g1 = swapped_certs.segments[1].groups[0].clone();
        swapped_certs.segments[0].groups[0] = g1;
        swapped_certs.segments[1].groups[0] = g0;
        let mut tv = Transcript::new(PUBLIC).expect("transcript");
        assert!(verify_segmented(&mut tv, &rel, &refs, &swapped_certs, sources).is_err());

        // Unexpected non-empty `reductions` rejects with ProofShape.
        let mut extra_red = proof.clone();
        extra_red.segments[0].reductions.push(vec![0u8; 4]);
        let mut tv = Transcript::new(PUBLIC).expect("transcript");
        assert_eq!(
            verify_segmented(&mut tv, &rel, &refs, &extra_red, sources).err(),
            Some(Error::ProofShape)
        );
    }

    // Tampering the relation so segment 1 reads non-carried `x0` rejects with StatementMismatch(Segment).
    let mut bad_rel = rel;
    bad_rel.identities[1].terms[1].factors[0] = Ref::identity(ColumnId(1), 2);
    let mut tv = Transcript::new(PUBLIC).expect("transcript");
    let empty_proof = ProofV2::default();
    assert!(matches!(
        verify_segmented(&mut tv, &bad_rel, &[], &empty_proof, Sources::CircleAll),
        Err(Error::StatementMismatch(Invalid::Segment { .. }))
    ));
}

/// RFC-0026 A28 / RFC-0028 (E18-02): v1 `prove`/`verify` rejects virtual relations with
/// `Unsupported`, `prove_segmented`/`verify_segmented` rejects `Pointwise`/`Contraction`
/// until E18-03/E18-04, and `relation_codec::encode` distinguishes virtual defs cleanly.
#[test]
fn rejects_unsupported_virtual_kinds_and_encodes_distinctly() {
    use stele_ir::relation::Def;

    let mut rel = Relation::default();
    let g = Kind::Witness(rel.add_group("G/v/1", 1));
    let x = rel.add_column("x", g, Width::signed(8), 1);
    rel.ranges.push(Range {
        name: "rx".into(),
        column: x,
        width: Width::signed(8),
    });
    let _v = rel.add_virtual(
        "v",
        Def::Linear {
            constant: 1,
            terms: vec![(2, Ref::identity(x, 1))],
        },
        1,
    );
    assert_eq!(rel.validate(), Ok(()));

    let mut vals = Values::new(&rel);
    vals.set(&rel, x, vec![3, -4]).expect("set");
    // Unsegmented v1 engine still rejects virtual relations (RFC-0028 §2.5 uses ProofV2).
    let mut t = Transcript::new(PUBLIC).expect("transcript");
    assert_eq!(
        prove(&mut t, &rel, &vals, &[], Sources::Expander).err(),
        Some(Error::Unsupported)
    );
    let mut tv = Transcript::new(PUBLIC).expect("transcript");
    assert_eq!(
        verify(&mut tv, &rel, &[], &Proof::default(), Sources::Expander).err(),
        Some(Error::Unsupported)
    );
    // dev-zk layout also rejects virtual relations cleanly without panicking.
    assert_eq!(
        crate::zk::relation::layout(&rel).err(),
        Some(crate::zk::Error::Statement)
    );

    // Pointwise and Contraction stay `Error::Unsupported` in `prove_segmented`/`verify_segmented`
    // until E18-03/E18-04.
    let mut rel_pw = rel.clone();
    rel_pw.columns[1].kind = Kind::Virtual(Def::Pointwise {
        terms: vec![IdentityTerm {
            coeff: 1,
            factors: vec![Ref::identity(x, 1), Ref::identity(x, 1)],
        }],
    });
    assert_eq!(rel_pw.validate(), Ok(()));
    let mut ts = Transcript::new(PUBLIC).expect("transcript");
    assert_eq!(
        prove_segmented(
            &mut ts,
            &rel_pw,
            |_| Ok(vals.clone()),
            &[],
            Sources::CircleAll
        )
        .err(),
        Some(Error::Unsupported)
    );
    let mut tvs = Transcript::new(PUBLIC).expect("transcript");
    assert_eq!(
        verify_segmented(
            &mut tvs,
            &rel_pw,
            &[],
            &ProofV2::default(),
            Sources::CircleAll
        )
        .err(),
        Some(Error::Unsupported)
    );

    let mut rel_ct = rel.clone();
    rel_ct.columns[1].kind = Kind::Virtual(Def::Contraction {
        free: 1,
        summed: 0,
        lhs: Ref::identity(x, 1),
        rhs: Ref::identity(x, 1),
    });
    assert_eq!(rel_ct.validate(), Ok(()));
    let mut ts = Transcript::new(PUBLIC).expect("transcript");
    assert_eq!(
        prove_segmented(
            &mut ts,
            &rel_ct,
            |_| Ok(vals.clone()),
            &[],
            Sources::CircleAll
        )
        .err(),
        Some(Error::Unsupported)
    );

    let enc1 = super::codec::encode(&rel);
    let mut rel2 = rel.clone();
    rel2.columns[1].kind = Kind::Virtual(Def::Linear {
        constant: 2,
        terms: vec![(2, Ref::identity(x, 1))],
    });
    let enc2 = super::codec::encode(&rel2);
    assert_ne!(enc1, enc2);
    assert!(enc1.starts_with(b"stele/v0.1/relation/encoding/v2"));

    // Unsegmented non-virtual relations retain the v1 magic prefix.
    let mut plain = Relation::default();
    let gp = Kind::Witness(plain.add_group("G/p/1", 1));
    let px = plain.add_column("x", gp, Width::signed(8), 1);
    plain.ranges.push(Range {
        name: "rx".into(),
        column: px,
        width: Width::signed(8),
    });
    assert!(super::codec::encode(&plain).starts_with(b"stele/v0.1/relation/encoding/v1"));
    plain.mark_carried(px);
    assert!(super::codec::encode(&plain).starts_with(b"stele/v0.1/relation/encoding/v2"));
    assert_eq!(
        crate::zk::relation::layout(&plain).err(),
        Some(crate::zk::Error::Statement)
    );
}

/// RFC-0028 §2.4 & RFC-0026 A28 (task E18-02): honest segmented proofs with chained `Linear`
/// virtual columns, lookups and ranges reading virtual columns, carried cross-segment
/// operands, weight/public operands, and unclaimed virtual columns, plus NC-1337 and NC-1338.
#[test]
fn accepts_linear_virtual_columns_and_rejects_nc_1337_and_nc_1338() {
    use stele_ir::relation::Def;

    let mut rel = Relation::default();
    let g0 = rel.add_group_in("s0/w", 2, 0);
    let g1 = rel.add_group_in("s1/w", 2, 1);

    // Segment 0: witness limbs lo (u8), hi (u4), carried witness c0 (s16), public bias p0.
    let lo = rel.add_column("s0/lo", Kind::Witness(g0), Width::unsigned(8), 2);
    let hi = rel.add_column("s0/hi", Kind::Witness(g0), Width::unsigned(4), 2);
    let c0 = rel.add_column("s0/c0", Kind::Witness(g0), Width::signed(16), 2);
    rel.mark_carried(c0);
    let p0 = rel.add_column(
        "s0/bias",
        Kind::Public(vec![1, 2, 3, 4]),
        Width::unsigned(4),
        2,
    );
    let w = rel.add_column("w", Kind::Weight, Width::signed(8), 2);
    for (name, col, width) in [
        ("r_lo", lo, Width::unsigned(8)),
        ("r_hi", hi, Width::unsigned(4)),
        ("r_c0", c0, Width::signed(16)),
        ("r_w", w, Width::signed(8)),
    ] {
        rel.ranges.push(Range {
            name: name.into(),
            column: col,
            width,
        });
    }
    // Chained Linear virtual columns in segment 0:
    // v1 = lo + 256 * hi (virtual Compose target)
    let v1 = rel.add_virtual(
        "s0/v1",
        Def::Linear {
            constant: 0,
            terms: vec![(1, Ref::identity(lo, 2)), (256, Ref::identity(hi, 2))],
        },
        2,
    );
    // v2 = 5 + v1 - p0 (chained Linear reading virtual v1 + public p0, read by identity + range)
    let v2 = rel.add_virtual(
        "s0/v2",
        Def::Linear {
            constant: 5,
            terms: vec![(1, Ref::identity(v1, 2)), (-1, Ref::identity(p0, 2))],
        },
        2,
    );
    // Unclaimed Linear virtual column in segment 0 (must emit 0 reduction sections).
    let _unused = rel.add_virtual(
        "s0/unused",
        Def::Linear {
            constant: 3,
            terms: vec![(2, Ref::identity(lo, 2))],
        },
        2,
    );
    // Identity in segment 0 equating carried c0 to v2: c0 - v2 = 0.
    rel.identities.push(Identity {
        name: "s0/carry_eq".into(),
        vars: 2,
        terms: vec![
            IdentityTerm {
                coeff: 1,
                factors: vec![Ref::identity(c0, 2)],
            },
            IdentityTerm {
                coeff: -1,
                factors: vec![Ref::identity(v2, 2)],
            },
        ],
    });
    // Range check directly on virtual column v2 (RFC-0026 A28).
    rel.ranges.push(Range {
        name: "s0/r_v2".into(),
        column: v2,
        width: Width::unsigned(13),
    });

    // Segment 1: witness y1 (s16), Linear v3 reading carried c0 + weight w + reversed y1.
    let y1 = rel.add_column("s1/y1", Kind::Witness(g1), Width::signed(16), 2);
    rel.ranges.push(Range {
        name: "s1/r_y1".into(),
        column: y1,
        width: Width::signed(16),
    });
    let v3 = rel.add_virtual(
        "s1/v3",
        Def::Linear {
            constant: -2,
            terms: vec![
                (1, Ref::identity(c0, 2)),
                (3, Ref::identity(w, 2)),
                (
                    1,
                    Ref {
                        column: y1,
                        vars: vec![1, 0],
                    },
                ),
            ],
        },
        2,
    );
    // Table lookup directly on virtual column v3 (RFC-0008 A9, RFC-0026 A28).
    let lo_vals = vec![10i64, 20, 30, 40];
    let hi_vals = vec![1i64, 2, 0, 3];
    let p0_vals = [1i64, 2, 3, 4];
    let v2_vals: Vec<i64> = (0..4)
        .map(|i| 5 + lo_vals[i] + 256 * hi_vals[i] - p0_vals[i])
        .collect();
    let w_vals = vec![2i64, -1, 4, 0];
    let y1_vals = vec![10i64, 20, 30, 40];
    let v3_vals: Vec<i64> = (0..4)
        .map(|i| {
            let rev = ((i & 1) << 1) | ((i >> 1) & 1);
            -2 + v2_vals[i] + 3 * w_vals[i] + y1_vals[rev]
        })
        .collect();
    let mut table_rows: Vec<Vec<i64>> = v3_vals.iter().map(|&v| vec![v]).collect();
    table_rows.sort_unstable();
    table_rows.dedup();
    let tbl = rel.add_table(Table {
        name: "v3_tbl".into(),
        widths: vec![Width::signed(16)],
        rows: table_rows,
    });
    rel.lookups.push(Lookup {
        name: "s1/v3_lu".into(),
        vars: 2,
        selector: None,
        tuple: vec![Ref::identity(v3, 2)],
        table: tbl,
    });
    assert_eq!(rel.validate(), Ok(()));

    let mut all_vals = Values::new(&rel);
    all_vals.set(&rel, lo, lo_vals).expect("lo");
    all_vals.set(&rel, hi, hi_vals).expect("hi");
    all_vals.set(&rel, c0, v2_vals).expect("c0");
    all_vals.set(&rel, w, w_vals).expect("w");
    all_vals.set(&rel, y1, y1_vals).expect("y1");
    assert_eq!(stele_ir::relation::check(&rel, &all_vals), Ok(()));

    let sources = Sources::CircleAll;
    let model_msgs = model_messages(&rel, &all_vals).expect("model msgs");
    let model_layouts = model_layout(&rel, sources).expect("model layouts");
    let prepared_models: Vec<_> = model_layouts
        .iter()
        .zip(&model_msgs)
        .map(|(l, m)| {
            let p = sources.prepare(l.id, l.ell, &l.code, m).expect("prepare");
            let (cert, _) = p.certificate().expect("cert");
            let (handle, _) = verify_certificate(*p.source(), &cert).expect("verify cert");
            (p, handle)
        })
        .collect();
    let model_prove: Vec<_> = prepared_models.iter().map(|(p, h)| (p, h)).collect();
    let model_verify: Vec<_> = prepared_models.iter().map(|(_, h)| h).collect();

    let mut tp = Transcript::new(PUBLIC).expect("transcript");
    let (proof, metrics) = prove_segmented_measured(
        &mut tp,
        &rel,
        |_| Ok(all_vals.clone()),
        &model_prove,
        sources,
    )
    .expect("prove");
    // Unclaimed `_unused` emits no reduction section: seg 0 has 2 (v2, v1), seg 1 has 1 (v3).
    assert_eq!(proof.segments[0].reductions.len(), 2);
    assert_eq!(proof.segments[1].reductions.len(), 1);
    // Committed cells include only witness columns (lo, hi, c0, y1 = 4 * 4 = 16), never virtuals.
    assert_eq!(metrics.committed_cells, 16);

    let mut tv = Transcript::new(PUBLIC).expect("transcript");
    let _ledger = verify_segmented(&mut tv, &rel, &model_verify, &proof, sources).expect("verify");

    // --- NC-1337: +1 on one operand evaluation in a Linear reduction rejects with LinearMismatch.
    let mut bad_nc1337 = proof.clone();
    let sec = &mut bad_nc1337.segments[0].reductions[0];
    let orig = K::from_le_bytes(sec[..16].try_into().expect("16")).expect("k");
    sec[..16].copy_from_slice(&(orig + K::from_i64(1)).to_le_bytes());
    let mut tv = Transcript::new(PUBLIC).expect("transcript");
    assert_eq!(
        verify_segmented(&mut tv, &rel, &model_verify, &bad_nc1337, sources).err(),
        Some(Error::LinearMismatch(v2))
    );

    // ProofShape checks on reductions section: truncated, dropped section.
    let mut short = proof.clone();
    short.segments[0].reductions[0].pop();
    let mut tv = Transcript::new(PUBLIC).expect("transcript");
    assert_eq!(
        verify_segmented(&mut tv, &rel, &model_verify, &short, sources).err(),
        Some(Error::ProofShape)
    );
    let mut dropped = proof.clone();
    dropped.segments[1].reductions.clear();
    let mut tv = Transcript::new(PUBLIC).expect("transcript");
    assert_eq!(
        verify_segmented(&mut tv, &rel, &model_verify, &dropped, sources).err(),
        Some(Error::ProofShape)
    );

    // --- NC-1338: malicious prover commits `out[0] = v[0] + 1` and proves with a forged
    // virtual table `v'[0] = v[0] + 1` so the consuming identity `out - v = 0` succeeds.
    // Direct variant sends honest operand evals -> verifier rejects with `LinearMismatch(v)`.
    // Adaptive variant lies on operand 0 to pass `Linear` -> verifier rejects at opening.
    let mut r_nc = Relation::default();
    let g_nc = r_nc.add_group_in("nc/w", 2, 0);
    let nc_lo = r_nc.add_column("nc/lo", Kind::Witness(g_nc), Width::unsigned(8), 2);
    let nc_hi = r_nc.add_column("nc/hi", Kind::Witness(g_nc), Width::unsigned(4), 2);
    let nc_out = r_nc.add_column("nc/out", Kind::Witness(g_nc), Width::unsigned(13), 2);
    for (n, col, w) in [
        ("r_lo", nc_lo, Width::unsigned(8)),
        ("r_hi", nc_hi, Width::unsigned(4)),
        ("r_out", nc_out, Width::unsigned(13)),
    ] {
        r_nc.ranges.push(Range {
            name: n.into(),
            column: col,
            width: w,
        });
    }
    let nc_v = r_nc.add_virtual(
        "nc/v",
        Def::Linear {
            constant: 0,
            terms: vec![(1, Ref::identity(nc_lo, 2)), (256, Ref::identity(nc_hi, 2))],
        },
        2,
    );
    r_nc.identities.push(Identity {
        name: "nc/eq".into(),
        vars: 2,
        terms: vec![
            IdentityTerm {
                coeff: 1,
                factors: vec![Ref::identity(nc_out, 2)],
            },
            IdentityTerm {
                coeff: -1,
                factors: vec![Ref::identity(nc_v, 2)],
            },
        ],
    });
    assert_eq!(r_nc.validate(), Ok(()));
    let mut forged_vals = Values::new(&r_nc);
    forged_vals
        .set(&r_nc, nc_lo, vec![10, 20, 30, 40])
        .expect("lo");
    forged_vals.set(&r_nc, nc_hi, vec![1, 2, 0, 3]).expect("hi");
    // Forged `nc_out[0] = 267` (honest is 266), matching forged `nc_v'[0] = 267`.
    forged_vals
        .set(&r_nc, nc_out, vec![267, 532, 30, 808])
        .expect("forged out");

    let mut tp = Transcript::new(PUBLIC).expect("transcript");
    let forged_direct = prove_segmented_forged_virtual(
        &mut tp,
        &r_nc,
        |_| Ok(forged_vals.clone()),
        &[],
        sources,
        nc_v,
        0,
        None,
    )
    .expect("forged direct");
    let mut tv = Transcript::new(PUBLIC).expect("transcript");
    assert_eq!(
        verify_segmented(&mut tv, &r_nc, &[], &forged_direct, sources).err(),
        Some(Error::LinearMismatch(nc_v))
    );

    // Adaptive NC-1338 compensating witness operand `nc_lo` passes Step 2.4 Linear check
    // and pushes the forged claim onto `nc_lo`, where the honest PCS opening prover itself
    // refuses to open a false claim (`Sumcheck(RoundSumMismatch)`).
    let mut tp = Transcript::new(PUBLIC).expect("transcript");
    assert!(matches!(
        prove_segmented_forged_virtual(
            &mut tp,
            &r_nc,
            |_| Ok(forged_vals.clone()),
            &[],
            sources,
            nc_v,
            0,
            Some(0),
        ),
        Err(Error::Sumcheck(stele_sumcheck::Error::RoundSumMismatch))
    ));

    // Adaptive NC-1338 compensating a Public operand passes Step 2.4 Linear check and
    // rejects at `PublicMismatch(pub_col)`, directly exercising downstream claim dispatch.
    let mut r_pub = Relation::default();
    let g_pub = r_pub.add_group_in("pub/w", 2, 0);
    let p_lo = r_pub.add_column("pub/lo", Kind::Witness(g_pub), Width::unsigned(8), 2);
    let p_pub = r_pub.add_column(
        "pub/c",
        Kind::Public(vec![1, 2, 3, 4]),
        Width::unsigned(4),
        2,
    );
    let p_out = r_pub.add_column("pub/out", Kind::Witness(g_pub), Width::unsigned(10), 2);
    for (n, col, w) in [
        ("r_lo", p_lo, Width::unsigned(8)),
        ("r_out", p_out, Width::unsigned(10)),
    ] {
        r_pub.ranges.push(Range {
            name: n.into(),
            column: col,
            width: w,
        });
    }
    let p_v = r_pub.add_virtual(
        "pub/v",
        Def::Linear {
            constant: 0,
            terms: vec![(1, Ref::identity(p_lo, 2)), (1, Ref::identity(p_pub, 2))],
        },
        2,
    );
    r_pub.identities.push(Identity {
        name: "pub/eq".into(),
        vars: 2,
        terms: vec![
            IdentityTerm {
                coeff: 1,
                factors: vec![Ref::identity(p_out, 2)],
            },
            IdentityTerm {
                coeff: -1,
                factors: vec![Ref::identity(p_v, 2)],
            },
        ],
    });
    assert_eq!(r_pub.validate(), Ok(()));
    let mut p_vals = Values::new(&r_pub);
    p_vals.set(&r_pub, p_lo, vec![10, 20, 30, 40]).expect("lo");
    // Forged `p_out[0] = 12` (honest is 11 = 10 + 1).
    p_vals
        .set(&r_pub, p_out, vec![12, 22, 33, 44])
        .expect("out");
    let mut tp = Transcript::new(PUBLIC).expect("transcript");
    let forged_pub = prove_segmented_forged_virtual(
        &mut tp,
        &r_pub,
        |_| Ok(p_vals.clone()),
        &[],
        sources,
        p_v,
        0,
        Some(1),
    )
    .expect("forged pub");
    let mut tv = Transcript::new(PUBLIC).expect("transcript");
    assert_eq!(
        verify_segmented(&mut tv, &r_pub, &[], &forged_pub, sources).err(),
        Some(Error::PublicMismatch(p_pub))
    );

    // Noncanonical QM31 limb (p = 2^31 - 1) in a Linear reduction section -> NoncanonicalField.
    let mut noncanon = proof.clone();
    noncanon.segments[0].reductions[0][..4].copy_from_slice(&((1u32 << 31) - 1).to_le_bytes());
    let mut tv = Transcript::new(PUBLIC).expect("transcript");
    assert_eq!(
        verify_segmented(&mut tv, &rel, &model_verify, &noncanon, sources).err(),
        Some(Error::NoncanonicalField)
    );
}

/// RFC-0026 A28 & RFC-0028 §2.4 (E18-02): white-box transcript binding of `absorb_linear_evals`
/// and `absorb_virtual_members` (no-op when no virtual member is present; shifts challenge
/// whenever a virtual member or sent operand evaluation changes).
#[test]
fn accepts_linear_transcript_binding_and_nonvirtual_parity() {
    use stele_hash::ChallengeLabel;

    let mut rel = Relation::default();
    let g = rel.add_group_in("g", 1, 0);
    let x = rel.add_column("x", Kind::Witness(g), Width::unsigned(4), 1);
    let v = rel.add_virtual(
        "v",
        stele_ir::relation::Def::Linear {
            constant: 1,
            terms: vec![(2, Ref::identity(x, 1))],
        },
        1,
    );
    rel.ranges.push(Range {
        name: "rx".into(),
        column: x,
        width: Width::unsigned(4),
    });
    rel.ranges.push(Range {
        name: "rv".into(),
        column: v,
        width: Width::unsigned(5),
    });
    let plan = super::plan_segmented(&rel, Sources::CircleAll).expect("plan");
    let checks = &plan.segments[0].checks;
    let nonvirt_check = checks
        .iter()
        .find(|c| c.members.iter().all(|m| m.tuple[0].0.column == x))
        .expect("nonvirt check");
    let virt_check = checks
        .iter()
        .find(|c| c.members.iter().any(|m| m.tuple[0].0.column == v))
        .expect("virt check");

    // Non-virtual member list must leave the transcript bit-identical (RFC-0026 A28).
    let mut t_base = Transcript::<K>::new(PUBLIC).expect("t");
    let mut t_nonvirt = Transcript::<K>::new(PUBLIC).expect("t");
    super::lookup::absorb_virtual_members(&mut t_nonvirt, nonvirt_check, &rel, &[K::from_i64(7)])
        .expect("absorb");
    let c_base = t_base.challenge(ChallengeLabel::LookupBeta).expect("c");
    let c_nonvirt = t_nonvirt.challenge(ChallengeLabel::LookupBeta).expect("c");
    assert_eq!(c_base, c_nonvirt);

    // Virtual member list must bind the transcript and shift when the member value changes.
    let mut t_v1 = Transcript::<K>::new(PUBLIC).expect("t");
    let mut t_v2 = Transcript::<K>::new(PUBLIC).expect("t");
    super::lookup::absorb_virtual_members(&mut t_v1, virt_check, &rel, &[K::from_i64(7)])
        .expect("absorb");
    super::lookup::absorb_virtual_members(&mut t_v2, virt_check, &rel, &[K::from_i64(8)])
        .expect("absorb");
    let c_v1 = t_v1.challenge(ChallengeLabel::LookupBeta).expect("c");
    let c_v2 = t_v2.challenge(ChallengeLabel::LookupBeta).expect("c");
    assert_ne!(c_base, c_v1);
    assert_ne!(c_v1, c_v2);

    // `absorb_linear_evals` must bind every operand evaluation.
    let mut t_e1 = Transcript::<K>::new(PUBLIC).expect("t");
    let mut t_e2 = Transcript::<K>::new(PUBLIC).expect("t");
    super::absorb_linear_evals(&mut t_e1, v, 0, &[K::from_i64(7), K::from_i64(11)]).expect("e1");
    super::absorb_linear_evals(&mut t_e2, v, 0, &[K::from_i64(7), K::from_i64(12)]).expect("e2");
    assert_ne!(
        t_e1.challenge(ChallengeLabel::LookupBeta).expect("c1"),
        t_e2.challenge(ChallengeLabel::LookupBeta).expect("c2")
    );
}

/// RFC-0028 §2.4 (E18-02): edge cases — broadcast `Ref`, constant-only `Def::Linear` on
/// `log_len == 0`, bogus `Values` entries on virtual columns ignored, overflow rejected with
/// `Error::Capacity`, and `prove_segmented_forged_virtual` rejecting invalid targets.
#[test]
fn accepts_linear_edge_cases_and_rejects_overflow_or_bad_forge_target() {
    use stele_ir::relation::Def;

    let mut rel = Relation::default();
    let g1 = rel.add_group_in("edge/w1", 1, 0);
    let g2 = rel.add_group_in("edge/w2", 2, 0);
    let g0 = rel.add_group_in("edge/w0", 0, 0);
    // 1-var witness column broadcast into a 2-var virtual column (`vars: vec![0]`).
    let a = rel.add_column("edge/a", Kind::Witness(g1), Width::unsigned(4), 1);
    let b = rel.add_column("edge/b", Kind::Witness(g2), Width::unsigned(8), 2);
    let s = rel.add_column("edge/s", Kind::Witness(g0), Width::unsigned(4), 0);
    for (n, col, w) in [
        ("ra", a, Width::unsigned(4)),
        ("rb", b, Width::unsigned(8)),
        ("rs", s, Width::unsigned(4)),
    ] {
        rel.ranges.push(Range {
            name: n.into(),
            column: col,
            width: w,
        });
    }
    let v_bcast = rel.add_virtual(
        "edge/v_bcast",
        Def::Linear {
            constant: 3,
            terms: vec![(
                2,
                Ref {
                    column: a,
                    vars: vec![0],
                },
            )],
        },
        2,
    );
    let v_const0 = rel.add_virtual(
        "edge/v_const0",
        Def::Linear {
            constant: 7,
            terms: vec![],
        },
        0,
    );
    rel.identities.push(Identity {
        name: "edge/eq_bcast".into(),
        vars: 2,
        terms: vec![
            IdentityTerm {
                coeff: 1,
                factors: vec![Ref::identity(b, 2)],
            },
            IdentityTerm {
                coeff: -1,
                factors: vec![Ref::identity(v_bcast, 2)],
            },
        ],
    });
    rel.identities.push(Identity {
        name: "edge/eq_const0".into(),
        vars: 0,
        terms: vec![
            IdentityTerm {
                coeff: 1,
                factors: vec![Ref::identity(s, 0)],
            },
            IdentityTerm {
                coeff: -1,
                factors: vec![Ref::identity(v_const0, 0)],
            },
        ],
    });
    assert_eq!(rel.validate(), Ok(()));

    let mut vals = Values::new(&rel);
    vals.set(&rel, a, vec![2, 5]).expect("a");
    // Ref { column: a, vars: [0] } maps x in 0..4 to bit 0 of x: [a[0], a[1], a[0], a[1]].
    vals.set(&rel, b, vec![7, 13, 7, 13]).expect("b");
    vals.set(&rel, s, vec![7]).expect("s");
    assert_eq!(stele_ir::relation::check(&rel, &vals), Ok(()));

    let sources = Sources::CircleAll;
    let mut tp = Transcript::new(PUBLIC).expect("t");
    let p1 = prove_segmented(&mut tp, &rel, |_| Ok(vals.clone()), &[], sources).expect("prove");
    let mut tv = Transcript::new(PUBLIC).expect("t");
    verify_segmented(&mut tv, &rel, &[], &p1, sources).expect("verify");

    // Populate a bogus Values slot for virtual column `v_bcast`: ResolvedColumns must ignore it
    // and produce a bit-identical proof.
    let mut vals_with_bogus = vals.clone();
    vals_with_bogus
        .set(&rel, v_bcast, vec![99, 99, 99, 99])
        .expect("set bogus");
    let mut tp2 = Transcript::new(PUBLIC).expect("t");
    let p2 = prove_segmented(
        &mut tp2,
        &rel,
        |_| Ok(vals_with_bogus.clone()),
        &[],
        sources,
    )
    .expect("prove2");
    assert_eq!(p1.segments.len(), p2.segments.len());
    assert_eq!(p1.segments[0].reductions, p2.segments[0].reductions);
    assert_eq!(p1.segments[0].identities, p2.segments[0].identities);

    // ResolvedColumns::get must refuse to fall back to `Values` for an uncomputed virtual column.
    let empty_resolved =
        super::ResolvedColumns::for_segment(&rel, &vals_with_bogus, &[]).expect("empty virtuals");
    assert_eq!(
        empty_resolved.get(v_bcast).err(),
        Some(Error::Missing(v_bcast))
    );

    // `prove_segmented_forged_virtual` rejects non-virtual target and invalid term index.
    let mut tp_bad = Transcript::new(PUBLIC).expect("t");
    assert_eq!(
        prove_segmented_forged_virtual(
            &mut tp_bad,
            &rel,
            |_| Ok(vals.clone()),
            &[],
            sources,
            b,
            0,
            None,
        )
        .err(),
        Some(Error::Unsupported)
    );
    let mut tp_bad2 = Transcript::new(PUBLIC).expect("t");
    assert_eq!(
        prove_segmented_forged_virtual(
            &mut tp_bad2,
            &rel,
            |_| Ok(vals.clone()),
            &[],
            sources,
            v_bcast,
            0,
            Some(9),
        )
        .err(),
        Some(Error::Unsupported)
    );

    // Overflow during materialization must return `Error::Capacity`, not silently truncate.
    let mut r_ovf = Relation::default();
    let g_ovf = r_ovf.add_group_in("ovf/w", 1, 0);
    let ox = r_ovf.add_column("ovf/x", Kind::Witness(g_ovf), Width::signed(8), 1);
    let ov = r_ovf.add_virtual(
        "ovf/v",
        Def::Linear {
            constant: 0,
            terms: vec![(i64::MAX, Ref::identity(ox, 1))],
        },
        1,
    );
    let mut ovf_vals = Values::new(&r_ovf);
    ovf_vals.set(&r_ovf, ox, vec![2, 0]).expect("ox");
    assert_eq!(
        super::ResolvedColumns::for_segment(&r_ovf, &ovf_vals, &[ov]).err(),
        Some(Error::Capacity)
    );
}

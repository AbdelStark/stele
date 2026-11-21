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

    // Distinct virtual definitions encode distinctly under `stele/v0.1/relation/encoding/v2`.
    let mut rel_pw = rel.clone();
    rel_pw.columns[1].kind = Kind::Virtual(Def::Pointwise {
        terms: vec![IdentityTerm {
            coeff: 1,
            factors: vec![Ref::identity(x, 1), Ref::identity(x, 1)],
        }],
    });
    assert_eq!(rel_pw.validate(), Ok(()));
    assert_ne!(super::codec::encode(&rel), super::codec::encode(&rel_pw));

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
    let empty_resolved = super::ResolvedColumns::for_segment(&rel, &vals_with_bogus, &[], None)
        .expect("empty virtuals");
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
        super::ResolvedColumns::for_segment(&r_ovf, &ovf_vals, &[ov], None).err(),
        Some(Error::Capacity)
    );
}

/// RFC-0028 §2.4 & RFC-0012 A19 (task E18-03): virtual `Def::Contraction` columns with
/// single-claim (no batching) and multi-claim (RFC-0006 A2 mode 1 batching), exact partial
/// evaluation counters (`contraction_partial_evals == 2 * contractions_reduced`), shared free
/// bits (`eq` check + `EqMismatch`), self-operand & row-blocked `Ref::FIXED_0/1` contractions,
/// chained `Linear -> Contraction -> Linear` across segments, `free == 0`/`summed == 0` and
/// unclaimed edge cases, overflow (`Error::Capacity`), NC-1307, and direct/adaptive NC-1338.
#[test]
fn accepts_contraction_virtual_columns_and_rejects_nc_1307_and_nc_1338() {
    use stele_ir::relation::Def;

    // --- Part 1: Single-claim vs multi-claim standard matmul C[t, o] = sum_i A[t, i] * W[o, i]
    // Domain: t in 0..2 (bit 0), o in 0..2 (bit 1), i in 0..4 (bits 2..4); free = 2, summed = 2.
    let build_matmul_rel = |multi_claim: bool| {
        let mut rel = Relation::default();
        let g = rel.add_group_in("mm/w", 3, 0);
        let g_out = rel.add_group_in("mm/out", 2, 0);
        // A[t, i]: log_len = 3 (bit 0 = t, bits 1..3 = i)
        let a = rel.add_column("mm/A", Kind::Witness(g), Width::signed(8), 3);
        // W[o, i]: log_len = 3 (bit 0 = o, bits 1..3 = i)
        let w = rel.add_column("mm/W", Kind::Weight, Width::signed(8), 3);
        // Committed witness `y` checked against virtual contraction `c`.
        let y = rel.add_column("mm/y", Kind::Witness(g_out), Width::signed(16), 2);
        for (name, col, width) in [
            ("r_a", a, Width::signed(8)),
            ("r_w", w, Width::signed(8)),
            ("r_y", y, Width::signed(16)),
        ] {
            rel.ranges.push(Range {
                name: name.into(),
                column: col,
                width,
            });
        }
        let c = rel.add_virtual(
            "mm/C",
            Def::Contraction {
                free: 2,
                summed: 2,
                lhs: Ref {
                    column: a,
                    vars: vec![0, 2, 3],
                },
                rhs: Ref {
                    column: w,
                    vars: vec![1, 2, 3],
                },
            },
            2,
        );
        // Unclaimed Contraction: must emit 0 reduction sections and 0 partial evals.
        let _unclaimed = rel.add_virtual(
            "mm/unclaimed",
            Def::Contraction {
                free: 2,
                summed: 2,
                lhs: Ref {
                    column: a,
                    vars: vec![0, 2, 3],
                },
                rhs: Ref {
                    column: w,
                    vars: vec![1, 2, 3],
                },
            },
            2,
        );
        // Claim 1: identity y - C = 0.
        rel.identities.push(Identity {
            name: "mm/eq".into(),
            vars: 2,
            terms: vec![
                IdentityTerm {
                    coeff: 1,
                    factors: vec![Ref::identity(y, 2)],
                },
                IdentityTerm {
                    coeff: -1,
                    factors: vec![Ref::identity(c, 2)],
                },
            ],
        });
        if multi_claim {
            // Claim 2: range check directly on virtual contraction C.
            rel.ranges.push(Range {
                name: "mm/r_c".into(),
                column: c,
                width: Width::signed(16),
            });
            // Claim 3: Linear virtual column reading C, read by a second identity.
            let c_plus = rel.add_virtual(
                "mm/C_plus1",
                Def::Linear {
                    constant: 1,
                    terms: vec![(1, Ref::identity(c, 2))],
                },
                2,
            );
            let y2 = rel.add_column("mm/y2", Kind::Witness(g_out), Width::signed(16), 2);
            rel.ranges.push(Range {
                name: "r_y2".into(),
                column: y2,
                width: Width::signed(16),
            });
            rel.identities.push(Identity {
                name: "mm/eq2".into(),
                vars: 2,
                terms: vec![
                    IdentityTerm {
                        coeff: 1,
                        factors: vec![Ref::identity(y2, 2)],
                    },
                    IdentityTerm {
                        coeff: -1,
                        factors: vec![Ref::identity(c_plus, 2)],
                    },
                ],
            });
            (rel, a, w, y, Some(y2), c)
        } else {
            (rel, a, w, y, None, c)
        }
    };

    let a_vals = vec![1i64, -2, 3, 4, -1, 2, 5, -3];
    let w_vals = vec![2i64, 1, -3, 2, 4, -1, 1, 3];
    // Compute exact C[t + 2*o] = sum_{i=0..4} A[t + 2*i] * W[o + 2*i].
    let c_vals: Vec<i64> = (0..4)
        .map(|x| {
            let t = x & 1;
            let o = (x >> 1) & 1;
            (0..4)
                .map(|i| a_vals[t | (i << 1)] * w_vals[o | (i << 1)])
                .sum()
        })
        .collect();

    let sources = Sources::CircleAll;
    let prepare_models = |rel: &Relation, vals: &Values| {
        let msgs = model_messages(rel, vals).expect("model msgs");
        let layouts = model_layout(rel, sources).expect("model layouts");
        layouts
            .iter()
            .zip(msgs)
            .map(|(l, m)| {
                let p = sources
                    .prepare_owned(l.id, l.ell, &l.code, m)
                    .expect("prepare");
                let (cert, _) = p.certificate().expect("cert");
                let (handle, _) = verify_certificate(*p.source(), &cert).expect("verify cert");
                (p, handle)
            })
            .collect::<Vec<_>>()
    };

    // Single-claim check: 0 RLC lines, 1 SC line, 1 contraction reduced, 2 partial evals.
    {
        let (rel, a, w, y, _, c) = build_matmul_rel(false);
        assert_eq!(rel.validate(), Ok(()));
        let mut vals = Values::new(&rel);
        vals.set(&rel, a, a_vals.clone()).expect("a");
        vals.set(&rel, w, w_vals.clone()).expect("w");
        vals.set(&rel, y, c_vals.clone()).expect("y");
        assert_eq!(stele_ir::relation::check(&rel, &vals), Ok(()));
        let prepared = prepare_models(&rel, &vals);
        let mp: Vec<_> = prepared.iter().map(|(p, h)| (p, h)).collect();
        let mv: Vec<_> = prepared.iter().map(|(_, h)| h).collect();

        let mut tp = Transcript::new(PUBLIC).expect("t");
        let (proof, metrics) =
            prove_segmented_measured(&mut tp, &rel, |_| Ok(vals.clone()), &mp, sources)
                .expect("prove single");
        // Only `c` is claimed; `_unclaimed` emits 0 reduction sections.
        assert_eq!(proof.segments[0].reductions.len(), 1);
        assert_eq!(metrics.contractions_reduced, 1);
        assert_eq!(metrics.contraction_partial_evals, 2);
        // Committed cells: A (8) + y (4) = 12 (never C or _unclaimed).
        assert_eq!(metrics.committed_cells, 12);

        let mut tv = Transcript::new(PUBLIC).expect("t");
        let ledger = verify_segmented(&mut tv, &rel, &mv, &proof, sources).expect("verify single");
        let c_lines: Vec<_> = ledger.entries.iter().filter(|e| e.name == "mm/C").collect();
        assert_eq!(c_lines.len(), 1);
        assert_eq!(c_lines[0].line, Line::Sc);
        assert_eq!(c_lines[0].numerator, 2 * 2); // summed = 2, degree = 2

        // Poisoning `Values` slot for virtual contraction `c` must be ignored (bit-identical proof).
        let mut vals_bogus = vals.clone();
        vals_bogus
            .set(&rel, c, vec![999, 999, 999, 999])
            .expect("bogus");
        let mut tp2 = Transcript::new(PUBLIC).expect("t");
        let (proof2, _) =
            prove_segmented_measured(&mut tp2, &rel, |_| Ok(vals_bogus.clone()), &mp, sources)
                .expect("prove bogus");
        assert_eq!(proof.segments[0].reductions, proof2.segments[0].reductions);

        // NC-1307 on virtual contraction: +1 on round 0 polynomial -> RoundSumMismatch.
        let mut bad_1307 = proof.clone();
        let sec = &mut bad_1307.segments[0].reductions[0];
        let orig = K::from_le_bytes(sec[..16].try_into().expect("16")).expect("k");
        sec[..16].copy_from_slice(&(orig + K::from_i64(1)).to_le_bytes());
        let mut tv = Transcript::new(PUBLIC).expect("t");
        assert_eq!(
            verify_segmented(&mut tv, &rel, &mv, &bad_1307, sources).err(),
            Some(Error::Sumcheck(stele_sumcheck::Error::RoundSumMismatch))
        );

        // Noncanonical QM31 limb in contraction reduction -> NoncanonicalField.
        let mut bad_nc = proof.clone();
        bad_nc.segments[0].reductions[0][..4].copy_from_slice(&((1u32 << 31) - 1).to_le_bytes());
        let mut tv = Transcript::new(PUBLIC).expect("t");
        assert_eq!(
            verify_segmented(&mut tv, &rel, &mv, &bad_nc, sources).err(),
            Some(Error::NoncanonicalField)
        );

        // Truncated reduction section -> ProofShape.
        let mut short = proof.clone();
        short.segments[0].reductions[0].pop();
        let mut tv = Transcript::new(PUBLIC).expect("t");
        assert_eq!(
            verify_segmented(&mut tv, &rel, &mv, &short, sources).err(),
            Some(Error::ProofShape)
        );

        // Direct NC-1338 on virtual contraction: forged C'[0] = C[0] + 1, honest sumcheck rounds
        // disagree with forged claim -> RoundSumMismatch.
        let mut forged_vals = vals.clone();
        let mut y_forged = c_vals.clone();
        y_forged[0] += 1;
        forged_vals.set(&rel, y, y_forged).expect("y_forged");
        let mut tp = Transcript::new(PUBLIC).expect("t");
        let forged_direct = prove_segmented_forged_virtual(
            &mut tp,
            &rel,
            |_| Ok(forged_vals.clone()),
            &mp,
            sources,
            c,
            0,
            None,
        )
        .expect("forged direct");
        let mut tv = Transcript::new(PUBLIC).expect("t");
        assert_eq!(
            verify_segmented(&mut tv, &rel, &mv, &forged_direct, sources).err(),
            Some(Error::Sumcheck(stele_sumcheck::Error::RoundSumMismatch))
        );

        // Adaptive NC-1338 on virtual contraction: force all round sums to pass -> rejects at
        // FinalEvaluationMismatch.
        let mut tp = Transcript::new(PUBLIC).expect("t");
        let forged_adapt = prove_segmented_forged_virtual(
            &mut tp,
            &rel,
            |_| Ok(forged_vals.clone()),
            &mp,
            sources,
            c,
            0,
            Some(0),
        )
        .expect("forged adapt");
        let mut tv = Transcript::new(PUBLIC).expect("t");
        assert_eq!(
            verify_segmented(&mut tv, &rel, &mv, &forged_adapt, sources).err(),
            Some(Error::Sumcheck(
                stele_sumcheck::Error::FinalEvaluationMismatch
            ))
        );
    }

    // Multi-claim check: 3 claims on C -> RFC-0006 A2 mode 1 batching (RLC + SC) + 1 contraction
    // sumcheck (SC), STILL exactly 1 contraction reduced and 2 partial evals!
    {
        let (rel, a, w, y, y2, c) = build_matmul_rel(true);
        let y2 = y2.expect("y2");
        assert_eq!(rel.validate(), Ok(()));
        let mut vals = Values::new(&rel);
        vals.set(&rel, a, a_vals.clone()).expect("a");
        vals.set(&rel, w, w_vals.clone()).expect("w");
        vals.set(&rel, y, c_vals.clone()).expect("y");
        let y2_vals: Vec<i64> = c_vals.iter().map(|v| v + 1).collect();
        vals.set(&rel, y2, y2_vals.clone()).expect("y2");
        assert_eq!(stele_ir::relation::check(&rel, &vals), Ok(()));
        let prepared = prepare_models(&rel, &vals);
        let mp: Vec<_> = prepared.iter().map(|(p, h)| (p, h)).collect();
        let mv: Vec<_> = prepared.iter().map(|(_, h)| h).collect();

        let mut tp = Transcript::new(PUBLIC).expect("t");
        let (proof, metrics) =
            prove_segmented_measured(&mut tp, &rel, |_| Ok(vals.clone()), &mp, sources)
                .expect("prove multi");
        // Reductions: `c_plus` (Linear) then `c` (Contraction).
        assert_eq!(proof.segments[0].reductions.len(), 2);
        assert_eq!(metrics.contractions_reduced, 1);
        assert_eq!(metrics.contraction_partial_evals, 2);

        let mut tv = Transcript::new(PUBLIC).expect("t");
        let ledger = verify_segmented(&mut tv, &rel, &mv, &proof, sources).expect("verify multi");
        let c_lines: Vec<_> = ledger.entries.iter().filter(|e| e.name == "mm/C").collect();
        assert_eq!(c_lines.len(), 3);
        assert_eq!(c_lines[0].line, Line::Rlc);
        assert_eq!(c_lines[1].line, Line::Sc);
        assert_eq!(c_lines[2].line, Line::Sc);

        // Tamper round 0 of the multi-claim `claim_batch` prefix inside `c`'s reduction section
        // (index 1 in decreasing ColumnId order: `c_plus` is 0, `c` is 1) -> `RoundSumMismatch`.
        let mut bad_batch = proof.clone();
        let sec = &mut bad_batch.segments[0].reductions[1];
        let orig = K::from_le_bytes(sec[..16].try_into().expect("16")).expect("k");
        sec[..16].copy_from_slice(&(orig + K::from_i64(1)).to_le_bytes());
        let mut tv = Transcript::new(PUBLIC).expect("t");
        assert_eq!(
            verify_segmented(&mut tv, &rel, &mv, &bad_batch, sources).err(),
            Some(Error::Sumcheck(stele_sumcheck::Error::RoundSumMismatch))
        );

        // Multi-claim NC-1338: forged C'[0] = C[0] + 1 passes claim batching over the forged
        // table and rejects at the contraction sumcheck (`RoundSumMismatch` / `FinalEvaluationMismatch`).
        let mut forged_vals = vals.clone();
        let mut y_f = c_vals.clone();
        y_f[0] += 1;
        let mut y2_f = y2_vals;
        y2_f[0] += 1;
        forged_vals.set(&rel, y, y_f).expect("yf");
        forged_vals.set(&rel, y2, y2_f).expect("y2f");
        let mut tp = Transcript::new(PUBLIC).expect("t");
        let forged_m = prove_segmented_forged_virtual(
            &mut tp,
            &rel,
            |_| Ok(forged_vals.clone()),
            &mp,
            sources,
            c,
            0,
            Some(0),
        )
        .expect("forged multi");
        let mut tv = Transcript::new(PUBLIC).expect("t");
        assert_eq!(
            verify_segmented(&mut tv, &rel, &mv, &forged_m, sources).err(),
            Some(Error::Sumcheck(
                stele_sumcheck::Error::FinalEvaluationMismatch
            ))
        );
    }

    // --- Part 2: Shared free bits (batched attention-like contraction), self-operand contraction,
    // row-blocked Ref::FIXED_0/1 contraction, and 0-var (`free=0, summed=0`) contraction.
    {
        let mut rel = Relation::default();
        let g3 = rel.add_group_in("sh/w3", 3, 0);
        let g2 = rel.add_group_in("sh/w2", 2, 0);
        let g0 = rel.add_group_in("sh/w0", 0, 0);
        // Q[h, t, i] and K[h, o, i]: 3 bits (bit 0 = h, bit 1 = t/o, bit 2 = i)
        let q = rel.add_column("sh/Q", Kind::Witness(g3), Width::signed(6), 3);
        let k = rel.add_column("sh/K", Kind::Witness(g3), Width::signed(6), 3);
        // Output out_sh[h, t, o]: free = 3 (bit 0 = h [shared], bit 1 = t, bit 2 = o), summed = 1 (bit 3 = i).
        let out_sh = rel.add_column("sh/out", Kind::Witness(g3), Width::signed(14), 3);
        // Self-operand row-blocked contraction: block0[t, o] = sum_i Q[h=0, t, i] * Q[h=0, o, i].
        let out_blk = rel.add_column("sh/blk", Kind::Witness(g2), Width::signed(14), 2);
        // Scalar 0-var contraction: s_out = s_a * s_b (`free = 0, summed = 0`).
        let s_a = rel.add_column("sh/sa", Kind::Witness(g0), Width::signed(6), 0);
        let s_out = rel.add_column("sh/sout", Kind::Witness(g0), Width::signed(12), 0);
        for (name, col, width) in [
            ("rq", q, Width::signed(6)),
            ("rk", k, Width::signed(6)),
            ("ro", out_sh, Width::signed(14)),
            ("rb", out_blk, Width::signed(14)),
            ("rsa", s_a, Width::signed(6)),
            ("rso", s_out, Width::signed(12)),
        ] {
            rel.ranges.push(Range {
                name: name.into(),
                column: col,
                width,
            });
        }
        let v_sh = rel.add_virtual(
            "sh/v_sh",
            Def::Contraction {
                free: 3,
                summed: 1,
                lhs: Ref {
                    column: q,
                    vars: vec![0, 1, 3],
                },
                rhs: Ref {
                    column: k,
                    vars: vec![0, 2, 3],
                },
            },
            3,
        );
        let v_blk = rel.add_virtual(
            "sh/v_blk",
            Def::Contraction {
                free: 2,
                summed: 1,
                lhs: Ref {
                    column: q,
                    vars: vec![Ref::FIXED_0, 0, 2],
                },
                rhs: Ref {
                    column: q,
                    vars: vec![Ref::FIXED_0, 1, 2],
                },
            },
            2,
        );
        let v_s0 = rel.add_virtual(
            "sh/v_s0",
            Def::Contraction {
                free: 0,
                summed: 0,
                lhs: Ref {
                    column: s_a,
                    vars: vec![],
                },
                rhs: Ref {
                    column: s_a,
                    vars: vec![],
                },
            },
            0,
        );
        rel.identities.push(Identity {
            name: "sh/eq_sh".into(),
            vars: 3,
            terms: vec![
                IdentityTerm {
                    coeff: 1,
                    factors: vec![Ref::identity(out_sh, 3)],
                },
                IdentityTerm {
                    coeff: -1,
                    factors: vec![Ref::identity(v_sh, 3)],
                },
            ],
        });
        rel.identities.push(Identity {
            name: "sh/eq_blk".into(),
            vars: 2,
            terms: vec![
                IdentityTerm {
                    coeff: 1,
                    factors: vec![Ref::identity(out_blk, 2)],
                },
                IdentityTerm {
                    coeff: -1,
                    factors: vec![Ref::identity(v_blk, 2)],
                },
            ],
        });
        rel.identities.push(Identity {
            name: "sh/eq_s0".into(),
            vars: 0,
            terms: vec![
                IdentityTerm {
                    coeff: 1,
                    factors: vec![Ref::identity(s_out, 0)],
                },
                IdentityTerm {
                    coeff: -1,
                    factors: vec![Ref::identity(v_s0, 0)],
                },
            ],
        });
        assert_eq!(rel.validate(), Ok(()));

        let q_vals = vec![1i64, -2, 3, 1, 2, -1, -3, 4];
        let k_vals = vec![2i64, 3, -1, 2, 1, -2, 4, -1];
        let sh_vals: Vec<i64> = (0..8)
            .map(|x| {
                let (h, t, o) = (x & 1, (x >> 1) & 1, (x >> 2) & 1);
                (0..2)
                    .map(|i| q_vals[h | (t << 1) | (i << 2)] * k_vals[h | (o << 1) | (i << 2)])
                    .sum()
            })
            .collect();
        let blk_vals: Vec<i64> = (0..4)
            .map(|x| {
                let (t, o) = (x & 1, (x >> 1) & 1);
                (0..2)
                    .map(|i| q_vals[(t << 1) | (i << 2)] * q_vals[(o << 1) | (i << 2)])
                    .sum()
            })
            .collect();
        let mut vals = Values::new(&rel);
        vals.set(&rel, q, q_vals).expect("q");
        vals.set(&rel, k, k_vals).expect("k");
        vals.set(&rel, out_sh, sh_vals).expect("sh");
        vals.set(&rel, out_blk, blk_vals).expect("blk");
        vals.set(&rel, s_a, vec![-5]).expect("sa");
        vals.set(&rel, s_out, vec![25]).expect("sout");
        assert_eq!(stele_ir::relation::check(&rel, &vals), Ok(()));

        let mut tp = Transcript::new(PUBLIC).expect("t");
        let (proof, metrics) =
            prove_segmented_measured(&mut tp, &rel, |_| Ok(vals.clone()), &[], sources)
                .expect("prove shared");
        assert_eq!(metrics.contractions_reduced, 3);
        assert_eq!(metrics.contraction_partial_evals, 6);
        let mut tv = Transcript::new(PUBLIC).expect("t");
        verify_segmented(&mut tv, &rel, &[], &proof, sources).expect("verify shared");

        // Tamper `eq` final value on `v_sh` (last section in decreasing ColumnId order is index 2):
        // `v_sh` has 2 sumcheck rounds of width 4 (`2 * 4 * 16 = 128` bytes), then 3 final values
        // `[eq, lhs, rhs]`. Changing `eq` while keeping `eq * lhs * rhs` fails at FinalEvaluationMismatch
        // or EqMismatch; scaling `eq` by 2 and `lhs` by 1/2 preserves `eq * lhs * rhs` and must hit `EqMismatch`!
        let mut bad_eq = proof.clone();
        let sec = &mut bad_eq.segments[0].reductions[2];
        let eq_off = 2 * 4 * 16;
        let eq_v = K::from_le_bytes(sec[eq_off..eq_off + 16].try_into().expect("16")).expect("k");
        let lhs_v =
            K::from_le_bytes(sec[eq_off + 16..eq_off + 32].try_into().expect("16")).expect("k");
        let two = K::from_i64(2);
        let inv_two = stele_field::Inverse::inverse(two).expect("inv2");
        sec[eq_off..eq_off + 16].copy_from_slice(&(eq_v * two).to_le_bytes());
        sec[eq_off + 16..eq_off + 32].copy_from_slice(&(lhs_v * inv_two).to_le_bytes());
        let mut tv = Transcript::new(PUBLIC).expect("t");
        assert_eq!(
            verify_segmented(&mut tv, &rel, &[], &bad_eq, sources).err(),
            Some(Error::EqMismatch)
        );
    }

    // --- Part 3: Overflow during `Def::Contraction` materialization -> Error::Capacity.
    {
        let mut r_ovf = Relation::default();
        let g = r_ovf.add_group_in("ovf/c", 1, 0);
        let x = r_ovf.add_column("ovf/x", Kind::Witness(g), Width::signed(8), 1);
        let c = r_ovf.add_virtual(
            "ovf/c",
            Def::Contraction {
                free: 0,
                summed: 1,
                lhs: Ref::identity(x, 1),
                rhs: Ref::identity(x, 1),
            },
            0,
        );
        let mut vals = Values::new(&r_ovf);
        vals.set(&r_ovf, x, vec![i64::MAX, i64::MAX]).expect("x");
        assert_eq!(
            super::ResolvedColumns::for_segment(&r_ovf, &vals, &[c], None).err(),
            Some(Error::Capacity)
        );
    }

    // --- Part 4: Two-segment carried `Linear -> Contraction -> Linear` chain (Step 2.4 -> Step 2.5
    // previous-segment witness opening) and `shared + summed > MAX_VARS` rejection.
    {
        let mut rel = Relation::default();
        let g0 = rel.add_group_in("seg0/w", 2, 0);
        let g1 = rel.add_group_in("seg1/w", 2, 1);
        let carried_a = rel.add_column("seg0/a", Kind::Witness(g0), Width::signed(6), 2);
        rel.mark_carried(carried_a);
        let b1 = rel.add_column("seg1/b", Kind::Witness(g1), Width::signed(6), 2);
        let y1 = rel.add_column("seg1/y", Kind::Witness(g1), Width::signed(14), 2);
        for (name, col, width) in [
            ("ra", carried_a, Width::signed(6)),
            ("rb", b1, Width::signed(6)),
            ("ry", y1, Width::signed(14)),
        ] {
            rel.ranges.push(Range {
                name: name.into(),
                column: col,
                width,
            });
        }
        // Segment 1: Linear `v_in = carried_a + b1 + 1` (owns seg 1 by reading `b1` and carried
        // seg-0 `carried_a`) -> Contraction `v_mm = sum_i v_in[t, i] * carried_a[o, i]`
        // -> Linear `v_out = 2 * v_mm - 3`, equated to `y1`.
        let v_in = rel.add_virtual(
            "seg1/v_in",
            Def::Linear {
                constant: 1,
                terms: vec![(1, Ref::identity(carried_a, 2)), (1, Ref::identity(b1, 2))],
            },
            2,
        );
        let v_mm = rel.add_virtual(
            "seg1/v_mm",
            Def::Contraction {
                free: 2,
                summed: 1,
                lhs: Ref {
                    column: v_in,
                    vars: vec![0, 2],
                },
                rhs: Ref {
                    column: carried_a,
                    vars: vec![1, 2],
                },
            },
            2,
        );
        let v_out = rel.add_virtual(
            "seg1/v_out",
            Def::Linear {
                constant: -3,
                terms: vec![(2, Ref::identity(v_mm, 2))],
            },
            2,
        );
        rel.identities.push(Identity {
            name: "seg1/eq".into(),
            vars: 2,
            terms: vec![
                IdentityTerm {
                    coeff: 1,
                    factors: vec![Ref::identity(y1, 2)],
                },
                IdentityTerm {
                    coeff: -1,
                    factors: vec![Ref::identity(v_out, 2)],
                },
            ],
        });
        assert_eq!(rel.validate(), Ok(()));

        let a_v = vec![1i64, -2, 3, 2];
        let b_v = vec![2i64, 1, -1, 3];
        let y_v: Vec<i64> = (0..4)
            .map(|x| {
                let (t, o) = (x & 1, (x >> 1) & 1);
                let mm: i64 = (0..2)
                    .map(|i| {
                        let idx = t | (i << 1);
                        (a_v[idx] + b_v[idx] + 1) * a_v[o | (i << 1)]
                    })
                    .sum();
                2 * mm - 3
            })
            .collect();
        let mut vals = Values::new(&rel);
        vals.set(&rel, carried_a, a_v).expect("a");
        vals.set(&rel, b1, b_v).expect("b");
        vals.set(&rel, y1, y_v).expect("y");
        assert_eq!(stele_ir::relation::check(&rel, &vals), Ok(()));

        let mut tp = Transcript::new(PUBLIC).expect("t");
        let (proof, metrics) =
            prove_segmented_measured(&mut tp, &rel, |_| Ok(vals.clone()), &[], sources)
                .expect("prove 2seg chain");
        assert_eq!(proof.segments.len(), 2);
        assert_eq!(proof.segments[0].reductions.len(), 0);
        assert_eq!(proof.segments[1].reductions.len(), 3);
        assert_eq!(metrics.contractions_reduced, 1);
        assert_eq!(metrics.contraction_partial_evals, 2);
        let mut tv = Transcript::new(PUBLIC).expect("t");
        verify_segmented(&mut tv, &rel, &[], &proof, sources).expect("verify 2seg chain");

        // `plan_segmented` rejects `shared + summed > MAX_VARS` with `Error::Unsupported`.
        let mut r_big = Relation::default();
        let gb = r_big.add_group_in("big/w", 20, 0);
        let bx = r_big.add_column("big/x", Kind::Witness(gb), Width::unsigned(1), 20);
        r_big.ranges.push(Range {
            name: "r_bx".into(),
            column: bx,
            width: Width::unsigned(1),
        });
        // `free = 20, summed = 15`: bits 0..16 are shared (`shared = 16`), so `shared + summed = 31 > 30`,
        // while derived magnitude `2^15 * 1 * 1 = 32768 <= HALF_MODULUS` passes `Relation::validate`.
        let _big_c = r_big.add_virtual(
            "big/c",
            Def::Contraction {
                free: 20,
                summed: 15,
                lhs: Ref {
                    column: bx,
                    vars: (0..16).chain(20..24).collect(),
                },
                rhs: Ref {
                    column: bx,
                    vars: (0..16).chain(24..28).collect(),
                },
            },
            20,
        );
        assert_eq!(r_big.validate(), Ok(()));
        let mut tv = Transcript::new(PUBLIC).expect("t");
        assert_eq!(
            verify_segmented(&mut tv, &r_big, &[], &ProofV2::default(), sources).err(),
            Some(Error::Unsupported)
        );
    }
}

/// RFC-0028 §2.4, §5, §6 & RFC-0012 A19 (task E18-04): virtual `Def::Pointwise` columns
/// (degree 1..=3 -> sumcheck degree 2..=4 with `eq`, repeated factors, constants, broadcast
/// `Ref`, `log_len == 0`, single-claim vs multi-claim RFC-0006 A2 mode 1 batching, virtual
/// lookups & range checks, unclaimed columns, `EqMismatch`, overflow `Capacity`), plus
/// `NC-1338` (direct & adaptive), `NC-1339` (virtual rounding remainder range lookup), and
/// `NC-1340` (advice inverse rejected by static magnitude bound).
#[test]
fn accepts_pointwise_virtual_columns_and_rejects_nc_1338_to_nc_1340() {
    use stele_ir::relation::Def;

    let sources = Sources::CircleAll;

    // --- Part 1: Degree-3 Pointwise (sumcheck degree 4 with `eq`), sign-magnitude
    // `a = (1 - 2*sigma) * x` (RFC-0028 §1.2), multi-claim batching, virtual lookup/range,
    // broadcast Ref, constant-only `log_len == 0`, and unclaimed Pointwise.
    {
        let mut rel = Relation::default();
        let g2 = rel.add_group_in("pw/w2", 2, 0);
        let g1 = rel.add_group_in("pw/w1", 1, 0);
        let g0 = rel.add_group_in("pw/w0", 0, 0);
        let x = rel.add_column("pw/x", Kind::Witness(g2), Width::signed(5), 2);
        let sigma = rel.add_column("pw/sigma", Kind::Witness(g2), Width::unsigned(1), 2);
        let z_b = rel.add_column("pw/zb", Kind::Witness(g1), Width::signed(4), 1);
        let out_mag = rel.add_column("pw/out_mag", Kind::Witness(g2), Width::unsigned(5), 2);
        let out_cub = rel.add_column("pw/out_cub", Kind::Witness(g2), Width::signed(14), 2);
        let out_c0 = rel.add_column("pw/out_c0", Kind::Witness(g0), Width::signed(5), 0);
        for (name, col, width) in [
            ("rx", x, Width::signed(5)),
            ("rsig", sigma, Width::unsigned(1)),
            ("rzb", z_b, Width::signed(4)),
            ("rmag", out_mag, Width::unsigned(5)),
            ("rcub", out_cub, Width::signed(14)),
            ("rc0", out_c0, Width::signed(5)),
        ] {
            rel.ranges.push(Range {
                name: name.into(),
                column: col,
                width,
            });
        }
        // Sign-magnitude virtual Pointwise: `mag = x - 2 * sigma * x` (degree 2 -> SC deg 3).
        let v_mag = rel.add_virtual(
            "pw/v_mag",
            Def::Pointwise {
                terms: vec![
                    IdentityTerm {
                        coeff: 1,
                        factors: vec![Ref::identity(x, 2)],
                    },
                    IdentityTerm {
                        coeff: -2,
                        factors: vec![Ref::identity(sigma, 2), Ref::identity(x, 2)],
                    },
                ],
            },
            2,
        );
        // Degree-3 Pointwise (SC degree 4 with `eq`) with repeated factor `x * x * zb_bcast + 2 * v_mag - 3`.
        let v_cub = rel.add_virtual(
            "pw/v_cub",
            Def::Pointwise {
                terms: vec![
                    IdentityTerm {
                        coeff: 1,
                        factors: vec![
                            Ref::identity(x, 2),
                            Ref::identity(x, 2),
                            Ref {
                                column: z_b,
                                vars: vec![0],
                            },
                        ],
                    },
                    IdentityTerm {
                        coeff: 2,
                        factors: vec![Ref::identity(v_mag, 2)],
                    },
                    IdentityTerm {
                        coeff: -3,
                        factors: vec![],
                    },
                ],
            },
            2,
        );
        // Constant-only Pointwise on `log_len == 0` (SC degree 1 with `eq`).
        let v_c0 = rel.add_virtual(
            "pw/v_c0",
            Def::Pointwise {
                terms: vec![IdentityTerm {
                    coeff: -5,
                    factors: vec![],
                }],
            },
            0,
        );
        // Unclaimed Pointwise (must emit 0 reduction sections).
        let _unclaimed = rel.add_virtual(
            "pw/unused",
            Def::Pointwise {
                terms: vec![IdentityTerm {
                    coeff: 1,
                    factors: vec![Ref::identity(x, 2), Ref::identity(x, 2)],
                }],
            },
            2,
        );
        // Multi-claim on `v_mag`: identity (`out_mag - v_mag = 0`), range check on `v_mag`,
        // AND `v_cub` reads `v_mag` -> 3 claims total on `v_mag`!
        rel.identities.push(Identity {
            name: "pw/eq_mag".into(),
            vars: 2,
            terms: vec![
                IdentityTerm {
                    coeff: 1,
                    factors: vec![Ref::identity(out_mag, 2)],
                },
                IdentityTerm {
                    coeff: -1,
                    factors: vec![Ref::identity(v_mag, 2)],
                },
            ],
        });
        rel.ranges.push(Range {
            name: "pw/r_vmag".into(),
            column: v_mag,
            width: Width::unsigned(5),
        });
        // Single-claim on `v_cub`: identity `out_cub - v_cub = 0`.
        rel.identities.push(Identity {
            name: "pw/eq_cub".into(),
            vars: 2,
            terms: vec![
                IdentityTerm {
                    coeff: 1,
                    factors: vec![Ref::identity(out_cub, 2)],
                },
                IdentityTerm {
                    coeff: -1,
                    factors: vec![Ref::identity(v_cub, 2)],
                },
            ],
        });
        // Single-claim on `v_c0`.
        rel.identities.push(Identity {
            name: "pw/eq_c0".into(),
            vars: 0,
            terms: vec![
                IdentityTerm {
                    coeff: 1,
                    factors: vec![Ref::identity(out_c0, 0)],
                },
                IdentityTerm {
                    coeff: -1,
                    factors: vec![Ref::identity(v_c0, 0)],
                },
            ],
        });
        assert_eq!(rel.validate(), Ok(()));

        let x_vals = vec![3i64, -4, 0, -2];
        let sig_vals = vec![0i64, 1, 0, 1];
        let zb_vals = vec![2i64, -3];
        let mag_vals: Vec<i64> = (0..4).map(|i| x_vals[i] * (1 - 2 * sig_vals[i])).collect();
        let cub_vals: Vec<i64> = (0..4)
            .map(|i| x_vals[i] * x_vals[i] * zb_vals[i & 1] + 2 * mag_vals[i] - 3)
            .collect();
        let mut vals = Values::new(&rel);
        vals.set(&rel, x, x_vals).expect("x");
        vals.set(&rel, sigma, sig_vals).expect("sigma");
        vals.set(&rel, z_b, zb_vals).expect("zb");
        vals.set(&rel, out_mag, mag_vals.clone()).expect("mag");
        vals.set(&rel, out_cub, cub_vals.clone()).expect("cub");
        vals.set(&rel, out_c0, vec![-5]).expect("c0");
        assert_eq!(stele_ir::relation::check(&rel, &vals), Ok(()));

        let mut tp = Transcript::new(PUBLIC).expect("t");
        let proof =
            prove_segmented(&mut tp, &rel, |_| Ok(vals.clone()), &[], sources).expect("prove pw");
        // Reductions in decreasing ColumnId order: `v_c0`, `v_cub`, `v_mag` (`_unclaimed` skipped).
        assert_eq!(proof.segments[0].reductions.len(), 3);

        let mut tv = Transcript::new(PUBLIC).expect("t");
        let ledger = verify_segmented(&mut tv, &rel, &[], &proof, sources).expect("verify pw");
        // `v_cub` has 1 claim -> 1 SC line of numerator `2 * 4 = 8` (m=2, degree=4).
        let cub_lines: Vec<_> = ledger
            .entries
            .iter()
            .filter(|e| e.name == "pw/v_cub")
            .collect();
        assert_eq!(cub_lines.len(), 1);
        assert_eq!(cub_lines[0].line, Line::Sc);
        assert_eq!(cub_lines[0].numerator, 2 * 4);
        assert_eq!(cub_lines[0].round, 4);
        // `v_mag` has 3 claims -> RLC + SC (batch) + SC (pointwise, m=2, degree=3 -> 6).
        let mag_lines: Vec<_> = ledger
            .entries
            .iter()
            .filter(|e| e.name == "pw/v_mag")
            .collect();
        assert_eq!(mag_lines.len(), 3);
        assert_eq!(mag_lines[0].line, Line::Rlc);
        assert_eq!(mag_lines[1].line, Line::Sc);
        assert_eq!(mag_lines[2].line, Line::Sc);
        assert_eq!(mag_lines[2].numerator, 2 * 3);

        // Tamper round 0 of the multi-claim `claim_batch` prefix inside `v_mag`'s reduction section
        // (index 2 in decreasing ColumnId order: `v_c0`, `v_cub`, `v_mag`) -> `RoundSumMismatch`.
        let mut bad_pw_batch = proof.clone();
        let sec = &mut bad_pw_batch.segments[0].reductions[2];
        let orig = K::from_le_bytes(sec[..16].try_into().expect("16")).expect("k");
        sec[..16].copy_from_slice(&(orig + K::from_i64(1)).to_le_bytes());
        let mut tv = Transcript::new(PUBLIC).expect("t");
        assert_eq!(
            verify_segmented(&mut tv, &rel, &[], &bad_pw_batch, sources).err(),
            Some(Error::Sumcheck(stele_sumcheck::Error::RoundSumMismatch))
        );

        // Poisoning `Values` slot for virtual Pointwise `v_cub` must be ignored (bit-identical proof).
        let mut vals_bogus = vals.clone();
        vals_bogus
            .set(&rel, v_cub, vec![123, 456, 789, 101])
            .expect("bogus");
        let mut tp2 = Transcript::new(PUBLIC).expect("t");
        let proof2 = prove_segmented(&mut tp2, &rel, |_| Ok(vals_bogus.clone()), &[], sources)
            .expect("prove bogus");
        assert_eq!(proof.segments[0].reductions, proof2.segments[0].reductions);

        // Noncanonical QM31 limb -> NoncanonicalField.
        let mut bad_nc = proof.clone();
        bad_nc.segments[0].reductions[1][..4].copy_from_slice(&((1u32 << 31) - 1).to_le_bytes());
        let mut tv = Transcript::new(PUBLIC).expect("t");
        assert_eq!(
            verify_segmented(&mut tv, &rel, &[], &bad_nc, sources).err(),
            Some(Error::NoncanonicalField)
        );

        // Truncated reduction section -> ProofShape.
        let mut short = proof.clone();
        short.segments[0].reductions[1].pop();
        let mut tv = Transcript::new(PUBLIC).expect("t");
        assert_eq!(
            verify_segmented(&mut tv, &rel, &[], &short, sources).err(),
            Some(Error::ProofShape)
        );

        // Direct & adaptive NC-1338 on single-claim `v_cub`:
        let mut forged_vals = vals.clone();
        let mut cub_f = cub_vals;
        cub_f[0] += 1;
        forged_vals.set(&rel, out_cub, cub_f).expect("cub_f");
        let mut tp = Transcript::new(PUBLIC).expect("t");
        let forged_direct = prove_segmented_forged_virtual(
            &mut tp,
            &rel,
            |_| Ok(forged_vals.clone()),
            &[],
            sources,
            v_cub,
            0,
            None,
        )
        .expect("forged direct");
        let mut tv = Transcript::new(PUBLIC).expect("t");
        assert_eq!(
            verify_segmented(&mut tv, &rel, &[], &forged_direct, sources).err(),
            Some(Error::Sumcheck(stele_sumcheck::Error::RoundSumMismatch))
        );

        let mut tp = Transcript::new(PUBLIC).expect("t");
        let forged_adapt = prove_segmented_forged_virtual(
            &mut tp,
            &rel,
            |_| Ok(forged_vals.clone()),
            &[],
            sources,
            v_cub,
            0,
            Some(0),
        )
        .expect("forged adapt");
        let mut tv = Transcript::new(PUBLIC).expect("t");
        assert_eq!(
            verify_segmented(&mut tv, &rel, &[], &forged_adapt, sources).err(),
            Some(Error::Sumcheck(
                stele_sumcheck::Error::FinalEvaluationMismatch
            ))
        );

        // Tamper `eq` final value on a single-term linear Pointwise (`v = x`, scaling `eq` by 2
        // and `x` by 1/2 preserves `eq * x == running` so sumcheck passes and `EqMismatch` fires!).
        let mut r_eq = Relation::default();
        let g_eq = r_eq.add_group_in("eq/w", 1, 0);
        let ex = r_eq.add_column("eq/x", Kind::Witness(g_eq), Width::signed(5), 1);
        let ey = r_eq.add_column("eq/y", Kind::Witness(g_eq), Width::signed(5), 1);
        r_eq.ranges.push(Range {
            name: "rx".into(),
            column: ex,
            width: Width::signed(5),
        });
        r_eq.ranges.push(Range {
            name: "ry".into(),
            column: ey,
            width: Width::signed(5),
        });
        let ev = r_eq.add_virtual(
            "eq/v",
            Def::Pointwise {
                terms: vec![IdentityTerm {
                    coeff: 1,
                    factors: vec![Ref::identity(ex, 1)],
                }],
            },
            1,
        );
        r_eq.identities.push(Identity {
            name: "eq/id".into(),
            vars: 1,
            terms: vec![
                IdentityTerm {
                    coeff: 1,
                    factors: vec![Ref::identity(ey, 1)],
                },
                IdentityTerm {
                    coeff: -1,
                    factors: vec![Ref::identity(ev, 1)],
                },
            ],
        });
        assert_eq!(r_eq.validate(), Ok(()));
        let mut eq_vals = Values::new(&r_eq);
        eq_vals.set(&r_eq, ex, vec![3, 5]).expect("ex");
        eq_vals.set(&r_eq, ey, vec![3, 5]).expect("ey");
        let mut tp = Transcript::new(PUBLIC).expect("t");
        let mut p_eq =
            prove_segmented(&mut tp, &r_eq, |_| Ok(eq_vals.clone()), &[], sources).expect("p_eq");
        // 1 round of width 3 (`3 * 16 = 48` bytes), then 2 finals `[eq, x]`.
        let sec = &mut p_eq.segments[0].reductions[0];
        let off = 3 * 16;
        let eq_v = K::from_le_bytes(sec[off..off + 16].try_into().expect("16")).expect("k");
        let x_v = K::from_le_bytes(sec[off + 16..off + 32].try_into().expect("16")).expect("k");
        let two = K::from_i64(2);
        let inv_two = stele_field::Inverse::inverse(two).expect("inv2");
        sec[off..off + 16].copy_from_slice(&(eq_v * two).to_le_bytes());
        sec[off + 16..off + 32].copy_from_slice(&(x_v * inv_two).to_le_bytes());
        let mut tv = Transcript::new(PUBLIC).expect("t");
        assert_eq!(
            verify_segmented(&mut tv, &r_eq, &[], &p_eq, sources).err(),
            Some(Error::EqMismatch)
        );
    }

    // --- Part 2: NC-1339 (commit `y + 1` for rounding, virtual `rem = acc - 2^k * y` range
    // lookup rejects with `Fraction(RootMismatch)`) and NC-1340 (advice inverse of `2^k`
    // declared as `Linear` rejects with `StatementMismatch(Invalid::Bound)`).
    {
        let mut r_rnd = Relation::default();
        let g = r_rnd.add_group_in("rnd/w", 2, 0);
        let acc = r_rnd.add_column("rnd/acc", Kind::Witness(g), Width::unsigned(12), 2);
        let y = r_rnd.add_column("rnd/y", Kind::Witness(g), Width::unsigned(8), 2);
        r_rnd.ranges.push(Range {
            name: "r_acc".into(),
            column: acc,
            width: Width::unsigned(12),
        });
        r_rnd.ranges.push(Range {
            name: "r_y".into(),
            column: y,
            width: Width::unsigned(8),
        });
        // Virtual remainder: `rem = acc - 16 * y` (k = 4), range-checked to `u4` (0..16).
        let rem = r_rnd.add_virtual(
            "rnd/rem",
            Def::Linear {
                constant: 0,
                terms: vec![(1, Ref::identity(acc, 2)), (-16, Ref::identity(y, 2))],
            },
            2,
        );
        r_rnd.ranges.push(Range {
            name: "r_rem".into(),
            column: rem,
            width: Width::unsigned(4),
        });
        assert_eq!(r_rnd.validate(), Ok(()));
        let mut honest_vals = Values::new(&r_rnd);
        // acc = [100, 205, 19, 31], y = [6, 12, 1, 1], rem = [4, 13, 3, 15].
        honest_vals
            .set(&r_rnd, acc, vec![100, 205, 19, 31])
            .expect("acc");
        honest_vals.set(&r_rnd, y, vec![6, 12, 1, 1]).expect("y");
        assert_eq!(stele_ir::relation::check(&r_rnd, &honest_vals), Ok(()));
        let mut tp = Transcript::new(PUBLIC).expect("t");
        let p_ok = prove_segmented(&mut tp, &r_rnd, |_| Ok(honest_vals.clone()), &[], sources)
            .expect("honest round");
        let mut tv = Transcript::new(PUBLIC).expect("t");
        verify_segmented(&mut tv, &r_rnd, &[], &p_ok, sources).expect("verify round");

        // NC-1339: commit `y[0] + 1 = 7` -> virtual `rem[0] = 100 - 112 = -12` outside `u4`.
        let mut bad_vals = honest_vals;
        bad_vals.set(&r_rnd, y, vec![7, 12, 1, 1]).expect("bad y");
        let mut tp = Transcript::new(PUBLIC).expect("t");
        let p_bad = prove_segmented(&mut tp, &r_rnd, |_| Ok(bad_vals.clone()), &[], sources)
            .expect("prove bad round");
        let mut tv = Transcript::new(PUBLIC).expect("t");
        assert_eq!(
            verify_segmented(&mut tv, &r_rnd, &[], &p_bad, sources).err(),
            Some(Error::Fraction(stele_lookup::fraction::Error::RootMismatch))
        );

        // NC-1340: declare rounding output `y` as `Def::Linear` using the field inverse of `2^4 = 16`
        // mod `p = 2^31 - 1` (`inv_16 = (p + 1) / 16 = 2^27 = 134_217_728`, so `16 * inv_16 ≡ 1 (mod p)`).
        let mut r_inv = Relation::default();
        let g_inv = r_inv.add_group_in("inv/w", 2, 0);
        let i_acc = r_inv.add_column("inv/acc", Kind::Witness(g_inv), Width::unsigned(12), 2);
        let i_rem = r_inv.add_column("inv/rem", Kind::Witness(g_inv), Width::unsigned(4), 2);
        r_inv.ranges.push(Range {
            name: "r_acc".into(),
            column: i_acc,
            width: Width::unsigned(12),
        });
        r_inv.ranges.push(Range {
            name: "r_rem".into(),
            column: i_rem,
            width: Width::unsigned(4),
        });
        let inv_16: i64 = 1i64 << 27;
        let _y_fake = r_inv.add_virtual(
            "inv/y_fake",
            Def::Linear {
                constant: 0,
                terms: vec![
                    (inv_16, Ref::identity(i_acc, 2)),
                    (-inv_16, Ref::identity(i_rem, 2)),
                ],
            },
            2,
        );
        let mut tv = Transcript::new(PUBLIC).expect("t");
        assert!(matches!(
            verify_segmented(&mut tv, &r_inv, &[], &ProofV2::default(), sources),
            Err(Error::StatementMismatch(
                stele_ir::relation::Invalid::Bound { .. }
            ))
        ));
    }

    // --- Part 3: Overflow during `Def::Pointwise` materialization -> Error::Capacity.
    {
        let mut r_ovf = Relation::default();
        let g = r_ovf.add_group_in("ovf/pw", 1, 0);
        let x = r_ovf.add_column("ovf/x", Kind::Witness(g), Width::signed(8), 1);
        let v = r_ovf.add_virtual(
            "ovf/v",
            Def::Pointwise {
                terms: vec![IdentityTerm {
                    coeff: i64::MAX,
                    factors: vec![Ref::identity(x, 1), Ref::identity(x, 1)],
                }],
            },
            1,
        );
        let mut vals = Values::new(&r_ovf);
        vals.set(&r_ovf, x, vec![i64::MAX, 0]).expect("x");
        assert_eq!(
            super::ResolvedColumns::for_segment(&r_ovf, &vals, &[v], None).err(),
            Some(Error::Capacity)
        );
    }
}

/// `MatmulSummand` (base-field first round + unexpanded `2^|shared|` eq table) matches
/// dense extension-field sumcheck bit-for-bit across all `(lhs, rhs)` base/ext variants,
/// both with and without shared bits, including `summed = 0` and `summed > 0` (E20-01).
#[test]
fn matches_reference_matmul_summand_across_base_and_shared_shapes() {
    use stele_sumcheck::{Dense, DenseTable};

    let base_tbl = |n: usize, seed: i64| -> Vec<M31> {
        (0..n)
            .map(|i| M31::from_i64(((i as i64 * 17 + seed * 31) % 97) - 48))
            .collect()
    };
    let ext_tbl = |n: usize, seed: i64| -> Vec<K> {
        let mut t = Transcript::<K>::new(b"e20-01-ext").expect("t");
        let base = K::from_i64(seed + 3);
        (0..n)
            .map(|i| {
                let c = t.challenge(ChallengeLabel::RelationPoint).expect("c");
                c + base * K::from_i64(i as i64)
            })
            .collect()
    };
    let to_k = |t: &DenseTable<K>| -> Vec<K> {
        match t {
            DenseTable::Base(b) => b
                .iter()
                .map(|v| K::from_i64(i64::from(v.as_u32())))
                .collect(),
            DenseTable::Ext(e) => e.clone(),
        }
    };

    // (summed_bits, shared_bits)
    let shapes = [(3u32, 0u32), (3, 2), (0, 3), (2, 1)];
    for (summed, shared) in shapes {
        let nv = summed + shared;
        let len = 1usize << nv;
        let eq_small = if shared > 0 {
            let mut t = Transcript::new(b"e20-01-eq").expect("t");
            let pt: Vec<K> = (0..shared)
                .map(|_| t.challenge(ChallengeLabel::RelationPoint).expect("c"))
                .collect();
            Some(stele_poly::eq_table(&pt).expect("eq"))
        } else {
            None
        };
        let eq_full = eq_small.as_ref().map(|e| {
            let mask = e.len() - 1;
            (0..len).map(|i| e[i & mask]).collect::<Vec<K>>()
        });
        for lhs_base in [true, false] {
            for rhs_base in [true, false] {
                let lhs = if lhs_base {
                    DenseTable::Base(base_tbl(len, 1))
                } else {
                    DenseTable::Ext(ext_tbl(len, 1))
                };
                let rhs = if rhs_base {
                    DenseTable::Base(base_tbl(len, 2))
                } else {
                    DenseTable::Ext(ext_tbl(len, 2))
                };
                let lk = to_k(&lhs);
                let rk = to_k(&rhs);
                let claimed: K = (0..len).fold(K::from_i64(0), |acc, i| {
                    let p = lk[i] * rk[i];
                    acc + match &eq_full {
                        Some(e) => e[i] * p,
                        None => p,
                    }
                });
                let instance = Instance {
                    id: MATMUL | u64::from(nv),
                    num_vars: nv,
                    inputs: (0..2 + u64::from(shared > 0)).collect(),
                    terms: vec![Term {
                        coefficient: K::from_i64(1),
                        factors: if shared > 0 {
                            vec![0, 1, 2]
                        } else {
                            vec![0, 1]
                        },
                    }],
                    claimed_sum: claimed,
                };
                let mut ref_tables = Vec::new();
                if let Some(e) = &eq_full {
                    ref_tables.push(e.clone());
                }
                ref_tables.push(lk);
                ref_tables.push(rk);
                let mut t_ref = Transcript::new(b"e20-01-parity").expect("t");
                let dense = Dense::new(&instance, ref_tables).expect("dense");
                let ref_proof = stele_sumcheck::prove(&instance, dense, &mut t_ref).expect("ref");

                let mut t_opt = Transcript::new(b"e20-01-parity").expect("t");
                let mut sc = Vec::new();
                let summand = MatmulSummand {
                    rem: len,
                    eq: eq_small.clone(),
                    lhs,
                    rhs,
                    point: &mut sc,
                };
                let opt_proof = stele_sumcheck::prove(&instance, summand, &mut t_opt).expect("opt");

                assert_eq!(opt_proof, ref_proof);
                assert_eq!(sc.len(), nv as usize);
                assert_eq!(
                    t_opt.challenge(ChallengeLabel::RelationPoint).expect("c"),
                    t_ref.challenge(ChallengeLabel::RelationPoint).expect("c")
                );
            }
        }
    }
}

/// RFC-0026 A8: unsplit plans (`B = 30`) produce byte-identical proofs; smaller `B` splits
/// oversized members along leading domain bits (`block_bits > 0`) and packs members into
/// ordered `<= 2^B` instances (for both `Range` and selected `Lookup`), verified under the
/// matching plan bound and rejected under a mismatched bound (`ProofShape`).
#[test]
fn accepts_a8_split_lookup_instances_and_matches_unsplit_bytes() {
    use stele_ir::relation::{Lookup, Range, Table};

    let mut rel = Relation::default();
    let g = rel.add_group("L0/a8/3", 3);
    let x = rel.add_column("x", Kind::Witness(g), Width::unsigned(2), 3);
    let y = rel.add_column("y", Kind::Witness(g), Width::unsigned(2), 3);
    let sel = rel.add_column(
        "sel",
        Kind::Public(vec![1, 0, 1, 1, 1, 1, 0, 1]),
        Width::unsigned(1),
        3,
    );
    let tbl = rel.add_table(Table {
        name: "pairs".into(),
        widths: vec![Width::unsigned(2), Width::unsigned(2)],
        rows: vec![vec![0, 3], vec![1, 2], vec![2, 1], vec![3, 0]],
    });
    rel.ranges.push(Range {
        name: "rx".into(),
        column: x,
        width: Width::unsigned(2),
    });
    rel.ranges.push(Range {
        name: "ry".into(),
        column: y,
        width: Width::unsigned(2),
    });
    rel.lookups.push(Lookup {
        name: "lxy".into(),
        vars: 3,
        selector: Some(Ref::identity(sel, 3)),
        tuple: vec![Ref::identity(x, 3), Ref::identity(y, 3)],
        table: tbl,
    });
    let mut values = Values::new(&rel);
    values
        .set(&rel, x, vec![0, 1, 2, 3, 3, 2, 1, 0])
        .expect("x");
    values
        .set(&rel, y, vec![3, 2, 1, 0, 0, 1, 2, 3])
        .expect("y");
    assert_eq!(stele_ir::relation::check(&rel, &values), Ok(()));

    // Unsplit B = 30 matches default `prove` byte-for-byte.
    let mut t0 = Transcript::new(PUBLIC).expect("t");
    let p_default = prove(&mut t0, &rel, &values, &[], Sources::CircleAll).expect("default");
    let mut t1 = Transcript::new(PUBLIC).expect("t");
    let p_b30 = prove_with_instance_bound(&mut t1, &rel, &values, &[], Sources::CircleAll, 30)
        .expect("b30");
    assert_eq!(p_default, p_b30);

    // Split B = 2: `lxy` (8 pos) -> 2 instances of 4; `range_2` (`rx` + `ry` = 16 pos) -> 4 instances of 4.
    let p = plan_with_bound(&rel, Sources::CircleAll, 2).expect("plan b2");
    assert_eq!(p.checks.len(), 6);
    assert!(p.checks.iter().all(|c| c.m <= 2));
    assert!(p.checks.iter().all(|c| c.members[0].block_bits == 1));

    let mut tp = Transcript::new(PUBLIC).expect("t");
    let (proof_b2, metrics_b2) =
        prove_measured_with_instance_bound(&mut tp, &rel, &values, &[], Sources::CircleAll, 2)
            .expect("prove b2");
    assert_eq!(metrics_b2.lookup_checks.len(), 6);

    let mut tv = Transcript::new(PUBLIC).expect("t");
    verify_with_instance_bound(&mut tv, &rel, &[], &proof_b2, Sources::CircleAll, 2)
        .expect("verify b2");

    // Verifier with wrong plan bound rejects immediately with ProofShape.
    let mut tv_wrong = Transcript::new(PUBLIC).expect("t");
    assert_eq!(
        verify_with_instance_bound(&mut tv_wrong, &rel, &[], &proof_b2, Sources::CircleAll, 30),
        Err(Error::ProofShape)
    );
}

/// RFC-0026 A8 negative control: moving a member value across an instance boundary without
/// moving its multiplicity is rejected by the receiving instance's root equation (`RootMismatch`).
#[test]
fn rejects_a8_member_value_moved_across_instance_boundary_without_multiplicity() {
    use stele_ir::relation::Range;

    let mut rel = Relation::default();
    let g = rel.add_group("L0/a8ctrl/3", 3);
    let x = rel.add_column("x", Kind::Witness(g), Width::unsigned(2), 3);
    rel.ranges.push(Range {
        name: "rx".into(),
        column: x,
        width: Width::unsigned(2),
    });
    // Honest split at B = 2:
    //   instance 0 (block 0): [0, 1, 2, 3] -> counts [1, 1, 1, 1]
    //   instance 1 (block 1): [3, 2, 1, 0] -> counts [1, 1, 1, 1]
    // Move value `0` from instance 0 into instance 1 (swapping x[0]=0 with x[4]=3 ->
    // instance 0 gets [3, 1, 2, 3], instance 1 receives [0, 2, 1, 0]):
    // global counts across x are unchanged ([2, 2, 2, 2]), instance 0 gets its true counts
    // [0, 1, 1, 2], while the receiving instance 1 retains the unmoved counts [1, 1, 1, 1].
    let mut moved = Values::new(&rel);
    moved
        .set(&rel, x, vec![3, 1, 2, 3, 0, 2, 1, 0])
        .expect("moved");
    assert_eq!(stele_ir::relation::check(&rel, &moved), Ok(()));

    // Honest proof with moved values AND updated per-instance multiplicities verifies cleanly.
    let mut th = Transcript::new(PUBLIC).expect("t");
    let honest = prove_with_instance_bound(&mut th, &rel, &moved, &[], Sources::CircleAll, 2)
        .expect("honest");
    let mut tvh = Transcript::new(PUBLIC).expect("t");
    verify_with_instance_bound(&mut tvh, &rel, &[], &honest, Sources::CircleAll, 2)
        .expect("honest verify");

    // Malicious prover: receiving instance 1 keeps unmoved multiplicity [1, 1, 1, 1].
    let mut p = plan_with_bound(&rel, Sources::CircleAll, 2).expect("plan b2");
    assert_eq!(p.checks.len(), 2);
    p.checks[1].count_override = Some(vec![1, 1, 1, 1]);
    let mut tf = Transcript::new(PUBLIC).expect("t");
    let forged = prove_plan(&mut tf, &rel, &p, &moved, &moved, &[], None).expect("forged bytes");
    let mut tvf = Transcript::new(PUBLIC).expect("t");
    assert_eq!(
        verify_with_instance_bound(&mut tvf, &rel, &[], &forged, Sources::CircleAll, 2),
        Err(Error::Fraction(stele_lookup::fraction::Error::RootMismatch))
    );
}

/// RFC-0026 A8 non-identity `Ref` and multi-member bucket split: verifies leading-bit
/// block splitting preserves `Ref` variable maps (transposition + broadcast) across
/// multiple members packed into one split bucket.
#[test]
fn accepts_a8_split_with_non_identity_ref_and_multi_member_bucket() {
    use stele_ir::relation::{Lookup, Table};

    let mut rel = Relation::default();
    let g = rel.add_group("L0/a8ref/2", 2);
    // Two 4-entry columns (`log_len = 2`), referenced with a 3-var (`8`-entry) transposed/broadcast Ref.
    let a = rel.add_column("a", Kind::Witness(g), Width::unsigned(2), 2);
    let b = rel.add_column("b", Kind::Witness(g), Width::unsigned(2), 2);
    let tbl = rel.add_table(Table {
        name: "u2".into(),
        widths: vec![Width::unsigned(2)],
        rows: vec![vec![0], vec![1], vec![2], vec![3]],
    });
    // `Ref` with swapped + broadcast vars: column bit 0 <- lookup var 2, column bit 1 <- lookup var 0.
    // Lookup var 1 is ignored (broadcast). When split with B = 2 (leading bit = var 2 fixed),
    // block 0 fixes var 2 = 0 (column bit 0 = 0) and block 1 fixes var 2 = 1 (column bit 0 = 1).
    rel.lookups.push(Lookup {
        name: "la".into(),
        vars: 3,
        selector: None,
        tuple: vec![Ref {
            column: a,
            vars: vec![2, 0],
        }],
        table: tbl,
    });
    // Second 2-var member on `b` with swapped vars `[1, 0]`.
    rel.lookups.push(Lookup {
        name: "lb".into(),
        vars: 2,
        selector: None,
        tuple: vec![Ref {
            column: b,
            vars: vec![1, 0],
        }],
        table: tbl,
    });
    let mut values = Values::new(&rel);
    values.set(&rel, a, vec![0, 1, 2, 3]).expect("a");
    values.set(&rel, b, vec![3, 2, 1, 0]).expect("b");
    assert_eq!(stele_ir::relation::check(&rel, &values), Ok(()));

    let p = plan_with_bound(&rel, Sources::CircleAll, 2).expect("plan");
    assert!(p.checks.iter().all(|c| c.m <= 2));
    assert_eq!(p.checks.len(), 3); // 2 split blocks for `la` + 1 unsplit for `lb`

    let mut tp = Transcript::new(PUBLIC).expect("t");
    let proof =
        prove_with_instance_bound(&mut tp, &rel, &values, &[], Sources::CircleAll, 2).expect("p");
    let mut tv = Transcript::new(PUBLIC).expect("t");
    verify_with_instance_bound(&mut tv, &rel, &[], &proof, Sources::CircleAll, 2).expect("v");
}

// Tests from the E20-01/E20-02 review (agents/reviews/e20-01-e20-02-engine-fast-paths.md, F2 and F4).

/// SplitMix64, for the seeded shapes below.
struct SeededRng(u64);
impl SeededRng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// The base commit's `MatmulShape::table` (a06fea90^), ported verbatim, sequential.
fn reference_matmul_table(shape: &MatmulShape, r: &Ref, col: &[i64]) -> Vec<K> {
    let nv = shape.vars.len();
    let mut mask = 0usize;
    let (mut inner, mut outer) = (Vec::new(), Vec::new());
    let mut eq = vec![K::from_i64(1)];
    for (j, d) in r.vars.iter().enumerate() {
        match shape.position(*d) {
            Some(p) => {
                mask |= 1 << (nv - 1 - p);
                inner.push((j, nv - 1 - p));
            }
            None => {
                let x = shape.fixed_at(*d);
                let low: Vec<K> = eq.iter().map(|w| *w * (K::from_i64(1) - x)).collect();
                let high: Vec<K> = eq.iter().map(|w| *w * x).collect();
                eq = [low, high].concat();
                outer.push(j);
            }
        }
    }
    let (mut fixed, mut selected) = (0usize, 0usize);
    for (j, d) in r.vars.iter().enumerate() {
        if let Some(bit) = Ref::fixed(*d) {
            fixed |= 1 << j;
            selected |= usize::from(bit) << j;
        }
    }
    let mut reduced = vec![K::from_i64(0); 1 << nv];
    for (index, entry) in col.iter().enumerate() {
        if index & fixed != selected {
            continue;
        }
        let z = inner
            .iter()
            .fold(0, |z, (j, to)| z | ((index >> j) & 1) << to);
        let o = outer
            .iter()
            .enumerate()
            .fold(0, |o, (k, j)| o | ((index >> j) & 1) << k);
        reduced[z] = reduced[z] + eq[o] * K::from_i64(*entry);
    }
    (0..1 << nv).map(|z| reduced[z & mask]).collect()
}

/// The base commit's `MatmulShape::eq_table`, ported verbatim.
fn reference_matmul_eq_table(shape: &MatmulShape) -> Vec<K> {
    let nv = shape.vars.len();
    (0..1usize << nv)
        .map(|z| {
            shape.shared.iter().fold(K::from_i64(1), |acc, d| {
                let p = shape.position(*d).unwrap_or(0);
                let x = shape.rho_at(*d);
                acc * if (z >> (nv - 1 - p)) & 1 == 1 {
                    x
                } else {
                    K::from_i64(1) - x
                }
            })
        })
        .collect()
}

/// Random operand shapes (permuted, broadcast, fixed bits, non-shared free bits): the new
/// operand tables, the unexpanded eq table and the sumcheck bytes equal the base code's.
#[test]
fn matches_reference_matmul_tables_of_the_all_extension_engine() {
    use stele_sumcheck::{Dense, DenseTable};
    let mut rng = SeededRng(99);
    let mut draws = Transcript::<K>::new(b"review/matmul").expect("t");
    let (mut base_tables, mut ext_tables, mut with_eq) = (0, 0, 0);
    for case in 0..600u64 {
        let free = rng.below(5) as u8;
        let summed = rng.below(5) as u8;
        let domain = free + summed;
        let operand = |rng: &mut SeededRng| -> (Ref, Vec<i64>) {
            let mut bits: Vec<u8> = (0..domain).filter(|_| rng.below(4) != 0).collect();
            for i in (1..bits.len()).rev() {
                let j = rng.below(i as u64 + 1) as usize;
                bits.swap(i, j);
            }
            for _ in 0..rng.below(3) {
                let at = rng.below(bits.len() as u64 + 1) as usize;
                bits.insert(
                    at,
                    if rng.below(2) == 0 {
                        Ref::FIXED_0
                    } else {
                        Ref::FIXED_1
                    },
                );
            }
            let col = (0..1usize << bits.len())
                .map(|_| rng.below(513) as i64 - 256)
                .collect();
            (
                Ref {
                    column: ColumnId(0),
                    vars: bits,
                },
                col,
            )
        };
        let (lhs, lcol) = operand(&mut rng);
        let (rhs, rcol) = operand(&mut rng);
        let rho: Vec<K> = (0..free)
            .map(|_| draws.challenge(ChallengeLabel::RelationPoint).expect("c"))
            .collect();
        let shape = MatmulShape::from_point(rho, free, summed, &lhs, &rhs);
        let nv = shape.vars.len();
        let (old_l, old_r) = (
            reference_matmul_table(&shape, &lhs, &lcol),
            reference_matmul_table(&shape, &rhs, &rcol),
        );
        let narrow: Vec<i16> = lcol.iter().map(|v| *v as i16).collect();
        let new_l = shape
            .table_mixed(&lhs, ColumnSlice::I16(&narrow))
            .expect("lhs");
        let new_r = shape
            .table_mixed(&rhs, ColumnSlice::I64(&rcol))
            .expect("rhs");
        let to_k = |t: &DenseTable<K>| -> Vec<K> {
            match t {
                DenseTable::Base(b) => b
                    .iter()
                    .map(|v| K::from_i64(i64::from(v.as_u32())))
                    .collect(),
                DenseTable::Ext(e) => e.clone(),
            }
        };
        assert_eq!(to_k(&new_l), old_l, "case {case} lhs");
        assert_eq!(to_k(&new_r), old_r, "case {case} rhs");
        for t in [&new_l, &new_r] {
            match t {
                DenseTable::Base(_) => base_tables += 1,
                DenseTable::Ext(_) => ext_tables += 1,
            }
        }
        let old_eq = reference_matmul_eq_table(&shape);
        let new_eq = shape.eq_shared().expect("eq");
        match &new_eq {
            None => assert!(shape.shared.is_empty()),
            Some(e) => {
                with_eq += 1;
                let mask = e.len() - 1;
                let expanded: Vec<K> = (0..1usize << nv).map(|z| e[z & mask]).collect();
                assert_eq!(expanded, old_eq, "case {case} eq");
            }
        }
        let claimed = (0..1usize << nv).fold(K::from_i64(0), |s, z| {
            s + if shape.shared.is_empty() {
                old_l[z] * old_r[z]
            } else {
                old_eq[z] * old_l[z] * old_r[z]
            }
        });
        let instance = shape.instance(MATMUL | case, claimed);
        let mut tables = Vec::new();
        if !shape.shared.is_empty() {
            tables.push(old_eq);
        }
        tables.extend([old_l, old_r]);
        let mut t_ref = Transcript::new(b"review/matmul/t").expect("t");
        let reference = stele_sumcheck::prove(
            &instance,
            Dense::new(&instance, tables).expect("dense"),
            &mut t_ref,
        )
        .expect("reference");
        let mut t_opt = Transcript::new(b"review/matmul/t").expect("t");
        let mut sc = Vec::new();
        let optimised = stele_sumcheck::prove(
            &instance,
            MatmulSummand {
                rem: 1usize << nv,
                eq: new_eq,
                lhs: new_l,
                rhs: new_r,
                point: &mut sc,
            },
            &mut t_opt,
        )
        .expect("optimised");
        assert_eq!(optimised, reference, "case {case} bytes");
        assert_eq!(
            t_opt.challenge(ChallengeLabel::RelationPoint).expect("c"),
            t_ref.challenge(ChallengeLabel::RelationPoint).expect("c")
        );
    }
    assert!(base_tables > 100 && ext_tables > 100 && with_eq > 100);
}

fn a8_range_fixture() -> (Relation, ColumnId) {
    let mut rel = Relation::default();
    let g = rel.add_group("L0/review-a8/3", 3);
    let x = rel.add_column("x", Kind::Witness(g), Width::unsigned(2), 3);
    rel.ranges.push(Range {
        name: "rx".into(),
        column: x,
        width: Width::unsigned(2),
    });
    (rel, x)
}

/// A8 block claim point: instance 1's leaves, multiplicities and member values are all
/// taken from block 0's data while block 1 of the commitment holds an out-of-range value.
/// A verifier that routed the block claim to `z_low` alone would accept.
#[test]
fn rejects_a8_block_claims_served_from_another_block() {
    let (rel, x) = a8_range_fixture();
    let mut committed = Values::new(&rel);
    committed
        .set(&rel, x, vec![0, 1, 2, 3, 0, 1, 2, 9])
        .expect("committed");
    let mut fake = Values::new(&rel);
    fake.set(&rel, x, vec![0, 1, 2, 3, 0, 1, 2, 3])
        .expect("fake");
    let plan = plan_with_bound(&rel, Sources::CircleAll, 2).expect("plan");
    assert_eq!(plan.checks.len(), 2);
    let mut t = Transcript::new(PUBLIC).expect("t");
    let proof = prove_plan(&mut t, &rel, &plan, &committed, &fake, &[], None).expect("bytes");
    let mut t = Transcript::new(PUBLIC).expect("t");
    assert_eq!(
        verify_with_instance_bound(&mut t, &rel, &[], &proof, Sources::CircleAll, 2).err(),
        Some(Error::Pcs(stele_pcs::Error::ValueMismatch))
    );
    // Proved honestly from the commitment, the out-of-range value fails its own instance.
    let mut t = Transcript::new(PUBLIC).expect("t");
    let proof = prove_with_instance_bound(&mut t, &rel, &committed, &[], Sources::CircleAll, 2)
        .expect("bytes");
    let mut t = Transcript::new(PUBLIC).expect("t");
    assert_eq!(
        verify_with_instance_bound(&mut t, &rel, &[], &proof, Sources::CircleAll, 2).err(),
        Some(Error::Fraction(stele_lookup::fraction::Error::RootMismatch))
    );
}

/// A8 through the segmented (`stele-dev-e2e-v2`) prover and verifier, which the reviewed
/// commits extend but never run with `B < 30`.
#[test]
fn accepts_a8_segmented_split_and_rejects_out_of_range_block_values() {
    let (rel, x) = a8_range_fixture();
    let mut values = Values::new(&rel);
    values
        .set(&rel, x, vec![3, 1, 2, 3, 0, 2, 1, 0])
        .expect("x");
    for set in [
        Sources::Expander,
        Sources::CircleAll,
        Sources::CircleAllGrind,
    ] {
        let mut t = Transcript::new(PUBLIC).expect("t");
        let (v2, _) = prove_segmented_measured_with_instance_bound(
            &mut t,
            &rel,
            |_| Ok(values.clone()),
            &[],
            set,
            2,
        )
        .expect("v2");
        let mut t = Transcript::new(PUBLIC).expect("t");
        verify_segmented_with_instance_bound(&mut t, &rel, &[], &v2, set, 2).expect("accept");
        let mut t = Transcript::new(PUBLIC).expect("t");
        let v1 = prove_with_instance_bound(&mut t, &rel, &values, &[], set, 2).expect("v1");
        assert_eq!(v2.segments[0].multiplicities, v1.multiplicities);
        assert_eq!(v2.segments[0].lookups, v1.lookups);
        assert_eq!(v2.segments[0].openings, v1.openings);
        // Any other bound is a different plan.
        for other in [1u8, 3, 30] {
            let mut t = Transcript::new(PUBLIC).expect("t");
            let outcome = verify_segmented_with_instance_bound(&mut t, &rel, &[], &v2, set, other);
            assert!(outcome.is_err());
        }
        // An out-of-range value in block 1 fails in the segmented verifier too.
        let mut bad = Values::new(&rel);
        bad.set(&rel, x, vec![3, 1, 2, 3, 0, 2, 1, 4]).expect("x");
        let mut t = Transcript::new(PUBLIC).expect("t");
        let (forged, _) = prove_segmented_measured_with_instance_bound(
            &mut t,
            &rel,
            |_| Ok(bad.clone()),
            &[],
            set,
            2,
        )
        .expect("bytes");
        let mut t = Transcript::new(PUBLIC).expect("t");
        assert_eq!(
            verify_segmented_with_instance_bound(&mut t, &rel, &[], &forged, set, 2).err(),
            Some(Error::Fraction(stele_lookup::fraction::Error::RootMismatch))
        );
    }
}

/// The three-segment fixture (weights, carried columns, a matmul) under every small bound.
#[test]
fn accepts_a8_three_segments_under_small_instance_bounds() {
    let (rel, seg_vals, full) = three_segment_fixture();
    let messages = model_messages(&rel, &full).expect("messages");
    let sources = Sources::CircleAll;
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
    let mut t = Transcript::new(PUBLIC).expect("t");
    let (reference, _) = prove_segmented_measured(
        &mut t,
        &rel,
        |s| Ok(seg_vals[s as usize].clone()),
        &model,
        sources,
    )
    .expect("default");
    // Per check: id, size and each member's (size, block bits, block index).
    type CheckLayout = (u64, u8, Vec<(u8, u8, usize)>);
    let layout = |bound: u8| -> Vec<CheckLayout> {
        plan_segmented_with_bound(&rel, sources, bound)
            .expect("plan")
            .segments
            .iter()
            .flat_map(|s| s.checks.iter())
            .map(|c| {
                (
                    c.id,
                    c.m,
                    c.members
                        .iter()
                        .map(|m| (m.m, m.block_bits, m.block_index))
                        .collect(),
                )
            })
            .collect()
    };
    for bound in [1u8, 2, 3, 4, 30] {
        let mut t = Transcript::new(PUBLIC).expect("t");
        let (proof, _) = prove_segmented_measured_with_instance_bound(
            &mut t,
            &rel,
            |s| Ok(seg_vals[s as usize].clone()),
            &model,
            sources,
            bound,
        )
        .expect("prove");
        let mut t = Transcript::new(PUBLIC).expect("t");
        verify_segmented_with_instance_bound(&mut t, &rel, &refs, &proof, sources, bound)
            .expect("accept");
        // Exactly the unsplit plans keep every byte.
        assert_eq!(
            proof == reference,
            layout(bound) == layout(30),
            "bound {bound}"
        );
        if layout(bound) != layout(30) {
            let mut t = Transcript::new(PUBLIC).expect("t");
            assert!(verify_segmented(&mut t, &rel, &refs, &proof, sources).is_err());
        }
    }
}

/// RFC-0026 A30: a check's bound is `min(B, max(25, m − 2))`. At most `2^25` positions
/// are one instance, a larger check has at most four up to `m = B + 2`, and a plan bound
/// below the floor, as the split tests pass, is kept.
#[test]
fn matches_reference_instance_bound_of_a_check() {
    for (bound, positions, expected) in [
        (30u8, 0u64, 25u8),
        (30, 1, 25),
        (30, 1 << 25, 25),
        (30, (1 << 25) + 1, 25),
        (30, 74_202_368, 25),
        (30, 1 << 27, 25),
        (30, (1 << 27) + 1, 26),
        (30, 1 << 31, 29),
        (30, 1 << 32, 30),
        (30, (1 << 32) + 1, 30),
        (30, u64::MAX, 30),
        (26, 1 << 30, 26),
        (6, 1 << 27, 6),
        (2, 9, 2),
    ] {
        assert_eq!(
            check_bound(bound, positions),
            expected,
            "{bound} {positions}"
        );
    }
}

/// RFC-0026 A30 in a plan: ranges of 8 bits over `2^26 + 2^22 + 2^21 + 2^19` positions, the
/// shape of L2a's largest check, are three instances of `2^25`, `2^25` and `2^23`
/// positions, the first two the blocks of the largest member. A check of `2^25` positions
/// stays one instance under its unsplit name.
#[test]
fn matches_reference_split_of_a_check_above_the_floor() {
    let mut rel = Relation::default();
    for (i, n) in [26u8, 22, 21, 19].into_iter().enumerate() {
        let g = Kind::Witness(rel.add_group(&alloc::format!("G/a30/{i}"), n));
        let x = rel.add_column(&alloc::format!("x{i}"), g, Width::unsigned(8), n);
        rel.ranges.push(Range {
            name: alloc::format!("r{i}"),
            column: x,
            width: Width::unsigned(8),
        });
    }
    let g = Kind::Witness(rel.add_group("G/a30/whole", 25));
    let y = rel.add_column("y", g, Width::unsigned(4), 25);
    rel.ranges.push(Range {
        name: "whole".to_string(),
        column: y,
        width: Width::unsigned(4),
    });
    assert_eq!(rel.validate(), Ok(()));
    let plan = plan(&rel, Sources::CircleAll).expect("plan");
    // One line per instance: name, domain bits, and each member's bits and block index.
    let shape: Vec<String> = plan
        .checks
        .iter()
        .map(|c| {
            let members: Vec<(u8, usize)> =
                c.members.iter().map(|m| (m.m, m.block_index)).collect();
            alloc::format!("{} {} {members:?}", c.name, c.m)
        })
        .collect();
    assert_eq!(
        shape,
        [
            "range_8/inst0 25 [(25, 0)]",
            "range_8/inst1 25 [(25, 1)]",
            "range_8/inst2 23 [(22, 0), (21, 0), (19, 0)]",
            "range_4 25 [(25, 0)]",
        ]
    );
}

/// The verifier's selector extension (`lookup::sigma_at`) against the vector the provers
/// build (`lookup::sigma_base`), at random points: absent, natural, permuted and narrower
/// public selectors, under every instance bound `1..=6`, where a selector also reads the
/// bits of its block. An entry other than 0 or 1 is `Selector`, as it is for the vector.
#[test]
fn matches_reference_selector_extension_of_the_selector_vector() {
    use stele_lookup::fraction;
    let mut rng = SeededRng(457);
    let mut draw = Transcript::<K>::new(b"test/selector-extension").expect("t");
    let mut point = |m: u8| -> Vec<K> {
        (0..m)
            .map(|_| draw.challenge(ChallengeLabel::Sumcheck).expect("c"))
            .collect()
    };
    // Members with an absent, natural, permuted and narrower selector.
    let mut shapes = [0usize; 4];
    for case in 0..24u64 {
        let mut rel = Relation::default();
        let table = rel.add_table(Table {
            name: "test/u2".to_string(),
            widths: vec![Width::unsigned(2)],
            rows: (0..4).map(|v| vec![v]).collect(),
        });
        let mut selectors = Vec::new();
        for i in 0..2 + rng.below(4) {
            let n = 1 + rng.below(6) as u8;
            let g = Kind::Witness(rel.add_group(&alloc::format!("G/test/{case}/{i}"), n));
            let x = rel.add_column(&alloc::format!("x{i}"), g, Width::unsigned(2), n);
            rel.ranges.push(Range {
                name: alloc::format!("r{i}"),
                column: x,
                width: Width::unsigned(2),
            });
            let shape = rng.below(4) as usize;
            shapes[shape] += 1;
            let selector = (shape > 0).then(|| {
                let mut vars: Vec<u8> = (0..n).collect();
                if shape > 1 {
                    for j in (1..vars.len()).rev() {
                        vars.swap(j, rng.below(j as u64 + 1) as usize);
                    }
                }
                if shape == 3 {
                    vars.truncate(rng.below(u64::from(n)) as usize);
                }
                let entries = (0..1usize << vars.len())
                    .map(|_| rng.below(2) as i64)
                    .collect();
                let column = rel.add_column(
                    &alloc::format!("sel{i}"),
                    Kind::Public(entries),
                    Width::unsigned(1),
                    vars.len() as u8,
                );
                selectors.push(column);
                Ref { column, vars }
            });
            rel.lookups.push(Lookup {
                name: alloc::format!("l{i}"),
                vars: n,
                selector,
                tuple: vec![Ref::identity(x, n)],
                table,
            });
        }
        assert_eq!(rel.validate(), Ok(()), "case {case}");
        for bound in 1..=6u8 {
            let plan = plan_with_bound(&rel, Sources::CircleAll, bound).expect("plan");
            for check in &plan.checks {
                let z = point(check.m);
                let weights = stele_poly::eq_table(&z).expect("eq");
                let expected = lookup::sigma_base(check, &rel)
                    .iter()
                    .zip(&weights)
                    .fold(K::from_i64(0), |sum, (s, w)| sum + w.mul_m31(*s));
                assert_eq!(
                    lookup::sigma_at(check, &rel, &z),
                    Ok(expected),
                    "case {case} bound {bound} check {}",
                    check.name
                );
            }
        }
        if let Some(column) = selectors.first() {
            let plan = plan_with_bound(&rel, Sources::CircleAll, 6).expect("plan");
            if let Kind::Public(entries) = &mut rel.columns[column.0 as usize].kind {
                entries[0] = 2;
            }
            let refused = plan
                .checks
                .iter()
                .filter(|check| {
                    lookup::sigma_at(check, &rel, &point(check.m)) == Err(fraction::Error::Selector)
                })
                .count();
            assert_eq!(refused, 1, "case {case}");
        }
    }
    assert!(shapes.iter().all(|&n| n > 8), "{shapes:?}");
}

/// Random lookups and ranges under every bound `1..=6`: each original position is in
/// exactly one instance, honest proofs verify, one out-of-table value is rejected by a
/// root equation, and a verifier with another bound never accepts a differently split proof.
#[test]
fn matches_reference_a8_split_plans_cover_every_position_once() {
    let mut rng = SeededRng(41);
    for case in 0..12u64 {
        let mut rel = Relation::default();
        let table = rel.add_table(Table {
            name: "review/u2".to_string(),
            widths: vec![Width::unsigned(2)],
            rows: (0..4).map(|v| vec![v]).collect(),
        });
        let mut set: Vec<(ColumnId, Vec<i64>)> = Vec::new();
        let mut positions = 0usize;
        for i in 0..2 + rng.below(4) {
            let n = 1 + rng.below(5) as u8;
            let g = Kind::Witness(rel.add_group(&alloc::format!("G/review/{case}/{i}"), n));
            let x = rel.add_column(&alloc::format!("x{i}"), g, Width::unsigned(2), n);
            let v: Vec<i64> = (0..1usize << n).map(|_| rng.below(4) as i64).collect();
            rel.ranges.push(Range {
                name: alloc::format!("r{i}"),
                column: x,
                width: Width::unsigned(2),
            });
            positions += 1 << n;
            if rng.below(2) == 0 {
                // The same column again through a selected lookup with reversed bits.
                let sel_v: Vec<i64> = (0..1usize << n).map(|_| rng.below(2) as i64).collect();
                let sel = rel.add_column(
                    &alloc::format!("sel{i}"),
                    Kind::Public(sel_v),
                    Width::unsigned(1),
                    n,
                );
                let reversed = |column| Ref {
                    column,
                    vars: (0..n).rev().collect(),
                };
                rel.lookups.push(Lookup {
                    name: alloc::format!("l{i}"),
                    vars: n,
                    selector: Some(reversed(sel)),
                    tuple: vec![reversed(x)],
                    table,
                });
                positions += 1 << n;
            }
            set.push((x, v));
        }
        assert_eq!(rel.validate(), Ok(()), "case {case}");
        let mut values = Values::new(&rel);
        for (id, v) in &set {
            values.set(&rel, *id, v.clone()).expect("set");
        }
        // One out-of-table value somewhere.
        let (bad_col, bad_v) = &set[rng.below(set.len() as u64) as usize];
        let mut bad_v = bad_v.clone();
        let at = rng.below(bad_v.len() as u64) as usize;
        bad_v[at] = 4 + rng.below(60) as i64;
        let mut bad = values.clone();
        bad.set(&rel, *bad_col, bad_v).expect("set");
        let mut proofs = Vec::new();
        for bound in 1..=6u8 {
            let plan = plan_with_bound(&rel, Sources::CircleAll, bound).expect("plan");
            // Coverage: (tuple column, selector, member-domain position) seen exactly once.
            let mut seen = alloc::collections::BTreeSet::new();
            let mut ids = alloc::collections::BTreeSet::new();
            let mut layout = Vec::new();
            for check in &plan.checks {
                assert!(check.m <= bound, "case {case} bound {bound}");
                assert!(ids.insert(check.id) && ids.len() <= plan.checks.len());
                let mut total = 0usize;
                for member in &check.members {
                    assert!(member.m <= bound);
                    assert_eq!(member.offset, total);
                    total += 1 << member.m;
                    for local in 0..1usize << member.m {
                        let position = (member.block_index << member.m) | local;
                        let key = (
                            member.tuple[0].0.column,
                            member.selector.as_ref().map(|s| s.column),
                            position,
                        );
                        assert!(seen.insert(key), "position covered twice");
                    }
                    layout.push((check.id, member.m, member.block_bits, member.block_index));
                }
                assert!(total <= 1 << bound);
            }
            assert_eq!(seen.len(), positions, "case {case} bound {bound}");
            let mut t = Transcript::new(PUBLIC).expect("t");
            let proof =
                prove_with_instance_bound(&mut t, &rel, &values, &[], Sources::CircleAll, bound)
                    .expect("prove");
            let mut t = Transcript::new(PUBLIC).expect("t");
            verify_with_instance_bound(&mut t, &rel, &[], &proof, Sources::CircleAll, bound)
                .expect("accept");
            let mut t = Transcript::new(PUBLIC).expect("t");
            let forged =
                prove_with_instance_bound(&mut t, &rel, &bad, &[], Sources::CircleAll, bound)
                    .expect("bytes");
            let mut t = Transcript::new(PUBLIC).expect("t");
            assert_eq!(
                verify_with_instance_bound(&mut t, &rel, &[], &forged, Sources::CircleAll, bound)
                    .err(),
                Some(Error::Fraction(stele_lookup::fraction::Error::RootMismatch)),
                "case {case} bound {bound}"
            );
            proofs.push((bound, layout, proof));
        }
        for (b1, l1, proof) in &proofs {
            for (b2, l2, _) in &proofs {
                let mut t = Transcript::new(PUBLIC).expect("t");
                let outcome =
                    verify_with_instance_bound(&mut t, &rel, &[], proof, Sources::CircleAll, *b2);
                if l1 == l2 {
                    assert!(outcome.is_ok(), "same plan under B={b1} and B={b2}");
                } else {
                    // Another split has another instance count: the sections miscount.
                    assert_eq!(
                        outcome.err(),
                        Some(Error::ProofShape),
                        "B={b1} under B={b2}"
                    );
                }
            }
        }
    }
}

/// A8 with a virtual tuple member (RFC-0026 A28, RFC-0008 A9): the block claim of a split
/// `Linear` column is absorbed, reduced at `(bits(block) ‖ z_low)` and bound to its operands.
#[test]
fn rejects_a8_out_of_range_sum_of_a_split_virtual_member() {
    let build = || {
        let mut rel = Relation::default();
        let g = rel.add_group("L0/review-a8v/3", 3);
        let x = rel.add_column("x", Kind::Witness(g), Width::unsigned(2), 3);
        let y = rel.add_column("y", Kind::Witness(g), Width::unsigned(2), 3);
        for (name, column) in [("rx", x), ("ry", y)] {
            rel.ranges.push(Range {
                name: name.into(),
                column,
                width: Width::unsigned(2),
            });
        }
        let v = rel.add_column(
            "v",
            Kind::Virtual(Def::Linear {
                constant: 0,
                terms: vec![(1, Ref::identity(x, 3)), (1, Ref::identity(y, 3))],
            }),
            Width::unsigned(0),
            3,
        );
        // x + y must stay in [0, 4): only the range on the virtual column says so.
        rel.ranges.push(Range {
            name: "rv".into(),
            column: v,
            width: Width::unsigned(2),
        });
        (rel, x, y)
    };
    let (rel, x, y) = build();
    assert_eq!(rel.validate(), Ok(()));
    let mut honest = Values::new(&rel);
    honest
        .set(&rel, x, vec![0, 1, 2, 3, 1, 0, 2, 1])
        .expect("x");
    honest
        .set(&rel, y, vec![3, 2, 1, 0, 1, 3, 0, 2])
        .expect("y");
    let mut bad = Values::new(&rel);
    bad.set(&rel, x, vec![0, 1, 2, 3, 1, 0, 2, 2]).expect("x"); // 2 + 2 = 4 in block 1
    bad.set(&rel, y, vec![3, 2, 1, 0, 1, 3, 0, 2]).expect("y");
    for bound in [1u8, 2, 3, 30] {
        let run = |values: &Values| {
            let mut t = Transcript::new(PUBLIC).expect("t");
            let (proof, _) = prove_segmented_measured_with_instance_bound(
                &mut t,
                &rel,
                |_| Ok(values.clone()),
                &[],
                Sources::CircleAll,
                bound,
            )
            .expect("bytes");
            let mut t = Transcript::new(PUBLIC).expect("t");
            verify_segmented_with_instance_bound(
                &mut t,
                &rel,
                &[],
                &proof,
                Sources::CircleAll,
                bound,
            )
            .map(|_| ())
        };
        assert_eq!(run(&honest), Ok(()), "bound {bound}");
        assert_eq!(
            run(&bad),
            Err(Error::Fraction(stele_lookup::fraction::Error::RootMismatch)),
            "bound {bound}"
        );
    }
}

// The A8 control through the segmented engine (review F2).

/// The A8 control of RFC-0026 through the segmented verifier, which real proofs use
/// (`stele-prover` routes every relation with virtual columns to `verify_segmented`).
#[test]
fn rejects_a8_member_value_moved_across_instance_boundary_in_the_segmented_engine() {
    use stele_ir::relation::Range;
    let mut rel = Relation::default();
    let g = rel.add_group("L0/a8ctrl/3", 3);
    let x = rel.add_column("x", Kind::Witness(g), Width::unsigned(2), 3);
    rel.ranges.push(Range {
        name: "rx".into(),
        column: x,
        width: Width::unsigned(2),
    });
    let mut moved = Values::new(&rel);
    moved
        .set(&rel, x, vec![3, 1, 2, 3, 0, 2, 1, 0])
        .expect("moved");
    for set in [
        Sources::Expander,
        Sources::CircleAll,
        Sources::CircleAllGrind,
    ] {
        let honest = plan_segmented_with_bound(&rel, set, 2).expect("plan");
        assert_eq!(honest.segments[0].checks.len(), 2);
        let run = |plan: &SegmentedPlan| {
            let mut t = Transcript::new(PUBLIC).expect("t");
            let (proof, _) = prove_segmented_with_plan(
                &mut t,
                &rel,
                plan,
                0,
                |_| Ok(moved.clone()),
                &[],
                None,
                None,
            )
            .expect("bytes");
            let mut t = Transcript::new(PUBLIC).expect("t");
            verify_segmented_with_instance_bound(&mut t, &rel, &[], &proof, set, 2).map(|_| ())
        };
        assert_eq!(run(&honest), Ok(()));
        // The receiving instance keeps the multiplicities of the unmoved values.
        let mut forged = plan_segmented_with_bound(&rel, set, 2).expect("plan");
        forged.segments[0].checks[1].count_override = Some(vec![1, 1, 1, 1]);
        assert_eq!(
            run(&forged),
            Err(Error::Fraction(stele_lookup::fraction::Error::RootMismatch))
        );
        // The sending instance keeps them instead: its own root equation rejects.
        let mut forged = plan_segmented_with_bound(&rel, set, 2).expect("plan");
        forged.segments[0].checks[0].count_override = Some(vec![1, 1, 1, 1]);
        assert_eq!(
            run(&forged),
            Err(Error::Fraction(stele_lookup::fraction::Error::RootMismatch))
        );
        // Both instances swap their (individually wrong, jointly complete) multiplicities.
        let mut forged = plan_segmented_with_bound(&rel, set, 2).expect("plan");
        forged.segments[0].checks[0].count_override = Some(vec![2, 1, 1, 0]);
        forged.segments[0].checks[1].count_override = Some(vec![0, 1, 1, 2]);
        assert_eq!(
            run(&forged),
            Err(Error::Fraction(stele_lookup::fraction::Error::RootMismatch))
        );
    }
}

// Selectors of split lookup members (RFC-0026 A8, §3.3; review F2).

/// A selected lookup into a table smaller than the column's range, cut into blocks.
/// Unselected positions hold out-of-table values, so each block must read its own part
/// of the public selector: honest proofs verify, a selected out-of-table value in the
/// second block is rejected by that instance, and an unselected one is not.
#[test]
fn rejects_a8_selected_out_of_table_values_in_split_blocks() {
    for reversed in [false, true] {
        let mut rel = Relation::default();
        let g = rel.add_group("L0/review-a8s/3", 3);
        let x = rel.add_column("x", Kind::Witness(g), Width::unsigned(2), 3);
        rel.ranges.push(Range {
            name: "rx".into(),
            column: x,
            width: Width::unsigned(2),
        });
        let sel_v = vec![1, 0, 1, 0, 0, 1, 0, 1];
        let sel = rel.add_column("sel", Kind::Public(sel_v.clone()), Width::unsigned(1), 3);
        let table = rel.add_table(Table {
            name: "review/bit".to_string(),
            widths: vec![Width::unsigned(2)],
            rows: vec![vec![0], vec![1]],
        });
        let r = |column| Ref {
            column,
            vars: if reversed {
                vec![2, 1, 0]
            } else {
                vec![0, 1, 2]
            },
        };
        rel.lookups.push(Lookup {
            name: "bit".to_string(),
            vars: 3,
            selector: Some(r(sel)),
            tuple: vec![r(x)],
            table,
        });
        assert_eq!(rel.validate(), Ok(()));
        // Selected entries (sel = 1) hold 0/1, the others 2/3.
        let honest = vec![0, 3, 1, 2, 3, 1, 2, 0];
        let with = |index: usize, value: i64| {
            let mut v = honest.clone();
            v[index] = value;
            let mut values = Values::new(&rel);
            values.set(&rel, x, v).expect("x");
            values
        };
        for bound in [1u8, 2, 3] {
            let v1 = |values: &Values| {
                let mut t = Transcript::new(PUBLIC).expect("t");
                let proof =
                    prove_with_instance_bound(&mut t, &rel, values, &[], Sources::CircleAll, bound)
                        .expect("bytes");
                let mut t = Transcript::new(PUBLIC).expect("t");
                verify_with_instance_bound(&mut t, &rel, &[], &proof, Sources::CircleAll, bound)
                    .map(|_| ())
            };
            let v2 = |values: &Values| {
                let mut t = Transcript::new(PUBLIC).expect("t");
                let (proof, _) = prove_segmented_measured_with_instance_bound(
                    &mut t,
                    &rel,
                    |_| Ok(values.clone()),
                    &[],
                    Sources::CircleAll,
                    bound,
                )
                .expect("bytes");
                let mut t = Transcript::new(PUBLIC).expect("t");
                verify_segmented_with_instance_bound(
                    &mut t,
                    &rel,
                    &[],
                    &proof,
                    Sources::CircleAll,
                    bound,
                )
                .map(|_| ())
            };
            let root = Err(Error::Fraction(stele_lookup::fraction::Error::RootMismatch));
            for run in [&v1 as &dyn Fn(&Values) -> Result<(), Error>, &v2] {
                assert_eq!(run(&with(0, 0)), Ok(()), "honest, bound {bound}");
                // Every selected entry in turn takes an in-range, out-of-table value.
                for index in (0..8).filter(|i| sel_v[*i] == 1) {
                    assert_eq!(
                        run(&with(index, 2)),
                        root,
                        "selected {index}, bound {bound}"
                    );
                }
                // Every unselected entry may hold any in-range value.
                for index in (0..8).filter(|i| sel_v[*i] == 0) {
                    for value in 0..4 {
                        assert_eq!(run(&with(index, value)), Ok(()), "unselected {index}");
                    }
                }
            }
        }
    }
}

/// RFC-0008 A5 multiplicities of a range block longer than one histogram piece equal a
/// direct count (task E20-23): pieces are added in order and every position counts once.
#[test]
fn matches_reference_range_multiplicities_past_one_histogram_piece() {
    // Two pieces of 2^16 positions.
    let bits = 17;
    let mut rel = Relation::default();
    let g = rel.add_group("L0/hist/17", bits);
    let x = rel.add_column("x", Kind::Witness(g), Width::unsigned(4), bits);
    rel.ranges.push(Range {
        name: "rx".into(),
        column: x,
        width: Width::unsigned(4),
    });
    let mut state = 7u64;
    let xs: Vec<i64> = (0..1usize << bits)
        .map(|_| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (state >> 60) as i64
        })
        .collect();
    let mut values = Values::new(&rel);
    values.set(&rel, x, xs.clone()).expect("x");
    let plan = plan(&rel, Sources::CircleAll).expect("plan");
    assert_eq!(plan.checks.len(), 1);
    let resolved = ResolvedColumns::borrowed(&rel, &values);
    let counted = lookup::counts(&plan.checks[0], &rel, &resolved).expect("counts");
    let mut expected = vec![0i64; counted.len()];
    for v in &xs {
        expected[*v as usize] += 1;
    }
    assert_eq!(counted, expected);
    // Both pieces hold values: the second piece's counts are in the total.
    assert_eq!(counted.iter().sum::<i64>(), 1 << bits);
}

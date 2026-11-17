//! RFC-0008 A7 / RFC-0014 §6: observe genuine steps without changing a proof.
#![cfg(feature = "bench")]
use stele_field::{Field, M31, QM31};
use stele_hash::{ChallengeLabel, Transcript};
use stele_reductions::zk::claims::{
    self, bench, Column, Geometry, Lifetime, Lookup, Member, ModelSecret, Public, Read, Statement,
};
use stele_reductions::zk::{Error, Seed};

#[path = "common/gkr_construction.rs"]
mod construction;

fn case(compact: bool) -> (Statement<QM31>, Vec<Vec<M31>>) {
    if !compact {
        let mut counts = vec![M31::ZERO; 64];
        let values = (0..64)
            .map(|i| {
                let j = (5 * i + 2) % 48;
                counts[j] = counts[j] + M31::ONE;
                M31::from_i64(3 * j as i64 + 1)
            })
            .collect();
        return (
            Statement {
                sources: 1,
                columns: vec![
                    Column {
                        source: 0,
                        log_len: 6
                    };
                    2
                ],
                relations: vec![],
                lookups: vec![Lookup::single(
                    &[0],
                    6,
                    1,
                    (0..64).map(|j| vec![3 * j + 1]).collect(),
                    48,
                )],
            },
            vec![values, counts],
        );
    }
    let member = |column, vars, shift, selector| Member {
        vars,
        tuple: vec![Read {
            column,
            vars: (0..vars).collect(),
        }],
        shifts: vec![shift],
        selector,
    };
    let tail: Vec<M31> = (0..16).map(|i| M31::from_i64(1 + i % 3)).collect();
    let mut counts = vec![M31::from_i64(8), M31::from_i64(4), M31::ZERO, M31::ZERO];
    for value in &tail {
        let j = value.as_u32() as usize - 1;
        counts[j] = counts[j] + M31::ONE;
    }
    (
        Statement {
            sources: 1,
            columns: [1, 2, 4, 2]
                .map(|log_len| Column { source: 0, log_len })
                .to_vec(),
            relations: vec![],
            lookups: vec![Lookup {
                members: vec![
                    member(
                        0,
                        1,
                        1,
                        Some(Public {
                            vars: vec![0],
                            values: vec![1, 0],
                        }),
                    ),
                    member(1, 2, 1, None),
                    member(2, 4, 0, None),
                ],
                multiplicity: 3,
                table: vec![vec![1], vec![2], vec![3], vec![0]],
                valid: 3,
            }],
        },
        vec![
            vec![M31::ZERO, M31::from_i64(-1)],
            vec![M31::ZERO, M31::ONE, M31::ZERO, M31::ONE],
            tail,
            counts,
        ],
    )
}

fn transcript() -> Transcript<QM31> {
    Transcript::new(b"gkr observation reference").expect("transcript")
}

#[test]
fn matches_reference_gkr_observation_and_complete_finals() {
    let mut constructed = [false; 8];
    for (compact, geometry, byte) in [
        (false, None, 17),
        (true, None, 29),
        (true, Some(Geometry::Balanced), 41),
        (true, Some(Geometry::Narrow), 53),
    ] {
        let balanced = geometry.is_some();
        let (statement, columns) = case(compact);
        let life = Lifetime {
            geometry: geometry.unwrap_or(Geometry::Balanced),
            source: 0,
            proofs: 1,
            index: 0,
            blocks: claims::occurrence_counts(&statement).expect("occurrence counts"),
        };
        let model_seed = [91; 32];
        let root = if balanced {
            claims::lifetime_root(&statement, &columns, &life, &model_seed).expect("model root")
        } else {
            [0; 32]
        };
        let model = || ModelSecret {
            seed: &model_seed,
            revealed: vec![],
            root,
        };
        let mut ordinary_t = transcript();
        let ordinary = if balanced {
            let (proof, disclosure) = claims::prove_lifetime(
                &statement,
                &columns,
                Seed::new([byte; 32]),
                &mut ordinary_t,
                &life,
                model(),
            )
            .expect("ordinary lifetime proof");
            (proof, Some(disclosure))
        } else {
            (
                claims::prove(&statement, &columns, Seed::new([byte; 32]), &mut ordinary_t)
                    .expect("ordinary proof"),
                None,
            )
        };
        let mut seen = [0; 3];
        let mut compact_seen = 0;
        let mut observed_t = transcript();
        let observed = bench::observe_gkr(
            &statement,
            &columns,
            Seed::new([byte; 32]),
            &mut observed_t,
            balanced.then(|| (&life, model())),
            &mut |step| {
                assert_eq!(step.step, seen.iter().sum::<usize>());
                assert_eq!(step.lookup, 0);
                seen[if step.leaf {
                    2
                } else if step.first {
                    0
                } else {
                    1
                }] += 1;
                let mut reference = step.reference()?;
                let inputs = step.construction()?;
                let mut rebuilt = construction::materialize(&inputs, &mut constructed);
                assert_eq!(inputs.num_vars, reference.variables());
                assert_eq!(inputs.degree, reference.degree());
                assert_eq!(rebuilt.terms(), reference.terms());
                assert_eq!(
                    rebuilt.vanishing().collect::<Vec<_>>(),
                    reference.vanishing().collect::<Vec<_>>()
                );
                assert_eq!(
                    rebuilt.tables().collect::<Vec<_>>(),
                    reference.tables().collect::<Vec<_>>()
                );
                compact_seen += usize::from(reference.is_compact());
                assert_eq!(reference.variables() as usize, step.point.len());
                assert_eq!(reference.tables().count(), reference.vanishing().count());
                assert!(!reference.terms().is_empty());
                assert_eq!(
                    reference.final_values(),
                    Err(stele_sumcheck::Error::InvalidInstance)
                );
                for point in step.point {
                    assert_eq!(rebuilt.round(), reference.round());
                    assert_eq!(
                        reference.round().expect("production round").len(),
                        reference.degree() + 1
                    );
                    reference.fold(*point).expect("production fold");
                    rebuilt.fold(*point).expect("constructed fold");
                    assert_eq!(
                        rebuilt.tables().collect::<Vec<_>>(),
                        reference.tables().collect::<Vec<_>>()
                    );
                }
                let finals = reference.final_values().expect("expanded finals");
                assert_eq!(&finals, step.finals);
                let compact_values = reference.tables().map(|(x, _)| x[0]).collect::<Vec<_>>();
                let mut changed_compact =
                    rebuilt.final_values().expect("constructed compact finals");
                assert_eq!(changed_compact, compact_values);
                changed_compact[0] = changed_compact[0] + QM31::ONE;
                assert_ne!(changed_compact, compact_values);
                assert_eq!(
                    reference.expand_at(step.point, &compact_values),
                    Err(stele_sumcheck::Error::InvalidInstance),
                    "external expansion consumes an unfolded reference"
                );
                assert_eq!(
                    step.reference()?
                        .expand_at(step.point, &compact_values)
                        .expect("external compact expansion"),
                    finals
                );
                assert_eq!(
                    step.reference()?
                        .expand_at(&step.point[..step.point.len() - 1], &compact_values),
                    Err(stele_sumcheck::Error::InvalidInstance)
                );
                assert_eq!(
                    step.reference()?
                        .expand_at(step.point, &compact_values[..compact_values.len() - 1]),
                    Err(stele_sumcheck::Error::InvalidInstance)
                );
                assert_eq!(step.route(&finals)?, step.routed);
                let mut changed = finals;
                changed[0] = changed[0] + QM31::ONE;
                assert_eq!(
                    step.route(&changed),
                    Err(Error::Sumcheck(stele_sumcheck::Error::ClaimMismatch))
                );
                assert_eq!(
                    step.route(&changed[..changed.len() - 1]),
                    Err(Error::Sumcheck(stele_sumcheck::Error::ProofShape))
                );
                Ok(())
            },
        )
        .expect("observed proof");
        assert!(seen.iter().all(|n| *n > 0));
        assert_eq!(compact_seen, usize::from(compact));
        assert_eq!(observed, ordinary);
        assert_eq!(claims::encode(&observed.0), claims::encode(&ordinary.0));
        assert_eq!(
            observed_t
                .challenge(ChallengeLabel::FractionGamma)
                .expect("observed continuation"),
            ordinary_t
                .challenge(ChallengeLabel::FractionGamma)
                .expect("ordinary continuation")
        );
        claims::verify_lifetime(
            &statement,
            balanced.then_some(&life),
            &observed.0,
            &mut transcript(),
        )
        .expect("genuine proof verifies");
        if balanced {
            let mut wrong = model();
            wrong.root[0] ^= 1;
            let mut calls = 0;
            assert_eq!(
                bench::observe_gkr(
                    &statement,
                    &columns,
                    Seed::new([43; 32]),
                    &mut transcript(),
                    Some((&life, wrong)),
                    &mut |_| {
                        calls += 1;
                        Err(Error::Statement)
                    },
                )
                .expect_err("wrong model must fail before observation"),
                Error::Pcs(stele_pcs::Error::Merkle(
                    stele_hash::merkle::Error::RootMismatch
                ))
            );
            assert_eq!(calls, 0);
        }
    }
    assert!(constructed.into_iter().all(|seen| seen));
}

#[test]
fn rejects_gkr_observer_failure_and_invalid_witness() {
    let (statement, mut columns) = case(false);
    let mut seen = 0;
    let error = bench::observe_gkr(
        &statement,
        &columns,
        Seed::new([13; 32]),
        &mut transcript(),
        None,
        &mut |_| {
            seen += 1;
            Err(Error::Statement)
        },
    )
    .expect_err("observer failure propagates");
    assert_eq!(error, Error::Statement);
    assert_eq!(seen, 1);
    columns[1][0] = columns[1][0] + M31::ONE;
    let mut seen = 0;
    let error = bench::observe_gkr(
        &statement,
        &columns,
        Seed::new([19; 32]),
        &mut transcript(),
        None,
        &mut |_| {
            seen += 1;
            Ok(())
        },
    )
    .expect_err("false witness is rejected");
    assert_eq!(
        error,
        Error::Sumcheck(stele_sumcheck::Error::RoundSumMismatch)
    );
    assert_eq!(seen, 0);
    columns.pop();
    assert_eq!(
        bench::observe_gkr(
            &statement,
            &columns,
            Seed::new([23; 32]),
            &mut transcript(),
            None,
            &mut |_| {
                seen += 1;
                Err(Error::Statement)
            }
        )
        .expect_err("invalid input must be rejected before observation"),
        Error::Statement
    );
    assert_eq!(seen, 0);
}

#[test]
fn rejects_lifetime_observation_without_disclosure() {
    let (mut statement, mut columns) = case(false);
    statement.sources = 2;
    statement.columns.push(Column {
        source: 1,
        log_len: 1,
    });
    columns.push(vec![M31::ONE; 2]);
    let life = Lifetime {
        geometry: Geometry::Balanced,
        source: 1,
        proofs: 1,
        index: 0,
        blocks: vec![0],
    };
    let model_seed = [91; 32];
    let root = claims::lifetime_root(&statement, &columns, &life, &model_seed)
        .expect("unused model source");
    let model = || ModelSecret {
        seed: &model_seed,
        revealed: vec![],
        root,
    };
    assert_eq!(
        claims::prove_lifetime(
            &statement,
            &columns,
            Seed::new([47; 32]),
            &mut transcript(),
            &life,
            model()
        )
        .err(),
        Some(Error::Statement)
    );
    let mut calls = 0;
    assert_eq!(
        bench::observe_gkr(
            &statement,
            &columns,
            Seed::new([47; 32]),
            &mut transcript(),
            Some((&life, model())),
            &mut |_| {
                calls += 1;
                Ok(())
            }
        )
        .err(),
        Some(Error::Statement)
    );
    assert_eq!(
        calls, 4,
        "the postcondition is checked after genuine GKR steps"
    );
}

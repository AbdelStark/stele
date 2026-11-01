//! RFC-0006 A4: independent original-table rounds and real public consumers.
use std::fmt::Debug;
use stele_field::{Field, M31, OM31, QM31};
use stele_gkr::{
    public_mle::{Axis, Kind},
    stacked::{self, Claim, Error, Limits, Order, Prepared, Statement},
};
use stele_hash::{ChallengeField, Transcript};
use stele_sumcheck::{Summand, Term};

const LIMITS: Limits = Limits {
    descriptor_bytes: 1 << 20,
    proof_bytes: 1 << 20,
    prepared_entries: 1 << 16,
    partial_entries: 1 << 12,
    axis_entries: 1 << 12,
};
const PUBLIC: &[u8] = b"stacked public native";
fn allocation_observations<K: ChallengeField + Eq + Debug>() {
    use std::mem::size_of;
    for (ell, inner) in [(0, 0), (0, 2), (2, 0), (1, 2)] {
        let axes = [
            Axis {
                bits: ell,
                real: 1 << ell,
            },
            Axis {
                bits: inner,
                real: 1 << inner,
            },
        ];
        let m = usize::from(ell + inner);
        let table: Vec<_> = (0..1 << m).map(|n| K::from_i64(n + 2)).collect();
        for order in [Order::LayerFirst, Order::LayerLast] {
            let terms = [Term {
                coefficient: K::from_i64(0),
                factors: vec![0; 3],
            }];
            let s = Statement {
                id: 1,
                axes: &axes,
                order,
                output: Claim {
                    id: 2,
                    axes: &[],
                    point: &[],
                    value: K::from_i64(0),
                },
                coefficient_id: 3,
                inputs: &[4],
                terms: &terms,
                selectors: &[None, None],
                kind: Kind::Eq,
                source_id: None,
            };
            let prepared = Prepared::new(&s, LIMITS).expect("prepared");
            let instance = prepared.instance();
            let nested = instance.inputs.capacity() * size_of::<u64>()
                + instance.terms.capacity() * size_of::<Term<K>>()
                + instance
                    .terms
                    .iter()
                    .map(|t| t.factors.capacity() * size_of::<u32>())
                    .sum::<usize>();
            assert!(prepared.owned_bytes().expect("owned") >= prepared.bytes().len() + nested);
            let mut ordinary = prepared.strategy(&[&table]).expect("strategy");
            let mut dense = prepared.strategy(&[&table]).expect("strategy");
            let initial_owned = dense.owned_bytes().expect("owned");
            assert!(
                initial_owned
                    >= dense.capacity_entries().expect("fields") * size_of::<K>()
                        + 2 * size_of::<Vec<K>>()
            );
            let transcript = || Transcript::<K>::new(PUBLIC).expect("transcript");
            let mut a = transcript();
            let mut b = transcript();
            let expected = ordinary.prove(&mut a).expect("ordinary");
            let mut a1 = vec![stele_sumcheck::RoundWork::default(); m];
            let mut rounds = vec![stacked::DenseRoundWork::default(); m];
            let (proof, work) = dense
                .prove_measured(&mut b, &mut a1, &mut rounds)
                .expect("measured");
            assert_eq!(proof, expected);
            assert_eq!(a.usage(), b.usage());
            assert_eq!(dense.work(), ordinary.work());
            assert_eq!(dense.owned_bytes().expect("retained"), initial_owned);
            assert_eq!(dense.work().rounds, m);
            for ((slot, fold), values) in a1.iter().zip(&rounds).zip(&proof.rounds) {
                assert_eq!(slot.values_bytes, fold.values_bytes);
                assert_eq!(fold.values_bytes, values.capacity() * size_of::<K>());
                assert!(fold.partial_bytes >= (1 << ell) * 5 * size_of::<K>());
                assert!(
                    work.peak_owned_bytes
                        >= slot.proof_prefix_bytes + slot.values_bytes + slot.payload_bytes
                );
            }
            let mut v = transcript();
            let mut mv = transcript();
            let (reduction, usage) = prepared
                .verify_reduction(&mut v, &proof)
                .expect("reduction");
            let ((same, measured), observed) = prepared
                .verify_reduction_measured(&mut mv, &proof)
                .expect("measured reduction");
            assert_eq!(same, reduction);
            assert_eq!(usage, observed);
            assert_eq!(usage, a.usage());
            assert_eq!(measured.point_bytes, same.point.capacity() * size_of::<K>());
            assert_eq!(
                measured.claims_bytes,
                same.claims.capacity() * size_of::<(u64, K)>()
            );
            assert_eq!(dense.into_point().expect("captured"), reduction.point);
            let next = a.challenge(stele_hash::ChallengeLabel::Sumcheck);
            for t in [&mut b, &mut v, &mut mv] {
                assert_eq!(t.challenge(stele_hash::ChallengeLabel::Sumcheck), next);
            }
            // Zero P leaves the coefficient obligation to the actual A7 consumer.
            let mut bad = proof;
            bad.final_values[1] = K::from_i64(2);
            let mut v = transcript();
            let mut mv = transcript();
            let ordinary_failure = prepared.verify_reduction(&mut v, &bad).expect_err("A7");
            let measured = prepared
                .verify_reduction_measured(&mut mv, &bad)
                .expect_err("A7");
            assert_eq!(ordinary_failure, measured);
            assert_eq!(measured.cause, Error::CoefficientMismatch);
            let mut sizes = vec![(m + 1, m), (m, m + 1)];
            if m > 0 {
                sizes.extend([(m - 1, m), (m, m - 1)]);
            }
            for (an, dn) in sizes {
                let mut dense = prepared.strategy(&[&table]).expect("strategy");
                let mut t = transcript();
                let before = t.usage();
                let failure = dense
                    .prove_measured(
                        &mut t,
                        &mut vec![stele_sumcheck::RoundWork::default(); an],
                        &mut vec![stacked::DenseRoundWork::default(); dn],
                    )
                    .expect_err("slot count");
                assert_eq!(failure.cause, Error::Capacity);
                assert_eq!(failure.usage, before);
                assert_eq!(t.usage(), before);
                assert_eq!(dense.work().rounds, 0);
            }
            if m > 0 {
                let before = a.usage();
                let failure = ordinary
                    .prove_measured(&mut a, &mut a1, &mut rounds)
                    .expect_err("pristine");
                assert_eq!(failure.cause, Error::InvalidStacked);
                assert_eq!(failure.usage, before);
            }
        }
    }
}
#[test]
fn matches_reference_qm31_stacked_allocations() {
    allocation_observations::<QM31>();
}
#[test]
fn matches_reference_om31_stacked_allocations() {
    allocation_observations::<OM31>();
}
fn eval<K: Field>(table: &[K], point: &[K]) -> K {
    table
        .iter()
        .enumerate()
        .fold(K::from_i64(0), |sum, (i, value)| {
            let weight = point.iter().enumerate().fold(K::from_i64(1), |w, (j, r)| {
                w * if i >> (point.len() - j - 1) & 1 == 1 {
                    *r
                } else {
                    K::from_i64(1) - *r
                }
            });
            sum + *value * weight
        })
}
fn boolean<K: Field>(axes: &[Axis], selectors: &[Option<&[K]>], kind: Kind<'_>) -> Vec<K> {
    let m: usize = axes.iter().map(|a| usize::from(a.bits)).sum();
    (0..1usize << m)
        .map(|index| {
            let mut shift = m;
            let coordinates: Vec<_> = axes
                .iter()
                .map(|a| {
                    shift -= usize::from(a.bits);
                    (index >> shift) as u64 & ((1u64 << a.bits) - 1)
                })
                .collect();
            if axes.iter().zip(&coordinates).any(|(a, x)| *x >= a.real) {
                return K::from_i64(0);
            }
            let value = match kind {
                Kind::Eq => 1,
                Kind::CausalMask { row, column } => {
                    i64::from(coordinates[column] <= coordinates[row])
                }
                Kind::WindowMask { row, column, width } => i64::from(
                    coordinates[column] <= coordinates[row]
                        && coordinates[row] - coordinates[column] < width,
                ),
                Kind::OnehotSparse {
                    row,
                    column,
                    indices,
                } => i64::from(coordinates[column] == indices[coordinates[row] as usize]),
                Kind::GqaBroadcast { head, group } => i64::from(
                    coordinates[group] == coordinates[head] / (axes[head].real / axes[group].real),
                ),
                Kind::RopeTables {
                    axes: chosen,
                    values,
                } => {
                    let at = chosen.iter().fold(0, |at, a| {
                        at * axes[*a].real as usize + coordinates[*a] as usize
                    });
                    i64::from(values[at].as_u32())
                }
            };
            let mut at = 0;
            axes.iter()
                .zip(selectors)
                .fold(K::from_i64(value), |mut v, (a, z)| {
                    for bit in 0..usize::from(a.bits) {
                        if let Some(z) = z {
                            v = v * if index >> (m - at - 1) & 1 == 1 {
                                z[bit]
                            } else {
                                K::from_i64(1) - z[bit]
                            };
                        }
                        at += 1;
                    }
                    v
                })
        })
        .collect()
}
fn exercise<K: ChallengeField + Eq + Debug>(axes: [Axis; 3]) {
    let ell = usize::from(axes[0].bits);
    let m: usize = axes.iter().map(|a| usize::from(a.bits)).sum();
    let n = 1usize << m;
    // Full extension values come from the real field transcript, independently of the proof.
    let mut randomness = Transcript::<K>::new(b"stacked fixture values").expect("stacked fixture");
    let z = [randomness
        .challenge(stele_hash::ChallengeLabel::Sumcheck)
        .expect("stacked fixture")];
    let layer_z = vec![z[0]; ell];
    let row_z = vec![z[0]; usize::from(axes[1].bits)];
    let selectors = [Some(&layer_z[..]), Some(&row_z[..]), None];
    let indices: Vec<_> = (0..axes[1].real).map(|i| (i + 1) % axes[2].real).collect();
    let values: Vec<_> = (0..axes[0].real * axes[1].real)
        .map(|i| M31::from_i64(i as i64 + 7))
        .collect();
    let kinds = [
        Kind::Eq,
        Kind::CausalMask { row: 1, column: 2 },
        Kind::WindowMask {
            row: 1,
            column: 2,
            width: 1,
        },
        Kind::OnehotSparse {
            row: 1,
            column: 2,
            indices: &indices,
        },
        Kind::GqaBroadcast { head: 1, group: 2 },
        Kind::RopeTables {
            axes: &[0, 1],
            values: &values,
        },
    ];
    let validity = boolean::<K>(&axes, &[None; 3], Kind::Eq);
    let originals: Vec<Vec<K>> = (0..2)
        .map(|input| {
            (0..n)
                .map(|i| {
                    if validity[i] == K::from_i64(0) {
                        K::from_i64(0)
                    } else {
                        K::from_i64((input * 9 + i + 2) as i64) + z[0]
                    }
                })
                .collect()
        })
        .collect();
    let tables: Vec<_> = originals.iter().map(Vec::as_slice).collect();
    for kind in kinds {
        for order in [Order::LayerFirst, Order::LayerLast] {
            let coefficient = boolean(&axes, &selectors, kind);
            let terms = [Term {
                coefficient: K::from_i64(3),
                factors: vec![1, 1, 1],
            }];
            let value = (0..n).fold(K::from_i64(0), |sum, i| {
                sum + coefficient[i]
                    * K::from_i64(3)
                    * originals[1][i]
                    * originals[1][i]
                    * originals[1][i]
            });
            let statement = Statement {
                id: 31,
                axes: &axes,
                order,
                output: Claim {
                    id: 50,
                    axes: &[],
                    point: &[],
                    value,
                },
                coefficient_id: 90,
                inputs: &[41, 42],
                terms: &terms,
                selectors: &selectors,
                kind,
                source_id: if matches!(kind, Kind::OnehotSparse { .. } | Kind::RopeTables { .. }) {
                    Some(99)
                } else {
                    None
                },
            };
            let mut prover = Transcript::new(PUBLIC).expect("stacked fixture");
            let proof = stacked::prove_public(&mut prover, &statement, &tables, LIMITS)
                .expect("stacked fixture");
            let measured_next = if matches!(kind, Kind::Eq) {
                let mut measured = Transcript::new(PUBLIC).expect("measurement");
                let (same, work) =
                    stacked::prove_public_measured(&mut measured, &statement, &tables, LIMITS)
                        .expect("measured producer");
                assert_eq!(same, proof);
                assert_eq!(measured.usage(), prover.usage());
                assert_eq!(work.rounds, m);
                assert!(work.dense_entries >= 3 * n + m);
                if m == 0 {
                    assert_eq!(
                        (
                            work.partial_entries,
                            work.round_entries,
                            work.round_scratch_entries
                        ),
                        (0, 0, 0)
                    );
                } else {
                    assert!(work.partial_entries >= (1 << ell) * 5);
                    assert!(work.round_entries >= 5);
                    assert!(work.round_scratch_entries >= work.partial_entries + 5);
                }
                Some(measured.challenge(stele_hash::ChallengeLabel::Sumcheck))
            } else {
                None
            };
            let mut verifier = Transcript::new(PUBLIC).expect("stacked fixture");
            let (record, usage) =
                stacked::verify_public(&mut verifier, &statement, &proof, &tables, LIMITS)
                    .expect("stacked fixture");
            assert_eq!(usage, prover.usage());
            assert_eq!(record.sc().numerator, 4 * m as u64);
            assert_eq!(record.claims().len(), 2);
            for (table, (_, value)) in tables.iter().zip(record.claims()) {
                assert_eq!(eval(table, record.point()), *value);
            }
            let next = prover.challenge(stele_hash::ChallengeLabel::Sumcheck);
            assert_eq!(
                next,
                verifier.challenge(stele_hash::ChallengeLabel::Sumcheck)
            );
            if let Some(expected) = measured_next {
                assert_eq!(next, expected);
            }
            let prepared = Prepared::new(&statement, LIMITS).expect("stacked fixture");
            let mut dense = prepared.strategy(&tables).expect("stacked fixture");
            assert_eq!(
                dense.work().dense_entries,
                dense.capacity_entries().expect("capacity")
            );
            let mut pi: Vec<_> = (0..m).collect();
            if order == Order::LayerLast {
                pi.rotate_left(ell);
            }
            for j in 0..m {
                let before = dense.work();
                let partials = dense.partials().expect("stacked fixture");
                assert_eq!(dense.work(), before);
                if matches!(kind, Kind::Eq) {
                    let strategy = &mut dense;
                    let round = strategy.round(prepared.instance()).expect("observed round");
                    assert_eq!(round, proof.rounds[j]);
                    assert_eq!(dense.work().rounds, before.rounds + 1);
                    assert!(dense.work().round_entries >= round.capacity());
                }
                assert_eq!(partials.len(), (1 << ell) * 5);
                let mut expected = vec![K::from_i64(0); (1 << ell) * 5];
                for suffix in 0..1usize << (m - j - 1) {
                    for node in 0..5 {
                        let mut point = vec![K::from_i64(0); m];
                        for fixed in 0..j {
                            point[pi[fixed]] = record.point()[pi[fixed]];
                        }
                        point[pi[j]] = K::from_i64(node as i64);
                        let mut owner = 0;
                        for (at, axis) in pi[j + 1..].iter().enumerate() {
                            let bit = suffix >> (pi.len() - j - 2 - at) & 1;
                            point[*axis] = K::from_i64(bit as i64);
                            if *axis < ell {
                                owner |= bit << (ell - axis - 1);
                            }
                        }
                        let x = eval(&originals[1], &point);
                        expected[owner * 5 + node] = expected[owner * 5 + node]
                            + eval(&coefficient, &point) * K::from_i64(3) * x * x * x;
                    }
                }
                assert_eq!(partials, expected);
                for node in 0..5 {
                    let sum = partials
                        .chunks_exact(5)
                        .fold(K::from_i64(0), |sum, b| sum + b[node]);
                    assert_eq!(sum, proof.rounds[j][node]);
                }
                (&mut dense)
                    .fold(record.point()[pi[j]])
                    .expect("stacked fixture");
            }
            let strategy = &mut dense;
            assert_eq!(
                strategy.final_values().expect("stacked fixture"),
                proof.final_values
            );
            let mut changed = proof.clone();
            changed.final_values[0] = changed.final_values[0] + K::from_i64(1);
            let failure = stacked::verify_public(
                &mut Transcript::new(PUBLIC).expect("stacked fixture"),
                &statement,
                &changed,
                &tables,
                LIMITS,
            )
            .err()
            .expect("stacked fixture");
            assert_eq!(failure.cause, Error::ClaimMismatch);
            assert_eq!(failure.usage, usage);
        }
    }
}
#[test]
fn matches_reference_qm31_stacked_rounds_and_consumers() {
    cases::<QM31>();
}
#[test]
fn matches_reference_om31_stacked_rounds_and_consumers() {
    cases::<OM31>();
}
fn cases<K: ChallengeField + Eq + Debug>() {
    for (ell, real, bits, rows, columns) in [
        (1, 1, 1, 2, 2),
        (2, 3, 1, 2, 2),
        (0, 1, 1, 2, 2),
        (2, 3, 0, 1, 1),
        (1, 2, 2, 4, 2),
        (0, 1, 0, 1, 1),
    ] {
        exercise::<K>([
            Axis { bits: ell, real },
            Axis { bits, real: rows },
            Axis {
                bits,
                real: columns,
            },
        ]);
    }
}

#[test]
fn rejects_preflight_without_transcript_mutation() {
    let axes = [Axis { bits: 0, real: 1 }];
    let s = Statement {
        id: 1,
        axes: &axes,
        order: Order::LayerLast,
        output: Claim {
            id: 2,
            axes: &[],
            point: &[],
            value: QM31::ZERO,
        },
        coefficient_id: 3,
        inputs: &[],
        terms: &[],
        selectors: &[None],
        kind: Kind::Eq,
        source_id: None,
    };
    let proof = stele_sumcheck::Proof {
        rounds: vec![],
        final_values: vec![QM31::ONE],
    };
    let mut t = Transcript::new(PUBLIC).expect("stacked fixture");
    let before = t.usage();
    let low = Limits {
        prepared_entries: 0,
        ..LIMITS
    };
    let failure = stacked::verify_public(&mut t, &s, &proof, &[], low)
        .err()
        .expect("stacked fixture");
    assert_eq!(failure.cause, Error::Capacity);
    assert_eq!(failure.usage, before);
    assert_eq!(t.usage(), before);
    let ordinary_failure = stacked::prove_public(&mut t, &s, &[], low).expect_err("ordinary cap");
    let measured_failure =
        stacked::prove_public_measured(&mut t, &s, &[], low).expect_err("measured cap");
    assert_eq!(ordinary_failure, measured_failure);
    assert_eq!(t.usage(), before);
    let honest = stacked::prove_public(&mut t, &s, &[], LIMITS).expect("stacked fixture");
    assert_eq!(honest, proof);
    let mut bad = honest;
    bad.final_values[0] = QM31::ZERO;
    let failure = stacked::verify_public(
        &mut Transcript::new(PUBLIC).expect("stacked fixture"),
        &s,
        &bad,
        &[],
        LIMITS,
    )
    .err()
    .expect("stacked fixture");
    assert_eq!(failure.cause, Error::CoefficientMismatch);
    assert!(failure.usage.state_updates > before.state_updates);
}

fn degenerate<K: ChallengeField + Eq + Debug>() {
    for (ell, inner) in [(0, 0), (0, 2), (2, 0), (2, 1)] {
        let axes = [
            Axis {
                bits: ell,
                real: 1 << ell,
            },
            Axis {
                bits: inner,
                real: 1 << inner,
            },
        ];
        let n = 1usize << (ell + inner);
        let original: Vec<_> = (0..n).map(|i| K::from_i64(i as i64 + 2)).collect();
        for inputs in [&[][..], &[41][..]] {
            for mode in 0..3 {
                for order in [Order::LayerFirst, Order::LayerLast] {
                    if mode == 2 && inputs.is_empty() {
                        continue;
                    }
                    let terms = match mode {
                        0 => vec![],
                        1 => vec![Term {
                            coefficient: K::from_i64(3),
                            factors: vec![],
                        }],
                        _ => vec![Term {
                            coefficient: K::from_i64(0),
                            factors: vec![0, 0, 0],
                        }],
                    };
                    let s = Statement {
                        id: 1,
                        axes: &axes,
                        order,
                        output: Claim {
                            id: 2,
                            axes: &[],
                            point: &[],
                            value: K::from_i64(if mode == 1 { 3 * n as i64 } else { 0 }),
                        },
                        coefficient_id: 3,
                        inputs,
                        terms: &terms,
                        selectors: &[None, None],
                        kind: Kind::Eq,
                        source_id: None,
                    };
                    let tables = if inputs.is_empty() {
                        vec![]
                    } else {
                        vec![&original[..]]
                    };
                    let proof = stacked::prove_public(
                        &mut Transcript::new(PUBLIC).expect("transcript"),
                        &s,
                        &tables,
                        LIMITS,
                    )
                    .expect("degenerate proof");
                    let mut t = Transcript::new(PUBLIC).expect("transcript");
                    let (record, _) = stacked::verify_public(&mut t, &s, &proof, &tables, LIMITS)
                        .expect("degenerate closure");
                    let degree = [0, 1, 4][mode];
                    assert_eq!(record.sc().degree, degree);
                    assert_eq!(
                        record.sc().numerator,
                        u64::from(ell + inner) * u64::from(degree)
                    );
                    assert_eq!(record.claims().len(), inputs.len());
                    if mode != 1 {
                        let mut changed = proof;
                        changed.final_values[inputs.len()] = K::from_i64(2);
                        let failure = stacked::verify_public(
                            &mut Transcript::new(PUBLIC).expect("transcript"),
                            &s,
                            &changed,
                            &tables,
                            LIMITS,
                        )
                        .err()
                        .expect("coefficient rejected");
                        assert_eq!(failure.cause, Error::CoefficientMismatch);
                    }
                }
            }
        }
    }
}
#[test]
fn accepts_empty_constant_and_zero_coefficient_relations() {
    degenerate::<QM31>();
    degenerate::<OM31>();
}

#[test]
fn rejects_unaddressable_storage_before_any_transcript_work() {
    let unlimited = Limits {
        descriptor_bytes: usize::MAX,
        proof_bytes: usize::MAX,
        prepared_entries: usize::MAX,
        partial_entries: usize::MAX,
        axis_entries: usize::MAX,
    };
    for bits in [59, 60, 61, 62, 63] {
        let axes = [Axis {
            bits,
            real: 1u64 << bits,
        }];
        let s = Statement {
            id: 1,
            axes: &axes,
            order: Order::LayerFirst,
            output: Claim {
                id: 2,
                axes: &[],
                point: &[],
                value: OM31::ZERO,
            },
            coefficient_id: 3,
            inputs: &[],
            terms: &[],
            selectors: &[None],
            kind: Kind::Eq,
            source_id: None,
        };
        let mut t = Transcript::new(PUBLIC).expect("transcript");
        let before = t.usage();
        let proof = stele_sumcheck::Proof {
            rounds: vec![],
            final_values: vec![],
        };
        let failure = stacked::verify_public(&mut t, &s, &proof, &[], unlimited)
            .err()
            .expect("addressability");
        assert_eq!(failure.cause, Error::Capacity);
        assert_eq!(failure.usage, before);
        assert_eq!(t.usage(), before);
    }
}

#[test]
fn rejects_malformed_statements_sources_and_proofs() {
    let axes = [Axis { bits: 1, real: 1 }, Axis { bits: 1, real: 2 }];
    let original = [2, 3, 0, 0].map(QM31::from_i64);
    let make = || Statement {
        id: 1,
        axes: &axes,
        order: Order::LayerLast,
        output: Claim {
            id: 2,
            axes: &[],
            point: &[],
            value: QM31::ZERO,
        },
        coefficient_id: 3,
        inputs: &[41],
        terms: &[],
        selectors: &[None, None],
        kind: Kind::Eq,
        source_id: None,
    };
    let proof = stacked::prove_public(
        &mut Transcript::new(PUBLIC).expect("transcript"),
        &make(),
        &[&original],
        LIMITS,
    )
    .expect("baseline");
    let reject = |s: &Statement<'_, QM31>,
                  p: &stele_sumcheck::Proof<QM31>,
                  tables: &[&[QM31]],
                  limits,
                  expected| {
        let mut t = Transcript::new(PUBLIC).expect("transcript");
        let mut unchanged = Transcript::new(PUBLIC).expect("transcript");
        for transcript in [&mut t, &mut unchanged] {
            transcript
                .absorb(stele_hash::AbsorbLabel::Final, b"earlier segment")
                .expect("prior frame");
        }
        let before = t.usage();
        let failure = stacked::verify_public(&mut t, s, p, tables, limits)
            .err()
            .expect("structural rejection");
        assert_eq!(failure.cause, expected);
        assert_eq!(failure.usage, before);
        assert_eq!(t.usage(), before);
        assert_eq!(
            t.challenge(stele_hash::ChallengeLabel::Sumcheck),
            unchanged.challenge(stele_hash::ChallengeLabel::Sumcheck)
        );
    };
    for bits in 0..=64 {
        let malformed = [Axis { bits, real: 0 }];
        let mut s = make();
        s.axes = &malformed;
        reject(&s, &proof, &[&original], LIMITS, Error::InvalidStacked);
    }
    let mut s = make();
    s.inputs = &[41, 41];
    reject(&s, &proof, &[&original], LIMITS, Error::InvalidStacked);
    let mut s = make();
    s.coefficient_id = 41;
    reject(&s, &proof, &[&original], LIMITS, Error::InvalidStacked);
    let mut s = make();
    s.output.id = 41;
    reject(&s, &proof, &[&original], LIMITS, Error::InvalidStacked);
    let mut s = make();
    s.output.point = &[QM31::ZERO];
    reject(&s, &proof, &[&original], LIMITS, Error::InvalidStacked);
    let invalid_terms = [Term {
        coefficient: QM31::ZERO,
        factors: vec![0; 4],
    }];
    let mut s = make();
    s.terms = &invalid_terms;
    reject(&s, &proof, &[&original], LIMITS, Error::InvalidStacked);
    let invalid_terms = [Term {
        coefficient: QM31::ZERO,
        factors: vec![1],
    }];
    let mut s = make();
    s.terms = &invalid_terms;
    reject(&s, &proof, &[&original], LIMITS, Error::InvalidStacked);
    for source in [None, Some(2), Some(3), Some(41)] {
        let mut s = make();
        s.kind = Kind::OnehotSparse {
            row: 0,
            column: 1,
            indices: &[0],
        };
        s.source_id = source;
        reject(&s, &proof, &[&original], LIMITS, Error::InvalidStacked);
    }
    for tables in [
        vec![],
        vec![&original[..3]],
        vec![&original[..], &original[..]],
    ] {
        reject(&make(), &proof, &tables, LIMITS, Error::PublicShape);
    }
    let padding = [QM31::ZERO, QM31::ZERO, QM31::ONE, QM31::ZERO];
    reject(&make(), &proof, &[&padding], LIMITS, Error::PublicShape);
    for limits in [
        Limits {
            descriptor_bytes: 0,
            ..LIMITS
        },
        Limits {
            proof_bytes: 0,
            ..LIMITS
        },
        Limits {
            prepared_entries: 0,
            ..LIMITS
        },
        Limits {
            partial_entries: 0,
            ..LIMITS
        },
    ] {
        reject(&make(), &proof, &[&original], limits, Error::Capacity);
    }
    let source_values = [M31::ONE; 2];
    let mut s = make();
    s.kind = Kind::RopeTables {
        axes: &[1],
        values: &source_values,
    };
    s.source_id = Some(99);
    reject(
        &s,
        &proof,
        &[&original],
        Limits {
            axis_entries: 0,
            ..LIMITS
        },
        Error::Capacity,
    );
    for rounds in 0..5 {
        for finals in 0..5 {
            if rounds == 2 && finals == 2 {
                continue;
            }
            let bad = stele_sumcheck::Proof {
                rounds: vec![vec![QM31::ZERO]; rounds],
                final_values: vec![QM31::ZERO; finals],
            };
            reject(
                &make(),
                &bad,
                &[&original],
                LIMITS,
                Error::Sumcheck(stele_sumcheck::Error::ProofShape),
            );
        }
    }
    for round in 0..proof.rounds.len() {
        for width in [0, 2] {
            let mut bad = proof.clone();
            bad.rounds[round] = vec![QM31::ZERO; width];
            reject(
                &make(),
                &bad,
                &[&original],
                LIMITS,
                Error::Sumcheck(stele_sumcheck::Error::ProofShape),
            );
        }
    }
}

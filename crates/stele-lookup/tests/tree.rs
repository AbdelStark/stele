//! Conditional tree consumers and complete accounting, RFC-0008 A3 / RFC-0012 A9.
use stele_field::{OM31, QM31};
use stele_hash::{ChallengeField, ChallengeLabel, Transcript};
use stele_lookup::fraction::{Descriptor, Error};

fn check<K: ChallengeField + Eq + core::fmt::Debug>() {
    let mut rng =
        Transcript::<K>::new(b"1000 seeded full-field tree cases").expect("fixture generator");
    for case in 0..1000 {
        let m = case % 5;
        let b = case / 5 % (m + 1);
        {
            let mut next = || {
                rng.challenge(ChallengeLabel::Sumcheck)
                    .expect("fixture draw")
            };
            let theta: Vec<_> = (0..m - b)
                .map(|_| {
                    if case % 7 == 0 {
                        K::from_i64(i64::from(case % 2))
                    } else {
                        next()
                    }
                })
                .collect();
            let d = Descriptor::new(77, m, b, [91, 92], &theta).expect("descriptor");
            let leaves: Vec<_> = (0..1 << m)
                .map(|_| {
                    [
                        next(),
                        if case % 11 == 0 {
                            K::from_i64(0)
                        } else {
                            next()
                        },
                    ]
                })
                .collect();
            let mut pt = Transcript::new(b"original source context").expect("transcript");
            let (proof, pr) = d.prove(&leaves, &mut pt).expect("honest prover");
            let mut vt = Transcript::new(b"original source context").expect("transcript");
            let vr = d
                .verify_public(&proof, &leaves, &mut vt)
                .expect("actual original consumer");
            assert_eq!(pr, vr);
            assert_eq!(vr.claims.map(|c| c.0), [91, 92]);
            assert_eq!(vr.point.len(), m as usize);
            assert_eq!(vr.accounting.tree_id, 77);
            assert_eq!(vr.accounting.gamma, u64::from(m));
            assert_eq!(vr.accounting.fold, u64::from(m));
            assert_eq!(vr.accounting.field_degree, K::DEGREE as u8);
            assert_eq!(vr.accounting.layers.len(), m as usize);
            for (k, record) in vr.accounting.layers.iter().enumerate() {
                assert_eq!(
                    (
                        record.id,
                        record.m,
                        record.degree,
                        record.field_degree,
                        record.numerator
                    ),
                    (k as u64, k as u32, 3, K::DEGREE as u8, 3 * k as u64)
                );
            }
            assert_eq!(
                pt.challenge(ChallengeLabel::Sumcheck),
                vt.challenge(ChallengeLabel::Sumcheck)
            );
            let mut wrong = proof.clone();
            wrong.root[0] = wrong.root[0] + K::from_i64(1);
            let error = d
                .verify_public(
                    &wrong,
                    &leaves,
                    &mut Transcript::new(b"original source context").expect("transcript"),
                )
                .expect_err("root binding");
            assert_eq!(
                error,
                if m == 0 {
                    Error::LeafMismatch
                } else {
                    Error::Sumcheck(stele_sumcheck::Error::FinalEvaluationMismatch)
                }
            );
            let mut malformed = proof.clone();
            malformed.steps.push(stele_sumcheck::Proof {
                rounds: vec![],
                final_values: vec![],
            });
            let mut invalid = Transcript::new(b"shape").expect("transcript");
            assert_eq!(
                d.verify(&malformed, &mut invalid).expect_err("shape"),
                Error::ProofShape
            );
            assert_eq!(
                invalid.challenge(ChallengeLabel::Sumcheck),
                Transcript::<K>::new(b"shape")
                    .expect("transcript")
                    .challenge(ChallengeLabel::Sumcheck)
            );
        }
    }
}
#[test]
fn accepts_qm31_fraction_tree_original_consumers() {
    check::<QM31>();
}
#[test]
fn accepts_om31_fraction_tree_original_consumers() {
    check::<OM31>();
}

fn check_base_leaves_parity<K: ChallengeField + Eq + core::fmt::Debug>() {
    use stele_field::{Field, M31};
    use stele_lookup::fraction::BaseLeaves;

    let one = K::from_i64(1);
    for m in [0u32, 1, 2, 5] {
        let len = 1usize << m;
        for b in [m, m.saturating_sub(1)] {
            let mut seed = Transcript::<K>::new(b"e20-02-tree-seed").expect("t");
            let alpha = seed.challenge(ChallengeLabel::Sumcheck).expect("alpha");
            let beta = seed.challenge(ChallengeLabel::Sumcheck).expect("beta");
            let theta: Vec<K> = (0..(m - b))
                .map(|_| seed.challenge(ChallengeLabel::Sumcheck).expect("theta"))
                .collect();
            let d = Descriptor::new(42, m, b, [10, 11], &theta).expect("desc");
            let sigma: Vec<M31> = (0..len)
                .map(|i| if i % 5 == 0 { M31::ZERO } else { M31::ONE })
                .collect();
            // Include both in-table and out-of-table values (for malicious-prover fallback).
            let x0: Vec<M31> = (0..len)
                .map(|i| {
                    if i + 1 == len && len > 2 {
                        M31::from_i64(70_000)
                    } else {
                        M31::from_i64((i * 13 + 3) as i64 % 64)
                    }
                })
                .collect();
            let x1: Vec<M31> = (0..len)
                .map(|i| M31::from_i64(((i * 7 + 1) % 31) as i64 - 15))
                .collect();

            // 1. SmallDomain (both pair-table <= 256 and denom-only 512).
            let leaves_c1: Vec<[K; 2]> = (0..len)
                .map(|i| {
                    let s = one.mul_m31(sigma[i]);
                    [s, one - s + s * (alpha - one.mul_m31(x0[i]))]
                })
                .collect();
            let mut t_ref = Transcript::new(b"e20-02-c1").expect("t");
            let (ref_p, ref_r) = d.prove(&leaves_c1, &mut t_ref).expect("ref");
            let ref_next = t_ref.challenge(ChallengeLabel::Sumcheck);
            for table_size in [64usize, 512usize] {
                let mut t_opt = Transcript::new(b"e20-02-c1").expect("t");
                let (opt_p, opt_r) = d
                    .prove_base_leaves(
                        BaseLeaves::SmallDomain {
                            sigma: &sigma,
                            values: &x0,
                            alpha,
                            table_size,
                        },
                        &mut t_opt,
                    )
                    .expect("opt");
                assert_eq!(opt_p, ref_p);
                assert_eq!(opt_r, ref_r);
                assert_eq!(t_opt.challenge(ChallengeLabel::Sumcheck), ref_next);
            }

            // 2. General (c = 2).
            let leaves_c2: Vec<[K; 2]> = (0..len)
                .map(|i| {
                    let s = one.mul_m31(sigma[i]);
                    let row = one.mul_m31(x0[i]) + beta * one.mul_m31(x1[i]);
                    [s, one - s + s * (alpha - row)]
                })
                .collect();
            let mut t_ref2 = Transcript::new(b"e20-02-c2").expect("t");
            let (ref_p2, ref_r2) = d.prove(&leaves_c2, &mut t_ref2).expect("ref2");
            let xs = vec![x0, x1];
            let mut t_opt2 = Transcript::new(b"e20-02-c2").expect("t");
            let (opt_p2, opt_r2) = d
                .prove_base_leaves(
                    BaseLeaves::General {
                        sigma: &sigma,
                        xs: &xs,
                        alpha,
                        beta,
                    },
                    &mut t_opt2,
                )
                .expect("opt2");
            assert_eq!(opt_p2, ref_p2);
            assert_eq!(opt_r2, ref_r2);
            assert_eq!(
                t_opt2.challenge(ChallengeLabel::Sumcheck),
                t_ref2.challenge(ChallengeLabel::Sumcheck)
            );
        }
    }
}

#[test]
fn matches_reference_base_leaves_fraction_tree_qm31_and_om31() {
    check_base_leaves_parity::<QM31>();
    check_base_leaves_parity::<OM31>();
}
#[test]
fn rejects_fraction_tree_source_shape_and_poles() {
    use stele_field::{Field, M31};
    use stele_lookup::fraction::{check_roots, BaseLeaves};
    let z = QM31::from_i64(0);
    let o = QM31::from_i64(1);
    let d = Descriptor::<QM31>::new(0, 63, 63, [0, 1], &[]).expect("maximum shape");
    assert_eq!(
        d.prove(&[], &mut Transcript::new(b"shape").expect("transcript"))
            .expect_err("short source"),
        Error::SourceShape
    );
    assert_eq!(check_roots([z, z], [z, o]), Err(Error::Pole));
    assert_eq!(check_roots([z, o], [z, z]), Err(Error::Pole));
    assert_eq!(check_roots([o, o], [z, o]), Err(Error::RootMismatch));
    assert_eq!(check_roots([o, o], [o, o]), Ok(()));

    // E20-02 F1: mismatched BuiltTree / BuiltBaseTree depth rejects before touching transcript.
    let d2 = Descriptor::<QM31>::new(1, 2, 2, [0, 1], &[]).expect("d2");
    let d3 = Descriptor::<QM31>::new(2, 3, 3, [0, 1], &[]).expect("d3");
    let leaves2 = vec![[o, o]; 4];
    let built2 = d2.build_levels(&leaves2).expect("built2");
    let mut t_built = Transcript::new(b"shape-built").expect("t");
    let before_built = t_built.usage();
    assert_eq!(
        d3.prove_built(built2, &mut t_built),
        Err(Error::SourceShape)
    );
    assert_eq!(t_built.usage(), before_built);

    let sigma2 = vec![M31::ONE; 4];
    let vals2 = vec![M31::ZERO; 4];
    let alpha = QM31::from_i64(77);
    let base2 = BaseLeaves::SmallDomain {
        sigma: &sigma2,
        values: &vals2,
        alpha,
        table_size: 16,
    };
    let built_base2 = d2.build_base_levels(base2).expect("built_base2");
    let sigma3 = vec![M31::ONE; 8];
    let vals3 = vec![M31::ZERO; 8];
    let base3 = BaseLeaves::SmallDomain {
        sigma: &sigma3,
        values: &vals3,
        alpha,
        table_size: 16,
    };
    let mut t_base = Transcript::new(b"shape-base").expect("t");
    let before_base = t_base.usage();
    assert_eq!(
        d3.prove_built_base(base3, built_base2, &mut t_base),
        Err(Error::SourceShape)
    );
    assert_eq!(t_base.usage(), before_base);

    // Non-Boolean sigma parity (exercises `else` branches in SmallDomain and General).
    let sigma_nb = vec![M31::ZERO, M31::ONE, M31::from_i64(3), M31::from_i64(5)];
    let x0_nb = vec![
        M31::from_i64(2),
        M31::from_i64(10),
        M31::from_i64(7),
        M31::from_i64(99),
    ];
    let x1_nb = vec![
        M31::from_i64(4),
        M31::from_i64(1),
        M31::from_i64(8),
        M31::from_i64(6),
    ];
    let beta = QM31::from_i64(19);
    let ref_c1: Vec<[QM31; 2]> = (0..4)
        .map(|i| {
            let s = o.mul_m31(sigma_nb[i]);
            [s, o - s + s * (alpha - o.mul_m31(x0_nb[i]))]
        })
        .collect();
    let mut tr1 = Transcript::new(b"nb-c1").expect("t");
    let (rp1, rr1) = d2.prove(&ref_c1, &mut tr1).expect("ref");
    let mut to1 = Transcript::new(b"nb-c1").expect("t");
    let (op1, or1) = d2
        .prove_base_leaves(
            BaseLeaves::SmallDomain {
                sigma: &sigma_nb,
                values: &x0_nb,
                alpha,
                table_size: 16,
            },
            &mut to1,
        )
        .expect("opt");
    assert_eq!((op1, or1), (rp1, rr1));
    let ref_c2: Vec<[QM31; 2]> = (0..4)
        .map(|i| {
            let s = o.mul_m31(sigma_nb[i]);
            let row = o.mul_m31(x0_nb[i]) + beta * o.mul_m31(x1_nb[i]);
            [s, o - s + s * (alpha - row)]
        })
        .collect();
    let mut tr2 = Transcript::new(b"nb-c2").expect("t");
    let (rp2, rr2) = d2.prove(&ref_c2, &mut tr2).expect("ref2");
    let xs_nb = vec![x0_nb, x1_nb];
    let mut to2 = Transcript::new(b"nb-c2").expect("t");
    let (op2, or2) = d2
        .prove_base_leaves(
            BaseLeaves::General {
                sigma: &sigma_nb,
                xs: &xs_nb,
                alpha,
                beta,
            },
            &mut to2,
        )
        .expect("opt2");
    assert_eq!((op2, or2), (rp2, rr2));
}

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
#[test]
fn rejects_fraction_tree_source_shape_and_poles() {
    use stele_field::Field;
    use stele_lookup::fraction::check_roots;
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
}

//! RFC-0006 A1: actual allocation observations preserve the production protocol.
use std::{cell::Cell, fmt::Debug, mem::size_of};
use stele_field::{OM31, QM31};
use stele_hash::{ChallengeField, ChallengeLabel, Transcript};
use stele_sumcheck::{
    prove, prove_measured, verify, verify_measured, Dense, Error, Instance, RoundWork, Summand,
    Term,
};

// Deliberately different capacities per round catch length-based observations
// and combining unrelated maxima instead of the actual retained proof prefix.
struct Roomy<K> {
    dense: Dense<K>,
    calls: Cell<usize>,
}
impl<K: ChallengeField> Summand<K> for Roomy<K> {
    fn shape(&self) -> (u32, usize) {
        self.dense.shape()
    }
    fn round(&self, i: &Instance<K>) -> Result<Vec<K>, Error> {
        let mut values = self.dense.round(i)?;
        let extra = [41, 3, 19][self.calls.get()];
        values.reserve_exact(extra);
        self.calls.set(self.calls.get() + 1);
        Ok(values)
    }
    fn fold(&mut self, r: K) -> Result<(), Error> {
        self.dense.fold(r)
    }
    fn final_values(&self) -> Result<Vec<K>, Error> {
        let mut values = self.dense.final_values()?;
        values.reserve_exact(29);
        Ok(values)
    }
}
fn exercise<K: ChallengeField + Eq + Debug>() {
    for m in 0..=3 {
        for degree in 0..=4 {
            let table: Vec<_> = (0..1 << m).map(|n| K::from_i64(n + 2)).collect();
            let i = Instance {
                id: 71,
                num_vars: m,
                inputs: vec![81, 82],
                terms: vec![Term {
                    coefficient: K::from_i64(2),
                    factors: vec![0; degree],
                }],
                claimed_sum: table.iter().fold(K::from_i64(0), |sum, x| {
                    sum + (0..degree).fold(K::from_i64(2), |p, _| p * *x)
                }),
            };
            let strategy = || Roomy {
                dense: Dense::new(&i, vec![table.clone(), table.clone()]).expect("fixture"),
                calls: Cell::new(0),
            };
            let transcript = || Transcript::<K>::new(b"measured A1").expect("fixture");
            let mut ordinary = transcript();
            let expected = prove(&i, strategy(), &mut ordinary).expect("fixture");
            let mut measured = transcript();
            let mut rounds = vec![RoundWork::default(); m as usize];
            let (proof, work) =
                prove_measured(&i, strategy(), &mut measured, &mut rounds).expect("fixture");
            assert_eq!(proof, expected);
            assert_eq!(measured.usage(), ordinary.usage());
            let headers = proof.rounds.capacity() * size_of::<Vec<K>>();
            assert_eq!(work.round_headers_bytes, headers);
            let mut prefix = headers;
            let mut peak = prefix + work.instance_bytes;
            for (values, round) in proof.rounds.iter().zip(&rounds) {
                assert_eq!(round.proof_prefix_bytes, prefix);
                assert_eq!(round.values_bytes, values.capacity() * size_of::<K>());
                assert!(round.values_bytes > values.len() * size_of::<K>());
                assert!(round.payload_bytes >= 12 + values.len() * 4 * K::DEGREE);
                peak = peak.max(prefix + round.values_bytes + round.payload_bytes);
                prefix += round.values_bytes;
            }
            assert_eq!(
                work.final_values_bytes,
                proof.final_values.capacity() * size_of::<K>()
            );
            assert_eq!(work.proof_bytes, prefix + work.final_values_bytes);
            assert_eq!(
                work.peak_owned_bytes,
                peak.max(work.proof_bytes + work.final_payload_bytes)
            );
            let mut native = transcript();
            let reduction = verify(&i, &proof, &mut native).expect("fixture");
            let mut observed = transcript();
            let (same, verifier) = verify_measured(&i, &proof, &mut observed).expect("fixture");
            assert_eq!(same.point, reduction.point);
            assert_eq!(same.claims, reduction.claims);
            assert_eq!(same.sc, reduction.sc);
            assert_eq!(verifier.point_bytes, same.point.capacity() * size_of::<K>());
            assert_eq!(
                verifier.claims_bytes,
                same.claims.capacity() * size_of::<(u64, K)>()
            );
            assert_eq!(
                verifier.peak_owned_bytes,
                verifier.point_bytes
                    + verifier.claims_bytes
                    + verifier
                        .instance_bytes
                        .max(verifier.round_payload_bytes)
                        .max(verifier.final_payload_bytes)
            );
            assert_eq!(observed.usage(), ordinary.usage());
            let following = Instance {
                id: 91,
                num_vars: 1,
                inputs: vec![92],
                terms: vec![Term {
                    coefficient: K::from_i64(1),
                    factors: vec![0],
                }],
                claimed_sum: K::from_i64(3),
            };
            let tables = vec![vec![K::from_i64(1), K::from_i64(2)]];
            let successor = prove(
                &following,
                Dense::new(&following, tables.clone()).expect("following"),
                &mut ordinary,
            )
            .expect("following");
            for t in [&mut measured, &mut native, &mut observed] {
                let _record = stele_sumcheck::verify_public(&following, &successor, &tables, t)
                    .expect("following consumer");
                assert_eq!(t.usage(), ordinary.usage());
            }
            let next = ordinary.challenge(ChallengeLabel::Sumcheck);
            for t in [&mut measured, &mut native, &mut observed] {
                assert_eq!(t.challenge(ChallengeLabel::Sumcheck), next);
            }
            if degree > 0 {
                let mut bad = proof.clone();
                bad.final_values[0] = K::from_i64(0);
                let mut a = transcript();
                let mut b = transcript();
                assert_eq!(
                    verify(&i, &bad, &mut a).expect_err("final"),
                    Error::FinalEvaluationMismatch
                );
                assert_eq!(
                    verify_measured(&i, &bad, &mut b).expect_err("final"),
                    Error::FinalEvaluationMismatch
                );
                assert_eq!(a.usage(), b.usage());
            }
            let mut bad = proof.clone();
            bad.final_values.pop();
            let mut t = transcript();
            let before = t.usage();
            assert_eq!(
                verify_measured(&i, &bad, &mut t).expect_err("shape"),
                Error::ProofShape
            );
            assert_eq!(t.usage(), before);
            let mut wrong = i.clone();
            wrong.claimed_sum = wrong.claimed_sum + K::from_i64(1);
            let mut a = transcript();
            let mut b = transcript();
            let expected_error = if m == 0 {
                Error::FinalEvaluationMismatch
            } else {
                Error::RoundSumMismatch
            };
            assert_eq!(
                prove(&wrong, strategy(), &mut a).expect_err("claim"),
                expected_error
            );
            assert_eq!(
                prove_measured(&wrong, strategy(), &mut b, &mut rounds).expect_err("claim"),
                expected_error
            );
            assert_eq!(a.usage(), b.usage());
            if m > 0 {
                let mut short = transcript();
                let before = short.usage();
                assert_eq!(
                    prove_measured(&i, strategy(), &mut short, &mut rounds[..m as usize - 1])
                        .expect_err("rejected"),
                    Error::Capacity
                );
                assert_eq!(short.usage(), before);
                assert_eq!(
                    short.challenge(ChallengeLabel::Sumcheck),
                    transcript().challenge(ChallengeLabel::Sumcheck)
                );
                let mut bad = proof;
                bad.rounds[0][0] = bad.rounds[0][0] + K::from_i64(1);
                let mut a = transcript();
                let mut b = transcript();
                assert_eq!(
                    verify(&i, &bad, &mut a).expect_err("rejected"),
                    Error::RoundSumMismatch
                );
                assert_eq!(
                    verify_measured(&i, &bad, &mut b).expect_err("rejected"),
                    Error::RoundSumMismatch
                );
                assert_eq!(a.usage(), b.usage());
            }
        }
    }
}
#[test]
fn matches_reference_qm31_allocation_observations() {
    exercise::<QM31>();
}
#[test]
fn matches_reference_om31_allocation_observations() {
    exercise::<OM31>();
}

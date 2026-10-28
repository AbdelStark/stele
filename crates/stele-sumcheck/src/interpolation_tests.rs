//! RFC-0006 A1/A3: checked interpolation through the maximum skip degree.
use super::{interpolate, interpolation_weights, Error};
use alloc::vec::Vec;
use stele_field::{Field, OM31, QM31};
use stele_hash::{ChallengeField, ChallengeLabel, Transcript};
fn polynomial<K: ChallengeField>(x: K, degree: usize) -> K {
    (0..degree).fold(K::from_i64(1), |v, _| v * x) + K::from_i64(3)
}
fn check<K: ChallengeField + Eq + core::fmt::Debug>() {
    let mut transcript = Transcript::<K>::new(b"interpolation test").expect("public");
    for degree in 0..=60 {
        let values: Vec<_> = (0..=degree)
            .map(|n| polynomial(K::from_i64(n as i64), degree))
            .collect();
        let point = transcript
            .challenge(ChallengeLabel::Sumcheck)
            .expect("challenge");
        assert_eq!(
            interpolate(&values, point).expect("distinct nodes"),
            polynomial(point, degree)
        );
    }
    for count in [1, 2, 5, 16, 61] {
        for node in 0..count {
            let weights =
                interpolation_weights::<K>(count, K::from_i64(node as i64)).expect("basis");
            for (index, weight) in weights.iter().enumerate() {
                assert_eq!(*weight, K::from_i64(i64::from(index == node)));
            }
        }
    }
}
#[test]
fn matches_reference_interpolation_through_degree_sixty() {
    check::<QM31>();
    check::<OM31>();
}
#[test]
fn rejects_invalid_interpolation_node_counts() {
    for count in [0, 62, usize::MAX] {
        assert_eq!(
            interpolation_weights::<QM31>(count, QM31::from_i64(0)),
            Err(Error::InvalidInstance)
        );
    }
}

//! Actual A3 resource observations preserve the RFC-0008 A3/A5 proof execution.
use core::mem::size_of;
use stele_field::{OM31, QM31};
use stele_hash::{ChallengeField, ChallengeLabel, Transcript};
use stele_lookup::fraction::{Descriptor, Error, LeafDescriptor, SelectedProduct};

fn transcript<K: ChallengeField>() -> Transcript<K> {
    Transcript::new(b"actual fraction resource observations").expect("fixed prefix")
}

fn check<K: ChallengeField + Eq + core::fmt::Debug>() {
    for m in [0, 3] {
        let n = 1 << m;
        let theta = vec![K::from_i64(0); m as usize];
        let d = Descriptor::new(7, m, 0, [8, 9], &theta).expect("grouped tree");
        let sigma: Vec<_> = (0..n).map(|i| K::from_i64((i % 2) as i64)).collect();
        let xs = vec![vec![K::from_i64(3); n], vec![K::from_i64(4); n]];
        let alpha = K::from_i64(17);
        let beta = K::from_i64(2);
        let leaves: Vec<_> = sigma
            .iter()
            .map(|s| [*s, K::from_i64(1) + *s * K::from_i64(5)])
            .collect();
        let mut ordinary = transcript();
        let (proof, reduction) = d.prove(&leaves, &mut ordinary).expect("ordinary tree");
        let mut measured = transcript();
        let (same, actual, work) = d
            .prove_measured(&leaves, &mut measured)
            .expect("measured tree");
        assert_eq!(same, proof);
        assert_eq!(actual, reduction);
        assert_eq!(measured.usage(), ordinary.usage());
        assert!(work.levels_bytes >= (2 * n - 1) * size_of::<[K; 2]>());
        assert!(work.peak_observed_bytes >= work.levels_bytes + work.dense_bytes);
        assert!(
            work.proof_bytes
                >= proof
                    .steps
                    .iter()
                    .map(
                        |p| (p.rounds.iter().map(Vec::len).sum::<usize>() + p.final_values.len())
                            * size_of::<K>()
                    )
                    .sum()
        );
        assert!(work.point_bytes >= actual.point.capacity() * size_of::<K>());
        if m > 0 {
            // The final Fold grows the new point while the old point still lives.
            assert!(work.point_bytes >= (2 * m as usize - 1) * size_of::<K>());
        }
        let mut verifier = transcript();
        assert_eq!(
            d.verify_public(&proof, &leaves, &mut verifier)
                .expect("actual leaves"),
            actual
        );
        let shape = LeafDescriptor::new(&d, &[10, 11]).expect("original sources");
        let leaf =
            SelectedProduct::new(shape, &actual, &sigma, alpha, beta).expect("selected product");
        let (proof, reduction) = leaf.prove(&xs, &mut ordinary).expect("ordinary leaf");
        let (same, actual, work) = leaf
            .prove_measured(&xs, &mut measured)
            .expect("measured leaf");
        assert_eq!(same, proof);
        assert_eq!(actual, reduction);
        assert_eq!(measured.usage(), ordinary.usage());
        assert_eq!(work.levels_bytes, 0);
        assert!(work.dense_bytes >= (xs.len() + 2) * n * size_of::<K>());
        assert!(work.peak_observed_bytes >= work.dense_bytes);
        assert_eq!(
            leaf.verify_public(&proof, &xs, &mut verifier)
                .expect("actual originals"),
            actual
        );
        let next = ordinary.challenge(ChallengeLabel::Sumcheck);
        assert_eq!(next, measured.challenge(ChallengeLabel::Sumcheck));
        assert_eq!(next, verifier.challenge(ChallengeLabel::Sumcheck));
        assert_eq!(measured.usage(), ordinary.usage());
        assert_eq!(ordinary.usage(), verifier.usage());
    }
}

fn failures<K: ChallengeField + Eq + core::fmt::Debug>() {
    let d = Descriptor::<K>::new(7, 0, 0, [8, 9], &[]).expect("scalar tree");
    let mut ordinary = transcript();
    let mut measured = transcript();
    assert_eq!(
        d.prove(&[], &mut ordinary).expect_err("shape"),
        Error::SourceShape
    );
    assert_eq!(
        d.prove_measured(&[], &mut measured).expect_err("shape"),
        Error::SourceShape
    );
    assert_eq!(ordinary.usage(), measured.usage());
    let leaves = [[K::from_i64(1), K::from_i64(2)]];
    let (_, original) = d.prove(&leaves, &mut ordinary).expect("tree");
    let (_, same) = d.prove(&leaves, &mut measured).expect("same tree");
    assert_eq!(same, original);
    let shape = LeafDescriptor::new(&d, &[10]).expect("source");
    let sigma = [K::from_i64(1)];
    let leaf = SelectedProduct::new(shape, &original, &sigma, K::from_i64(3), K::from_i64(1))
        .expect("leaf");
    // The fixed incoming denominator requires x=1; genuine wrong work must abort.
    let wrong = [vec![K::from_i64(2)]];
    let before = ordinary.usage();
    let a = leaf
        .prove(&wrong, &mut ordinary)
        .expect_err("false scalar relation");
    let b = leaf
        .prove_measured(&wrong, &mut measured)
        .expect_err("same failure");
    assert_eq!(a, b);
    assert_ne!(ordinary.usage(), before);
    assert_eq!(ordinary.usage(), measured.usage());
}

#[test]
fn matches_reference_qm31_fraction_work() {
    check::<QM31>();
}
#[test]
fn matches_reference_om31_fraction_work() {
    check::<OM31>();
}
#[test]
fn rejects_qm31_measured_fraction_failures() {
    failures::<QM31>();
}
#[test]
fn rejects_om31_measured_fraction_failures() {
    failures::<OM31>();
}

//! RFC-0012 A10 / native-field-pcs §9: observations do not authorize a proof.
use super::*;

#[test]
fn rejects_unrepresentable_frame_lengths() {
    assert_eq!(frame_lengths(0, 0), Ok((0, 0)));
    assert_eq!(frame_lengths(255, 105), Ok((255, 105)));
    if let Ok(large) = usize::try_from(u64::from(u32::MAX) + 1) {
        assert_eq!(frame_lengths(large, 0), Err(Error::LengthOverflow));
    }
}

#[test]
fn matches_reference_transcript_usage() {
    fn check<K: ChallengeField>() {
        let mut t = Transcript::<K>::new(b"usage").expect("public input");
        let initial = t.usage();
        assert_eq!(
            initial,
            HashUsage {
                hash_evaluations: 2,
                state_updates: 1,
                ..HashUsage::default()
            }
        );
        t.absorb(AbsorbLabel::Round, b"row").expect("absorb");
        t.challenge(ChallengeLabel::Sumcheck).expect("challenge");
        assert_eq!(
            t.usage(),
            HashUsage {
                hash_evaluations: 4,
                xof_requests: 1,
                xof_bytes: 256,
                state_updates: 3,
                candidate_words: K::DEGREE as u64,
                ..HashUsage::default()
            }
        );
        assert_eq!(initial.hash_evaluations, 2);
    }
    check::<QM31>();
    check::<OM31>();
}

#[test]
fn rejects_usage_overflow_before_unrecorded_work() {
    fn check<K: ChallengeField>() {
        for field in 0..5 {
            let mut t = Transcript::<K>::new(b"usage").expect("public input");
            match field {
                0 => t.usage.hash_evaluations = u64::MAX,
                1 => t.usage.xof_requests = u64::MAX,
                2 => t.usage.xof_bytes = u64::MAX - 255,
                3 => t.usage.state_updates = u64::MAX,
                _ => t.usage.candidate_words = u64::MAX - 2,
            }
            let before = t.usage();
            let state = t.state;
            if field == 0 || field == 3 {
                assert_eq!(
                    t.absorb(AbsorbLabel::Round, b"row"),
                    Err(Error::UsageOverflow)
                );
                assert_eq!(t.usage(), before);
            }
            assert!(matches!(
                t.challenge(ChallengeLabel::Sumcheck),
                Err(Error::UsageOverflow)
            ));
            assert_eq!(t.state, state);
            if field == 1 || field == 2 {
                assert_eq!(t.usage(), before);
            } else {
                assert_eq!(t.usage().xof_requests, before.xof_requests + 1);
                assert_eq!(t.usage().xof_bytes, before.xof_bytes + 256);
                assert_eq!(
                    t.usage().candidate_words - before.candidate_words,
                    if field == 4 { 2 } else { K::DEGREE as u64 }
                );
                assert_eq!(t.usage().hash_evaluations, before.hash_evaluations);
                assert_eq!(t.usage().state_updates, before.state_updates);
            }
        }
    }
    check::<QM31>();
    check::<OM31>();
}

#[test]
fn rejects_sampling_exhaustion_with_usage() {
    fn check<K: ChallengeField>() {
        let mut usage = HashUsage::default();
        assert_eq!(
            sample::<K>(&[255; 256], &mut usage),
            Err(Error::SamplingExhausted)
        );
        assert_eq!(
            usage,
            HashUsage {
                candidate_words: 64,
                ..HashUsage::default()
            }
        );
        let mut raw = [255; 256];
        raw[256 - 4 * K::DEGREE..].fill(0);
        assert_eq!(
            sample::<K>(&raw, &mut usage).expect("last allowed word").1,
            64
        );
        assert_eq!(usage.candidate_words, 128);
    }
    check::<QM31>();
    check::<OM31>();
}

#[test]
fn rejects_merkle_overflow_with_usage() {
    use merkle::{Descriptor, Error as MerkleError, Kind, Opening, Tree};
    let spec = Descriptor {
        kind: Kind::Columns,
        id: 1,
        count: 3,
        width: 1,
    };
    let mut usage = HashUsage {
        hash_evaluations: u64::MAX - 6,
        ..HashUsage::default()
    };
    let before = usage;
    assert!(matches!(
        Tree::new_with_usage(spec, &[&[0], &[1], &[2]], &mut usage),
        Err(MerkleError::UsageOverflow)
    ));
    assert_eq!(usage, before);
    usage.hash_evaluations = u64::MAX - 7;
    let tree =
        Tree::new_with_usage(spec, &[&[0], &[1], &[2]], &mut usage).expect("last seven hashes fit");
    assert_eq!(usage.hash_evaluations, u64::MAX);
    let opening = Opening {
        payload: &[0],
        siblings: &[[0; 32]; 2],
    };
    usage.hash_evaluations = u64::MAX - 2;
    let before = usage;
    assert_eq!(
        merkle::verify_with_usage(spec, &[0; 32], 0, opening, &mut usage),
        Err(MerkleError::UsageOverflow)
    );
    assert_eq!(usage, before);
    usage.hash_evaluations = u64::MAX - 3;
    assert_eq!(
        merkle::verify_with_usage(
            spec,
            &tree.root(),
            0,
            Opening {
                siblings: &tree.path(0).expect("path"),
                ..opening
            },
            &mut usage
        ),
        Ok(())
    );
    assert_eq!(usage.hash_evaluations, u64::MAX);
}

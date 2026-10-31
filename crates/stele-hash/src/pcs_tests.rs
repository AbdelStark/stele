//! RFC-0012 A10: capped candidate decoding and complete ratchet/work preservation.
use super::*;
use crate::{OM31, QM31};

#[test]
fn rejects_column_thresholds_exhaustion_and_invalid_domains() {
    for log in 1..=30 {
        let n = 1 << log;
        let threshold = M31::MODULUS - (n as u32 - 1);
        assert_eq!(
            ColumnDecoder::new(n).expect("domain").push(threshold - 1),
            Ok(Some(n - 1))
        );
        let mut decoder = ColumnDecoder::new(n).expect("domain");
        for _ in 0..63 {
            assert_eq!(decoder.push(threshold), Ok(None));
        }
        assert_eq!(decoder.push(threshold), Err(Error::ColumnSamplingExhausted));
        assert_eq!(decoder.push(0), Err(Error::ColumnSamplingExhausted));
        let mut decoder = ColumnDecoder::new(n).expect("domain");
        for _ in 0..63 {
            assert_eq!(decoder.push(threshold), Ok(None));
        }
        assert_eq!(decoder.push(0), Ok(Some(0)));
    }
    let mut t = Transcript::<QM31>::new(b"columns").expect("public");
    let before = t.usage();
    let state = t.state;
    for n in [0, 1, 3, 1 << 31, u64::MAX] {
        assert_eq!(t.certificate_column(n), Err(Error::InvalidColumnDomain));
        assert_eq!(t.usage(), before);
        assert_eq!(t.state, state);
    }
    // Outer reservation survives an inner failure before any XOF/state work.
    t.usage.xof_requests = u64::MAX;
    assert_eq!(t.certificate_column(2), Err(Error::UsageOverflow));
    assert_eq!(t.usage().column_attempts, 1);
    assert_eq!(t.state, state);
    t.usage.xof_requests = 0;
    t.usage.column_attempts = u64::MAX;
    assert_eq!(t.certificate_column(2), Err(Error::UsageOverflow));
    assert_eq!(t.usage().xof_requests, 0);
    assert_eq!(t.state, state);
}
#[test]
fn matches_reference_full_field_column_ratchets() {
    fn check<K: ChallengeField>() {
        let mut actual = Transcript::<K>::new(b"columns").expect("public");
        let mut expected = Transcript::<K>::new(b"columns").expect("public");
        for _ in 0..16 {
            let index = loop {
                let value = expected
                    .challenge(ChallengeLabel::CertificateColumn)
                    .expect("draw")
                    .to_le_bytes();
                let first = u32::from_le_bytes(value.as_ref()[..4].try_into().expect("limb"));
                if first < 1 << 30 {
                    break u64::from(first);
                }
            };
            assert_eq!(actual.certificate_column(1 << 30), Ok(index));
            assert_eq!(actual.state, expected.state);
        }
        assert!(actual.usage().column_attempts > 16);
        let mut expected_usage = expected.usage();
        expected_usage.column_attempts = expected_usage.xof_requests;
        assert_eq!(actual.usage(), expected_usage);
    }
    check::<QM31>();
    check::<OM31>();
}

#[test]
fn rejects_certificate_id_hash_overflow() {
    assert_eq!(
        certificate_id(
            b"source",
            b"proof",
            &mut HashUsage {
                hash_evaluations: u64::MAX,
                ..HashUsage::default()
            }
        ),
        Err(Error::UsageOverflow)
    );
}

//! RFC-0021 §§3,6: independent exact-entry vectors and strict rounding checks.
use super::*;
use alloc::vec::Vec;

#[test]
fn matches_reference_thirty_thousand_varied_activation_entries() {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../research/cqis-tables/native-activation-entries.json"
    ))
    .expect("two exact Python methods");
    let hex = vectors["records"].as_str().expect("records");
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
        .collect();
    assert_eq!(bytes.len(), 30090 * 13);
    let mut counts = [0; 3];
    for row in bytes.chunks_exact(13) {
        let kind = usize::from(row[0]);
        let name = ["sigmoid_q", "silu_q", "softcap_q"][kind];
        let p = if kind == 2 { &row[1..6] } else { &row[1..3] };
        let d = Descriptor::new(name, 1, p).expect("descriptor");
        let t = i32::from(i16::from_le_bytes(row[6..8].try_into().expect("input")));
        let expected = i32::from_le_bytes(row[9..13].try_into().expect("value"));
        assert_eq!(
            certify(&d, t),
            if row[8] == 1 {
                Err(Error::Overflow)
            } else {
                Ok(expected)
            },
            "{name} {p:?} {t}"
        );
        counts[kind] += 1;
    }
    assert_eq!(counts, [10030; 3]);
}

#[test]
fn matches_reference_ten_thousand_numpy_integer_endpoint_roundings() {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../research/cqis-tables/native-activation-entries.json"
    ))
    .expect("NumPy integer oracle");
    let hex = vectors["numpy_rounding"].as_str().expect("rounding");
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
        .collect();
    assert_eq!(bytes.len(), 10000 * 13);
    for row in bytes.chunks_exact(13) {
        let n = i32::from_le_bytes(row[..4].try_into().expect("n"));
        let d = u32::from_le_bytes(row[4..8].try_into().expect("d"));
        let expected = i32::from_le_bytes(row[9..13].try_into().expect("value"));
        let endpoint = Endpoint {
            negative: n < 0,
            numerator: Natural::from_u64(u64::from(n.unsigned_abs())).expect("n"),
            denominator: Natural::from_u64(u64::from(d)).expect("d"),
        };
        assert_eq!(endpoint.rounded(row[8] as i8), Ok(expected));
    }
}

#[test]
fn matches_reference_signed_half_away_and_one_sided_limits() {
    for n in -8i32..=8 {
        let numerator = 2 * n + 1;
        let endpoint = Endpoint {
            negative: numerator < 0,
            numerator: Natural::from_u64(u64::from(numerator.unsigned_abs())).expect("n"),
            denominator: Natural::from_u64(2).expect("d"),
        };
        assert_eq!(endpoint.rounded(-1), Ok(n));
        assert_eq!(endpoint.rounded(1), Ok(n + 1));
        assert_eq!(endpoint.rounded(0), Ok(if n < 0 { n } else { n + 1 }));
        assert_eq!(endpoint.rounded(2), Err(Error::Interval));
    }
}

#[test]
fn accepts_every_precision_and_rejects_invalid_entry_arguments() {
    for (name, p, expected) in [
        ("sigmoid_q", &[1, 12][..], 2550),
        ("silu_q", &[1, 12][..], 1275),
        ("softcap_q", &[1, 12, 1, 0, 0][..], 1893),
    ] {
        let d = Descriptor::new(name, 1, p).expect("descriptor");
        for bits in [32, 64, 128, 256] {
            let (low, high) = interval(&d, 1, bits).expect("interval");
            assert_eq!(low.rounded(1), Ok(expected));
            assert_eq!(high.rounded(-1), Ok(expected));
        }
        for t in [-32769, 32768, i32::MIN, i32::MAX] {
            assert_eq!(certify(&d, t), Err(Error::Parameters));
        }
    }
    let one = Natural::from_u64(1).expect("one");
    assert_eq!(strict_exp(&one, &one, 33), Err(Error::Precision));
    assert_eq!(strict_exp(&one, &Natural::zero(), 32), Err(Error::Interval));
    assert_eq!(
        exp::enclosure_ratio(&one, &Natural::zero(), 32),
        Err(Error::Interval)
    );
    // Equal ratios with wide non-power-of-two denominators preserve exact results.
    let scale = one.shl(400).expect("wide").add(&one).expect("odd");
    for bits in [32, 64, 128, 256] {
        assert_eq!(
            exp::enclosure_ratio(&scale, &scale.mul_u64(2).expect("twice"), bits),
            exp::enclosure_ratio(&one, &Natural::from_u64(2).expect("two"), bits)
        );
    }
}

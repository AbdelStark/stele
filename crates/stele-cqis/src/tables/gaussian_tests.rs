//! RFC-0021 §§3,6: independent normalizer and tanh-GeLU entry parity.
use super::*;
use alloc::vec::Vec;

fn fixture() -> serde_json::Value {
    serde_json::from_str(include_str!(
        "../../../../research/cqis-tables/native-tanh-gelu.json"
    ))
    .expect("independent exact oracle")
}

fn hex_integer(s: &str) -> Natural {
    s.strip_prefix("0x")
        .expect("prefix")
        .chars()
        .fold(Natural::zero(), |n, c| {
            n.mul_u64(16)
                .expect("shift")
                .add(&Natural::from_u64(u64::from(c.to_digit(16).expect("digit"))).expect("digit"))
                .expect("sum")
        })
}

#[test]
fn matches_reference_every_normalizer_precision_and_checks_domain() {
    for row in fixture()["normalizers"].as_array().expect("normalizers") {
        let bits = row["bits"].as_u64().expect("precision") as usize;
        let c = normalizer(bits).expect("certified normalizer");
        assert_eq!(c.precision, bits);
        assert_eq!(c.low, hex_integer(row["low"].as_str().expect("low")));
        assert_eq!(c.high, hex_integer(row["high"].as_str().expect("high")));
        let d = Descriptor::new("gelu_tanh_q", 1, &[1, 14]).expect("descriptor");
        for t in [-1, 1] {
            let (low, high) = tanh_interval(&d, t, bits - 8, &c).expect("interval");
            let expected = Gaussian::new().certify(&d, t).expect("rounding");
            assert_eq!(low.rounded(1), Ok(expected));
            assert_eq!(high.rounded(-1), Ok(expected));
        }
        let d = Descriptor::new("gelu_q", 1, &[8, 8]).expect("exact descriptor");
        for t in [-2049, -2048, -2047, -1, 1, 2047, 2048, 2049] {
            let (low, high) =
                exact::interval(&d, t, bits - 8, Some(&c)).expect("integral/tail transition");
            let expected = Gaussian::new().certify(&d, t).expect("exact rounding");
            assert_eq!(low.rounded(1), Ok(expected));
            assert_eq!(high.rounded(-1), Ok(expected));
        }
    }
    for bits in [0, 31, 273, usize::MAX] {
        assert!(matches!(normalizer(bits), Err(Error::Precision)));
    }
    for (k, bits) in [(0, 40), (3, 40), (5, 39), (239, 281), (u64::MAX, 40)] {
        assert!(matches!(atan(k, bits), Err(Error::Parameters)));
    }
    let mut generator = Gaussian::new();
    for (name, p, t) in [
        ("silu_q", &[8, 8][..], 0),
        ("range_8", &[][..], 0),
        ("gelu_tanh_q", &[0, 0][..], -32769),
        ("gelu_tanh_q", &[0, 0][..], 32768),
    ] {
        assert_eq!(
            generator.certify(&Descriptor::new(name, 1, p).expect("descriptor"), t),
            Err(Error::Parameters)
        );
    }
}

#[test]
fn matches_reference_ten_thousand_varied_tanh_gelu_entries_and_boundaries() {
    let data = fixture();
    let hex = data["records"].as_str().expect("records");
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
        .collect();
    assert_eq!(bytes.len(), 10030 * 9);
    let mut generator = Gaussian::new();
    for row in bytes.chunks_exact(9) {
        let d = Descriptor::new("gelu_tanh_q", 1, &row[..2]).expect("descriptor");
        let t = i32::from(i16::from_le_bytes(row[2..4].try_into().expect("input")));
        let value = i32::from_le_bytes(row[5..9].try_into().expect("output"));
        assert_eq!(
            generator.certify(&d, t),
            if row[4] == 1 {
                Err(Error::Overflow)
            } else {
                Ok(value)
            },
            "{row:?}"
        );
    }
}

#[test]
fn matches_reference_ten_thousand_varied_exact_gelu_entries_and_boundaries() {
    let data: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../research/cqis-tables/native-exact-gelu.json"
    ))
    .expect("independent exact oracle");
    let hex = data["records"].as_str().expect("records");
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
        .collect();
    assert_eq!(bytes.len(), 10030 * 9);
    let mut generator = Gaussian::new();
    for row in bytes.chunks_exact(9) {
        let d = Descriptor::new("gelu_q", 1, &row[..2]).expect("descriptor");
        let t = i32::from(i16::from_le_bytes(row[2..4].try_into().expect("input")));
        let value = i32::from_le_bytes(row[5..9].try_into().expect("output"));
        assert_eq!(
            generator.certify(&d, t),
            if row[4] == 1 {
                Err(Error::Overflow)
            } else {
                Ok(value)
            },
            "{row:?}"
        );
    }
}

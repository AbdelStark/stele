//! RFC-0025 conversion §§1–2: independent exact decode and rounding fixtures.
use super::*;
use alloc::vec::Vec;

#[test]
fn matches_reference_finite_ieee_and_vector_rounding() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/source-conversion.json"
    ))
    .expect("fixtures");
    for case in fixture["scalars"].as_array().expect("scalars") {
        let dtype = case["dtype"].as_u64().expect("dtype") as u8;
        let hex = case["raw"].as_str().expect("raw");
        let raw: Vec<_> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
            .collect();
        let result = Scalar::decode(dtype, &raw);
        if case["error"].is_string() {
            assert_eq!(result.err(), Some(Error::SourceNonfinite));
            continue;
        }
        let s = result.expect("finite");
        let n = if s.negative {
            -(s.magnitude as i64)
        } else {
            s.magnitude as i64
        };
        assert_eq!(n, case["n"].as_i64().expect("significand"));
        assert_eq!(i64::from(s.power), case["p"].as_i64().expect("exponent"));
        let fraction = case["fraction"].as_u64().expect("fraction") as u8;
        let expected = case["rounded"]
            .as_i64()
            .map(|v| v as i16)
            .ok_or(Error::ConversionOverflow);
        assert_eq!(s.vector(fraction), expected, "dtype={dtype} raw={hex}");
    }
    for case in fixture["exhaustive"].as_array().expect("exhaustive") {
        let dtype = case["dtype"].as_u64().expect("dtype") as u8;
        let mut digest = blake3::Hasher::new();
        let mut accepted = 0;
        for word in 0..=u16::MAX {
            match Scalar::decode(dtype, &word.to_le_bytes()) {
                Ok(s) => {
                    let n = if s.negative {
                        -(s.magnitude as i64)
                    } else {
                        s.magnitude as i64
                    };
                    digest.update(&[1]);
                    digest.update(&n.to_le_bytes());
                    digest.update(&s.power.to_le_bytes());
                    accepted += 1;
                }
                Err(Error::SourceNonfinite) => {
                    digest.update(&[0]);
                }
                _ => unreachable!(),
            }
        }
        assert_eq!(
            digest.finalize().to_hex().as_str(),
            case["digest"].as_str().expect("digest")
        );
        assert_eq!(accepted, case["accepted"].as_u64().expect("accepted"));
    }
}

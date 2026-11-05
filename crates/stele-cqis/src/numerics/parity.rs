//! RFC-0025 §2/6: exact rational parity for every shared scalar rounding caller.
use super::{scaled_sum, Error};

struct Rng(u64);
impl Rng {
    fn word(&mut self) -> u32 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (self.0 >> 32) as u32
    }
    fn signed(&mut self) -> i128 {
        i128::from(self.word() as u16 as i16)
    }
}
#[test]
fn matches_reference_ten_thousand_cases_per_composed_scalar_operation() {
    let expected: serde_json::Value =
        serde_json::from_str(include_str!("../../tests/fixtures/runtime-arithmetic.json"))
            .expect("exact oracle");
    let mut rng = Rng(50427);
    for kind in 0..5 {
        let mut digest = blake3::Hasher::new();
        let mut accepted = 0;
        for i in 0..10000 {
            let (x, y, m, s, f, fo) = (
                rng.signed(),
                rng.signed(),
                1 + rng.word() % 65535,
                rng.word() % 8454662,
                rng.word() % 45,
                rng.word() % 31,
            );
            let (mut e, fb, divisor) = (
                (rng.word() % 2124) as i32 - 1099,
                rng.word() % 31,
                1 + rng.word() % u32::MAX,
            );
            if i % 2 == 1 {
                e = -e.rem_euclid(32);
            }
            let (left, le, mut right, mut re, den, bits) = match kind {
                0 => (
                    x * y * i128::from(m) * i128::from(s),
                    e - f as i32 + fo as i32,
                    rng.signed(),
                    fo as i32 - fb as i32,
                    1u64,
                    16u32,
                ),
                1 => (
                    (x.rem_euclid(255) - 127) * i128::from(m),
                    e + fo as i32,
                    ((y.rem_euclid(255) - 127) * i128::from(divisor)).rem_euclid(65535),
                    (rng.word() % 2124) as i32 - 1099 + fo as i32,
                    1,
                    16,
                ),
                2 => (
                    x,
                    fo as i32 - (f % 31) as i32,
                    y,
                    fo as i32 - fb as i32,
                    1,
                    16,
                ),
                3 => (
                    x * y * i128::from(m) * i128::from(s % 65536),
                    (rng.word() % 183) as i32 - 122,
                    0,
                    0,
                    1,
                    32,
                ),
                _ => (
                    x * y * i128::from(s),
                    (rng.word() % 123) as i32 - 30,
                    0,
                    0,
                    u64::from(divisor),
                    16,
                ),
            };
            if kind == 1 && i % 19 == 0 {
                right = -left;
                re = le;
            }
            digest.update(&left.to_le_bytes());
            digest.update(&le.to_le_bytes());
            digest.update(&right.to_le_bytes());
            digest.update(&re.to_le_bytes());
            digest.update(&den.to_le_bytes());
            digest.update(&bits.to_le_bytes());
            let value = scaled_sum(left, le, right, re, den);
            match value {
                Ok(v) if -(1i64 << (bits - 1)) <= v && v < 1i64 << (bits - 1) => {
                    accepted += 1;
                    digest.update(&[1]);
                    digest.update(&v.to_le_bytes());
                }
                Ok(_) | Err(Error::Range) => {
                    digest.update(&[0]);
                }
                other => {
                    assert!(other.is_ok(), "unexpected arithmetic failure: {other:?}");
                }
            }
        }
        let row = &expected["groups"][kind];
        assert_eq!(accepted, row["accepted"].as_u64().expect("accepted"));
        assert_eq!(
            digest.finalize().to_hex().as_str(),
            row["digest"].as_str().expect("digest")
        );
    }
}

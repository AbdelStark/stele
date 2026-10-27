//! Scalar field checks against integer remainder arithmetic (RFC-0003 §§1,5,6).
use super::{Scalar, P};
use stele_field::{Field, Inverse, Serialize};
const CASES: usize = 1_000_000;

#[test]
#[allow(clippy::assertions_on_constants)] // The field's specified constant is under test.
fn accepts_prime_modulus() {
    assert!(P > 2 && P % 2 == 1);
    let mut divisor = 3;
    while divisor * divisor <= P {
        assert_ne!(P % divisor, 0);
        divisor += 2;
    }
}

// Fixed test data only; this generator is never used for protocol challenges.
fn next(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e3779b97f4a7c15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
    z ^ (z >> 31)
}

fn reference_pow(mut base: u64, mut exponent: u64) -> u64 {
    let mut result = 1;
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = result * base % P;
        }
        base = base * base % P;
        exponent >>= 1;
    }
    result
}

#[allow(clippy::eq_op)] // Commutativity is a property under test, not an operator assumption.
fn check_ops(a: Scalar, b: Scalar, c: Scalar) {
    let av = u64::from(a.as_u32());
    let bv = u64::from(b.as_u32());
    assert_eq!(u64::from((a + b).as_u32()), (av + bv) % P);
    assert_eq!(u64::from((a - b).as_u32()), (av + P - bv) % P);
    assert_eq!(u64::from((a * b).as_u32()), av * bv % P);
    assert_eq!(u64::from((-a).as_u32()), (P - av) % P);
    assert_eq!(a + b, b + a);
    assert_eq!(a * b, b * a);
    assert_eq!((a + b) + c, a + (b + c));
    assert_eq!((a * b) * c, a * (b * c));
    assert_eq!(a * (b + c), a * b + a * c);
    assert_eq!(a + Scalar::ZERO, a);
    assert_eq!(a * Scalar::ONE, a);
    assert_eq!(a * Scalar::ZERO, Scalar::ZERO);
    assert_eq!(a + (-a), Scalar::ZERO);
    assert_eq!((a - b) + b, a);
}

#[test]
fn matches_reference_million_ring_and_encoding_cases() {
    let mut seed = 0x5354_454c_4500_0001;
    for _ in 0..CASES {
        let raw = next(&mut seed);
        let a = Scalar::from_u64(raw);
        let b = Scalar::from_u64(next(&mut seed));
        let c = Scalar::from_u64(next(&mut seed));
        assert_eq!(u64::from(a.as_u32()), raw % P);
        check_ops(a, b, c);
        assert_eq!(Scalar::from_le_bytes(a.to_le_bytes()), Some(a));
        assert_eq!(a.to_le_bytes(), (raw % P).to_le_bytes()[..4]);
        assert_eq!(Scalar::from_canonical(a.as_u32()), Some(a));
        let lazy = (next(&mut seed) % (2 * P)) as u32;
        assert_eq!(
            Scalar::from_lazy(lazy),
            Some(Scalar::from_u64(u64::from(lazy)))
        );
        let signed = (next(&mut seed) % P) as i64 - (P / 2) as i64;
        assert_eq!(Scalar::from_i64(signed).to_i64_signed(), signed);
    }
}

#[test]
fn matches_reference_million_inverse_and_frobenius_cases() {
    let mut seed = 0x5354_454c_4500_0002;
    for _ in 0..CASES {
        let raw = next(&mut seed) % (P - 1) + 1;
        let a = Scalar::from_u64(raw);
        let inverse = a.inverse().expect("nonzero field element");
        assert_eq!(a * inverse, Scalar::ONE);
        assert_eq!(u64::from(inverse.as_u32()), reference_pow(raw, P - 2));
        assert_eq!(a.pow(P), a);
    }
}

#[test]
fn matches_reference_boundary_arithmetic() {
    assert_eq!(u64::from(Scalar::MODULUS), P);
    let values = [0, 1, 2, P / 2, P / 2 + 1, P - 2, P - 1];
    for a in values {
        for b in values {
            for c in values {
                check_ops(
                    Scalar::from_u64(a),
                    Scalar::from_u64(b),
                    Scalar::from_u64(c),
                );
            }
        }
    }
    for raw in [0, P - 1, P, P + 1, 2 * P - 1, 2 * P, P * P, u64::MAX] {
        assert_eq!(u64::from(Scalar::from_u64(raw).as_u32()), raw % P);
    }
    for raw in [0, P - 1, P, P + 1, 2 * P - 1] {
        assert_eq!(Scalar::from_lazy(raw as u32), Some(Scalar::from_u64(raw)));
    }
    assert_eq!(Scalar::ZERO.pow(0), Scalar::ONE);
    assert_eq!(Scalar::ZERO.pow(P), Scalar::ZERO);
    assert_eq!(Scalar::ONE.inverse(), Some(Scalar::ONE));
    let a = Scalar::from_u64(13);
    assert_eq!(
        u64::from(a.pow(u64::MAX).as_u32()),
        reference_pow(13, u64::MAX)
    );
}

#[test]
fn matches_reference_signed_boundaries() {
    let half = (P / 2) as i64;
    for value in [-half, -half + 1, -1, 0, 1, half - 1, half] {
        assert_eq!(Scalar::from_i64(value).to_i64_signed(), value);
    }
    for value in [
        i64::MIN,
        -(P as i64),
        -half - 1,
        half + 1,
        P as i64,
        i64::MAX,
    ] {
        let a = Scalar::from_i64(value);
        assert_eq!(i64::from(a.as_u32()), value.rem_euclid(P as i64));
        assert!((-half..=half).contains(&a.to_i64_signed()));
        assert_eq!(Scalar::from_i64(a.to_i64_signed()), a);
    }
    assert_eq!(Scalar::from_u64(P / 2).to_i64_signed(), half);
    assert_eq!(Scalar::from_u64(P / 2 + 1).to_i64_signed(), -half);
}

#[test]
fn rejects_noncanonical_encoding_and_out_of_range_lazy_values() {
    for raw in [P as u32, P as u32 + 1, (2 * P) as u32, u32::MAX] {
        assert_eq!(Scalar::from_canonical(raw), None);
        assert_eq!(Scalar::from_le_bytes(raw.to_le_bytes()), None);
    }
    for raw in [(2 * P) as u32, u32::MAX] {
        assert_eq!(Scalar::from_lazy(raw), None);
    }
    assert_eq!(Scalar::ZERO.inverse(), None);
}

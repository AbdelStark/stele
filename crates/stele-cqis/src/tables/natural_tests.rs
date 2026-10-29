//! RFC-0021 §3: independent arithmetic oracles and bounded-capacity failures.
use super::*;
use alloc::format;

fn parse(hex: &str) -> Natural {
    let words = hex
        .as_bytes()
        .rchunks(8)
        .map(|part| {
            u32::from_str_radix(core::str::from_utf8(part).expect("ASCII"), 16).expect("limb")
        })
        .collect();
    Natural::finish(words).expect("fixture capacity")
}

#[test]
fn matches_reference_python_large_arithmetic() {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../research/cqis-tables/native-arithmetic-vectors.json"
    ))
    .expect("Python integers");
    assert_eq!(vectors["cases"].as_array().expect("cases").len(), 72);
    for row in vectors["cases"].as_array().expect("cases") {
        let value = |name: &str| parse(row[name].as_str().expect("integer"));
        let a = value("a");
        let b = value("b");
        assert_eq!(a.add(&b), Ok(value("add")));
        if row["sub"].is_null() {
            assert_eq!(a.sub(&b), Err(Error::Interval));
        } else {
            assert_eq!(a.sub(&b), Ok(value("sub")));
        }
        assert_eq!(a.mul(&b), Ok(value("mul")));
        assert_eq!(a.div_rem(&b), Ok((value("quotient"), value("remainder"))));
        let shift = row["shift"].as_u64().expect("shift") as usize;
        assert_eq!(a.shl(shift), Ok(value("left")));
        assert_eq!(a.shr(shift), Ok(value("right")));
    }
}

#[test]
fn matches_reference_ten_thousand_machine_integer_cases() {
    let mut state = 250203u64;
    for _ in 0..10000 {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let a = state;
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let b = state | 1;
        let x = Natural::from_u64(a).expect("small");
        let y = Natural::from_u64(b).expect("small");
        let expected = |v: u128| parse(&format!("{v:x}"));
        assert_eq!(x.add(&y), Ok(expected(u128::from(a) + u128::from(b))));
        assert_eq!(x.mul(&y), Ok(expected(u128::from(a) * u128::from(b))));
        assert_eq!(x.mul_u64(b), x.mul(&y));
        assert_eq!(
            x.div_rem(&y),
            Ok((expected(u128::from(a / b)), expected(u128::from(a % b))))
        );
        let shift = (state % 64) as usize;
        assert_eq!(x.shl(shift), Ok(expected(u128::from(a) << shift)));
        assert_eq!(x.shr(shift), Ok(expected(u128::from(a) >> shift)));
        if a >= b {
            assert_eq!(x.sub(&y), Ok(expected(u128::from(a - b))));
        } else {
            assert_eq!(x.sub(&y), Err(Error::Interval));
        }
    }
}

#[test]
fn rejects_capacity_overflow_and_zero_division_without_changing_inputs() {
    let zero = Natural::zero();
    let one = Natural::from_u64(1).expect("one");
    let top = one.shl(MAX_BITS - 1).expect("largest supported bit");
    assert_eq!(top.bits(), MAX_BITS);
    assert_eq!(top.shl(1), Err(Error::Capacity));
    assert_eq!(top.add(&top), Err(Error::Capacity));
    assert_eq!(top.mul_u64(2), Err(Error::Capacity));
    assert_eq!(one.shl(usize::MAX), Err(Error::Capacity));
    assert_eq!(top.div_rem(&zero), Err(Error::Interval));
    assert_eq!(top.mul(&one), top.try_clone());
    assert_eq!(
        top.div_rem(&top),
        Ok((Natural::from_u64(1).expect("one"), Natural::zero()))
    );
    assert_eq!(top.shr(MAX_BITS - 1), Ok(one));
    assert_eq!(top.shr(usize::MAX), Ok(zero));
    assert_eq!(
        Natural::from_u64(u64::MAX).expect("u64").to_u32(),
        Err(Error::Interval)
    );
}

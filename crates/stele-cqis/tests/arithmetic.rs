//! RFC-0004 §2, §5.2 and A1: scalar integer semantics, not proof validation.
use stele_cqis::{residual_add, Error, Format, Requant};

#[test]
fn accepts_signed_ties_identity_and_zero() {
    let round = Requant::new(1, 1).expect("valid scale");
    for (acc, expected) in [(-5, -3), (-3, -2), (-1, -1), (0, 0), (1, 1), (3, 2), (5, 3)] {
        assert_eq!(round.apply(acc, Format::Int8), Ok(expected));
        assert_eq!(round.apply(acc, Format::Int16), Ok(expected));
    }
    let identity = Requant::new(1, 0).expect("valid scale");
    for value in [i16::MIN, -128, -1, 0, 1, 127, i16::MAX] {
        assert_eq!(identity.apply(i32::from(value), Format::Int16), Ok(value));
    }
}

#[test]
fn rejects_invalid_configuration_and_target_overflow() {
    for mantissa in [0, 65536, u32::MAX] {
        assert_eq!(Requant::new(mantissa, 0), Err(Error::Scale));
    }
    for shift in [63, 64, u32::MAX] {
        assert_eq!(Requant::new(1, shift), Err(Error::Shift));
    }
    let identity = Requant::new(1, 0).expect("valid scale");
    for acc in [-129, 128, i32::MIN, i32::MAX] {
        assert_eq!(identity.apply(acc, Format::Int8), Err(Error::Range));
    }
    for acc in [-32769, 32768, i32::MIN, i32::MAX] {
        assert_eq!(identity.apply(acc, Format::Int16), Err(Error::Range));
    }
    // A tie can overflow the target: saturation must not turn it into success.
    assert_eq!(
        Requant::new(1, 1)
            .expect("valid scale")
            .apply(255, Format::Int8),
        Err(Error::Range)
    );
    assert_eq!(
        Requant::new(1, 1)
            .expect("valid scale")
            .apply(-257, Format::Int8),
        Err(Error::Range)
    );
}

#[test]
fn accepts_full_accumulator_mantissa_and_supported_shift_bounds() {
    for acc in [i32::MIN, -1, 0, 1, i32::MAX] {
        assert_eq!(
            Requant::new(65535, 62)
                .expect("valid scale")
                .apply(acc, Format::Int16),
            Ok(0)
        );
    }
    assert_eq!(
        Requant::new(65535, 32)
            .expect("valid scale")
            .apply(i32::MIN, Format::Int16),
        Ok(-32768)
    );
    assert_eq!(
        Requant::new(65535, 32)
            .expect("valid scale")
            .apply(i32::MAX, Format::Int16),
        Ok(32767)
    );
    assert_eq!(
        Requant::new(65535, 0)
            .expect("valid scale")
            .apply(i32::MIN, Format::Int16),
        Err(Error::Range)
    );
}

#[test]
fn accepts_exact_residual_addition_and_rejects_overflow() {
    for (a, b, expected) in [
        (i16::MIN, i16::MAX, -1),
        (32766, 1, 32767),
        (-32767, -1, -32768),
        (0, 0, 0),
    ] {
        assert_eq!(residual_add(a, b), Ok(expected));
    }
    for (a, b) in [
        (i16::MAX, 1),
        (i16::MIN, -1),
        (i16::MAX, i16::MAX),
        (i16::MIN, i16::MIN),
    ] {
        assert_eq!(residual_add(a, b), Err(Error::Range));
    }
}

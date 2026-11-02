//! RFC-0023 §6: frozen independent bytes and whole-domain arithmetic boundaries.
use super::*;
use alloc::vec;
use stele_field::{Field, QM31};

#[test]
fn matches_reference_frozen_witness_bytes() {
    let fixtures: &[(i32, u32, i16, &[u8])] = &[
        (
            0,
            0,
            0,
            include_bytes!("../../../tests/negative-controls/fixtures/requant/control-zero-0.bin"),
        ),
        (
            0,
            31,
            0,
            include_bytes!("../../../tests/negative-controls/fixtures/requant/control-zero-31.bin"),
        ),
        (
            i32::MAX,
            31,
            1,
            include_bytes!("../../../tests/negative-controls/fixtures/requant/control-p-31.bin"),
        ),
        (
            1,
            0,
            1,
            include_bytes!("../../../tests/negative-controls/fixtures/requant/control-one-0.bin"),
        ),
        (
            -1,
            1,
            -1,
            include_bytes!(
                "../../../tests/negative-controls/fixtures/requant/control-tie-negative.bin"
            ),
        ),
        (
            1,
            1,
            1,
            include_bytes!(
                "../../../tests/negative-controls/fixtures/requant/control-tie-positive.bin"
            ),
        ),
        (
            -128,
            0,
            -128,
            include_bytes!(
                "../../../tests/negative-controls/fixtures/requant/control-negative-h.bin"
            ),
        ),
    ];
    for &(acc, shift, output, expected) in fixtures {
        let schema = Schema::new(1, shift, Format::Int8).expect("valid fixed fixture");
        let w = schema
            .witness(&[acc], schema.rows() + 4)
            .expect("valid fixed fixture");
        assert_eq!(w.output(), &[output]);
        assert_eq!(
            w.owned_bytes(),
            Ok(4 * w.input.capacity() + 4 * w.advice.capacity() + 2 * w.output.capacity())
        );
        assert_eq!(
            w.advice()
                .iter()
                .map(|v| v.as_u32() as u8)
                .collect::<Vec<_>>(),
            expected
        );
        assert_eq!(
            w.input()
                .iter()
                .map(|v| v.as_u32() as u8)
                .collect::<Vec<_>>(),
            (i64::from(acc) + (1 << 31)).to_le_bytes()[..4]
        );
    }
}

#[test]
fn accepts_witness_shift_width_sign_and_padding_boundaries() {
    // All supported shifts, both targets and mantissas around radix boundaries.
    // Actual closed equations check every byte/carry and shared high column.
    for shift in 0..=62 {
        for mantissa in [1, 255, 256, 65535] {
            for format in [Format::Int8, Format::Int16] {
                let schema = Schema::new(mantissa, shift, format).expect("valid fixed fixture");
                let config = Requant::new(mantissa, shift).expect("valid fixed fixture");
                let constraints = schema.constraints::<QM31>().expect("valid fixed fixture");
                let mut inputs = vec![0, -1, 1];
                for acc in [i32::MIN, i32::MAX, -32768, 32767, -128, 127] {
                    if config.apply(acc, format).is_ok() {
                        inputs.push(acc);
                    }
                }
                inputs.retain(|acc| config.apply(*acc, format).is_ok());
                // Always retain a non-power-of-two shape and explicit zero padding.
                while inputs.len().is_power_of_two() {
                    inputs.push(0);
                }
                let n = inputs.len().next_power_of_two();
                let w = schema
                    .witness(&inputs, (schema.rows() + 4) * n)
                    .expect("valid fixed fixture");
                assert_eq!(w.input().len(), 4 * n);
                assert_eq!(w.advice().len(), schema.rows() * n);
                for (acc, result) in inputs.iter().zip(w.output()) {
                    assert_eq!(config.apply(*acc, format), Ok(*result));
                }
                for i in 0..n {
                    let mut row = vec![QM31::from_i64(i64::from(i < inputs.len()))];
                    row.extend(
                        w.input()
                            .chunks_exact(n)
                            .chain(w.advice().chunks_exact(n))
                            .map(|r| QM31::from_i64(i64::from(r[i].as_u32()))),
                    );
                    for terms in constraints.equations() {
                        let value = terms.iter().fold(QM31::from_i64(0), |sum, term| {
                            sum + term
                                .factors
                                .iter()
                                .fold(term.coefficient, |v, f| v * row[*f as usize])
                        });
                        assert_eq!(
                            value,
                            QM31::from_i64(0),
                            "mantissa={mantissa}, shift={shift}, format={format:?}, position={i}"
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn rejects_witness_overflow_and_resource_caps() {
    for (format, low, high) in [(Format::Int8, -128, 127), (Format::Int16, -32768, 32767)] {
        let s = Schema::new(1, 0, format).expect("valid fixed fixture");
        for acc in [low - 1, high + 1, i32::MIN, i32::MAX] {
            assert_eq!(
                s.witness(&[acc], s.rows() + 4)
                    .expect_err("invalid fixed input"),
                Error::Parameters(stele_cqis::Error::Range)
            );
        }
        assert_eq!(
            s.witness(&[], usize::MAX).expect_err("invalid fixed input"),
            Error::Statement
        );
        assert_eq!(
            s.witness(&[0], s.rows() + 3)
                .expect_err("invalid fixed input"),
            Error::ResourceLimit
        );
        assert_eq!(
            s.witness(&[0, 0, 0], (s.rows() + 4) * 4 - 1)
                .expect_err("invalid fixed input"),
            Error::ResourceLimit
        );
        assert_eq!(
            s.witness(&[low, high], (s.rows() + 4) * 2)
                .expect("valid fixed fixture")
                .output(),
            &[low as i16, high as i16]
        );
    }
}

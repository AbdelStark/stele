//! RFC-0024 §2.1: independent complete static bytes/terms, never proof controls.
use super::*;
use alloc::vec;
use stele_field::{OM31, QM31};

fn words(line: &str) -> Vec<i64> {
    line.split_whitespace()
        .map(|v| v.parse().expect("fixture integer"))
        .collect()
}
fn hex(line: &str) -> Vec<u8> {
    line.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(core::str::from_utf8(pair).expect("hex"), 16).expect("hex byte")
        })
        .collect()
}
fn evaluate<K: ChallengeField>(terms: &[stele_sumcheck::Term<K>], row: &[K]) -> K {
    terms.iter().fold(K::from_i64(0), |sum, term| {
        sum + term
            .factors
            .iter()
            .fold(term.coefficient, |v, f| v * row[*f as usize])
    })
}
fn parity<K: ChallengeField + Eq + core::fmt::Debug>() {
    let lines: Vec<_> = include_str!("../tests/fixtures/embedded-requant.txt")
        .lines()
        .filter(|s| !s.starts_with('#'))
        .collect();
    assert_eq!(lines.len(), 20 * 6);
    for case in lines.chunks_exact(6) {
        let p = words(case[0]);
        let format = if p[3] == 8 {
            Format::Int8
        } else {
            Format::Int16
        };
        let schema =
            EmbeddedSchema::new(p[0] as u8, p[1] as u32, p[2] as u32, format).expect("schema");
        assert_eq!(schema.bound(), (1 << p[0]) * 128 * 128);
        assert_eq!(schema.semantic().allocated_rows(), p[4] as usize);
        assert_eq!(schema.allocated_rows(), p[4] as usize + 11);
        assert_eq!(schema.rows(), p[5] as usize);
        assert_eq!(schema.semantic().bounds().as_bytes(), hex(case[5]));
        let captured: Vec<_> = words(case[1]).into_iter().map(|v| v as i32).collect();
        let witness = schema
            .witness(&captured, schema.rows() * captured.len())
            .expect("witness");
        assert_eq!(
            witness
                .output()
                .iter()
                .map(|v| i64::from(*v))
                .collect::<Vec<_>>(),
            words(case[2])
        );
        assert_eq!(
            witness
                .advice()
                .iter()
                .map(|v| v.as_u32())
                .collect::<Vec<_>>(),
            hex(case[3]).into_iter().map(u32::from).collect::<Vec<_>>()
        );
        assert_eq!(
            witness.owned_bytes(),
            Ok(witness.advice.capacity() * 4 + witness.output.capacity() * 2)
        );
        let plan = schema.constraints::<K>().expect("constraints");
        assert_eq!(plan.input_count(), schema.rows() + 1);
        let encoded = words(case[4]);
        assert_eq!(plan.equations().len(), encoded[0] as usize);
        let mut at = 1;
        for equation in plan.equations() {
            assert_eq!(equation.len(), encoded[at] as usize);
            at += 1;
            for term in equation {
                let mut expected = vec![0; 4 * K::DEGREE];
                expected[..4].copy_from_slice(&(encoded[at] as u32).to_le_bytes());
                assert_eq!(term.coefficient.to_le_bytes().as_ref(), expected);
                let n = encoded[at + 1] as usize;
                at += 2;
                assert_eq!(
                    term.factors,
                    encoded[at..at + n]
                        .iter()
                        .map(|v| *v as u32)
                        .collect::<Vec<_>>()
                );
                at += n;
            }
        }
        assert_eq!(at, encoded.len());
        for i in 0..captured.len() {
            let mut row = vec![K::from_i64(1)];
            row.extend(
                witness
                    .advice()
                    .chunks_exact(captured.len())
                    .map(|r| K::from_i64(i64::from(r[i].as_u32()))),
            );
            assert!(plan
                .equations()
                .iter()
                .all(|e| evaluate(e, &row) == K::from_i64(0)));
        }
    }
}
#[test]
fn matches_reference_qm31_embedded() {
    parity::<QM31>();
}
#[test]
fn matches_reference_om31_embedded() {
    parity::<OM31>();
}

#[test]
fn rejects_embedded_bounds_shapes_and_caps() {
    for b in 0..=15 {
        let s = EmbeddedSchema::new(b, 1, 32, Format::Int16).expect("schema");
        let bound = s.bound() as i32;
        assert!(s.witness(&[-bound, bound], 2 * s.rows()).is_ok());
        for acc in [-bound - 1, bound + 1, i32::MAX, i32::MIN] {
            assert_eq!(
                s.witness(&[acc], s.rows()).expect_err("bound"),
                Error::Witness
            );
        }
        for input in [&[][..], &[0, 0, 0][..]] {
            assert_eq!(
                s.witness(input, usize::MAX).expect_err("shape"),
                Error::Statement
            );
        }
        assert_eq!(
            s.witness(&[0], s.rows() - 1).expect_err("cap"),
            Error::ResourceLimit
        );
    }
    for b in [16, 63, 64, 255] {
        assert!(matches!(
            EmbeddedSchema::new(b, 1, 32, Format::Int16),
            Err(Error::Bounds(bounds::Error::FieldBound))
        ));
    }
    assert!(matches!(
        EmbeddedSchema::new(0, 0, 0, Format::Int8),
        Err(Error::Parameters(_))
    ));
    assert!(matches!(
        EmbeddedSchema::new(0, 1, 63, Format::Int8),
        Err(Error::Parameters(_))
    ));
    let s = EmbeddedSchema::new(0, 1, 0, Format::Int8).expect("schema");
    assert_eq!(
        s.witness(&[128], s.rows()).expect_err("output range"),
        Error::Parameters(stele_cqis::Error::Range)
    );
}

#[test]
fn rejects_embedded_high_cap_and_reserved_equations() {
    let s = EmbeddedSchema::new(0, 1, 32, Format::Int16).expect("schema");
    let plan = s.constraints::<QM31>().expect("constraints");
    let w = s.witness(&[0], s.rows()).expect("witness");
    let mut row = vec![QM31::from_i64(1)];
    row.extend(
        w.advice()
            .iter()
            .map(|v| QM31::from_i64(i64::from(v.as_u32()))),
    );
    let start = plan.equations().len() - s.rows() - 7;
    let high_slack = s.semantic().allocated_rows() + 7;
    row[high_slack] = QM31::from_i64(1);
    assert_eq!(
        evaluate(&plan.equations()[start + 2], &row),
        QM31::from_i64(1)
    );
    row[high_slack] = QM31::from_i64(0);
    row[s.allocated_rows() + 1] = QM31::from_i64(1);
    assert_eq!(
        evaluate(&plan.equations()[start + 7 + s.allocated_rows()], &row),
        QM31::from_i64(1)
    );
}

#[test]
fn rejects_embedded_alias_and_truncated_cap_equations() {
    let s = EmbeddedSchema::new(0, 1, 32, Format::Int16).expect("schema");
    let plan = s.constraints::<QM31>().expect("constraints");
    let start = plan.equations().len() - s.rows() - 7;
    for acc in [s.bound() as i32 + 1, 65536, i32::MAX] {
        let old = s
            .semantic()
            .witness(&[acc], s.semantic().rows() + 4)
            .expect("valid old Requant");
        let mut row = vec![QM31::from_i64(0); plan.input_count()];
        row[0] = QM31::from_i64(1);
        for (i, v) in old
            .input()
            .iter()
            .chain(&old.advice()[..s.semantic().allocated_rows()])
            .enumerate()
        {
            row[i + 1] = QM31::from_i64(i64::from(v.as_u32()));
        }
        assert!(plan.equations()[..start]
            .iter()
            .all(|e| evaluate(e, &row) == QM31::from_i64(0)));
        // Adversarial slack wraps at the full four-byte width; final carry is fixed zero.
        let slack = (s.bound() as u32).wrapping_sub(acc as u32);
        let mut carry = 0;
        for k in 0..4 {
            let byte = (slack >> (8 * k)) & 255;
            row[s.semantic().allocated_rows() + 5 + k] = QM31::from_i64(i64::from(byte));
            carry = (((acc as u32 >> (8 * k)) & 255) + byte + carry) / 256;
            if k < 3 {
                row[s.semantic().allocated_rows() + 9 + k] = QM31::from_i64(i64::from(carry));
            }
        }
        assert_eq!(
            evaluate(&plan.equations()[start + 3], &row),
            QM31::from_i64(256)
        );
        assert!(plan.equations()[start..start + 3]
            .iter()
            .all(|e| evaluate(e, &row) == QM31::from_i64(0)));
    }
    let w = s.witness(&[0], s.rows()).expect("witness");
    let mut row = vec![QM31::from_i64(1)];
    row.extend(
        w.advice()
            .iter()
            .map(|v| QM31::from_i64(i64::from(v.as_u32()))),
    );
    row[s.semantic().allocated_rows() + 9] = QM31::from_i64(2);
    assert_eq!(
        evaluate(&plan.equations()[start + 4], &row),
        QM31::from_i64(2)
    );
}

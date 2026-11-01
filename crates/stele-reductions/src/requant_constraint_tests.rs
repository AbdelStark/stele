//! RFC-0023 §2.2: complete independent terms and direct equation regressions.
use super::*;
use alloc::vec;
use stele_cqis::Format;
use stele_field::{OM31, QM31};

fn words(line: &str) -> Vec<i64> {
    line.split_whitespace()
        .map(|v| v.parse().expect("fixture integer"))
        .collect()
}

fn evaluate<K: ChallengeField>(terms: &[Term<K>], row: &[K]) -> K {
    terms.iter().fold(K::from_i64(0), |sum, term| {
        sum + term
            .factors
            .iter()
            .fold(term.coefficient, |v, f| v * row[*f as usize])
    })
}

fn parity<K: ChallengeField + PartialEq + core::fmt::Debug>() {
    let lines: Vec<_> = include_str!("../tests/fixtures/requant-constraints.txt")
        .lines()
        .filter(|s| !s.starts_with('#'))
        .collect();
    assert_eq!(lines.len(), 18 * 4);
    let mut zero_variable = false;
    let mut control_counts = [0; 2];
    for fixture in lines.chunks_exact(4) {
        let p = words(fixture[0]);
        let format = if p[2] == 8 {
            Format::Int8
        } else {
            Format::Int16
        };
        let schema = Schema::new(p[0] as u32, p[1] as u32, format).expect("schema");
        let plan = schema.constraints::<K>().expect("constraints");
        assert_eq!(plan.input_count(), p[3] as usize);
        let encoded = words(fixture[1]);
        assert_eq!(plan.equations().len(), encoded[0] as usize);
        let mut at = 1;
        for equation in plan.equations() {
            assert_eq!(
                equation
                    .iter()
                    .map(|t| t.factors.len())
                    .max()
                    .expect("nonempty"),
                encoded[at] as usize
            );
            assert_eq!(equation.len(), encoded[at + 1] as usize);
            at += 2;
            for term in equation {
                let mut coefficient = vec![0; 4 * K::DEGREE];
                coefficient[..4].copy_from_slice(&(encoded[at] as u32).to_le_bytes());
                assert_eq!(
                    term.coefficient.to_le_bytes().as_ref(),
                    coefficient,
                    "{}",
                    fixture[0]
                );
                let count = encoded[at + 1] as usize;
                assert_eq!(term.factors.len(), count);
                at += 2;
                for factor in &term.factors {
                    assert_eq!(*factor, encoded[at] as u32);
                    assert!((*factor as usize) < plan.input_count());
                    at += 1;
                }
                zero_variable |= term.coefficient == K::from_i64(0) && count == 2;
            }
        }
        assert_eq!(at, encoded.len());
        assert_eq!(plan.equations()[0][0].factors, [0, 5, 5]);
        let rows = words(fixture[2]);
        assert_eq!(rows.len(), 1 + rows[0] as usize * plan.input_count());
        let rows: Vec<Vec<K>> = rows[1..]
            .chunks_exact(plan.input_count())
            .map(|row| row.iter().map(|v| K::from_i64(*v)).collect())
            .collect();
        for row in &rows {
            for (i, equation) in plan.equations().iter().enumerate() {
                assert_eq!(
                    evaluate(equation, row),
                    K::from_i64(0),
                    "{} equation {i}",
                    fixture[0]
                );
            }
        }
        let padding = vec![K::from_i64(0); plan.input_count()];
        assert!(plan
            .equations()
            .iter()
            .all(|e| evaluate(e, &padding) == K::from_i64(0)));
        let controls = words(fixture[3]);
        assert_eq!(controls.len(), 1 + 5 * controls[0] as usize);
        for c in controls[1..].chunks_exact(5) {
            let mut row = if c[0] == -1 {
                padding.clone()
            } else {
                rows[c[0] as usize].clone()
            };
            assert_ne!(row[c[1] as usize], K::from_i64(c[2]));
            row[c[1] as usize] = K::from_i64(c[2]);
            assert_eq!(
                evaluate(&plan.equations()[c[3] as usize], &row),
                K::from_i64(c[4])
            );
            control_counts[usize::from(c[4] != 0)] += 1;
        }
    }
    assert!(zero_variable);
    // Two low division columns miss the high-byte tamper; its full-width cap rejects.
    assert_eq!(control_counts, [2, 20]);
}

#[test]
fn matches_reference_qm31_constraints() {
    parity::<QM31>();
}
#[test]
fn matches_reference_om31_constraints() {
    parity::<OM31>();
}

#[test]
fn rejects_constraint_caps_and_resources() {
    for side in 0..2 {
        let mut schema = Schema::new(1, 0, Format::Int8).expect("schema");
        schema.layout.roles[0].bounds[side] = 0;
        assert!(matches!(schema.constraints::<QM31>(), Err(Error::Encoding)));
    }
    let mut schema = Schema::new(1, 0, Format::Int8).expect("schema");
    schema.layout.roles[0].count = 1;
    assert!(matches!(schema.constraints::<QM31>(), Err(Error::Encoding)));
    for rows in [usize::MAX, 1 << 20] {
        let mut schema = Schema::new(1, 0, Format::Int8).expect("schema");
        schema.layout.rows = rows;
        assert!(matches!(schema.constraints::<QM31>(), Err(Error::Capacity)));
    }
    assert!(buffer::<Term<OM31>>(usize::MAX).is_err());
    let schema = Schema::new(1, 62, Format::Int16).expect("schema");
    for k in [7, 8, 19, usize::MAX] {
        let t = digit::<QM31>(&schema, Operand::Constant(1 << 62), k).expect("constant digit");
        assert_eq!(
            t.coefficient,
            <QM31 as stele_field::Field>::from_i64(if k == 7 { 64 } else { 0 })
        );
        assert!(t.factors.is_empty());
    }
}

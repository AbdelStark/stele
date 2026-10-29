//! RFC-0021 §4: signed lifts, MSB-first points and separate valid-row evaluation.
use stele_cqis::tables::{Descriptor, Error, Table};
use stele_field::{Field, QM31};

#[path = "support/table_mle.rs"]
mod oracle;

fn compare<K: oracle::TestField>(table: &Table) {
    let dimension = table.descriptor().shape().padded().ilog2() as usize;
    let mut expected = oracle::BooleanOracle::<K>::new(table);
    let mut state = 0x1234_0000_0021;
    for _ in 0..2 {
        let point: Vec<K> = (0..dimension).map(|_| K::random(&mut state)).collect();
        let reference = expected.evaluate(table, &point);
        let actual = table.evaluate(&point).expect("native values");
        assert_eq!(actual.columns(), reference.0);
        assert_eq!(actual.valid_rows(), reference.1);
    }
}

#[test]
fn matches_reference_all_kinds_maximum_shapes_and_extension_fields() {
    for case in oracle::CASES {
        let table = oracle::generate(case);
        compare::<QM31>(&table);
        compare::<stele_field::OM31>(&table);
    }
}

#[test]
fn matches_reference_msb_coordinates_and_nonboolean_validity() {
    let range = Table::range(8).expect("range");
    let point: Vec<QM31> = (2..10).map(QM31::from_i64).collect();
    let expected = point.iter().enumerate().fold(QM31::ZERO, |v, (i, r)| {
        v + *r * QM31::from_i64(1 << (7 - i))
    });
    assert_eq!(
        range.evaluate(&point).expect("range MLE").columns(),
        &[expected]
    );
    let rsqrt = Table::rsqrt().expect("rsqrt");
    let point: Vec<QM31> = (2..18).map(QM31::from_i64).collect();
    assert_eq!(
        rsqrt
            .evaluate(&point)
            .expect("three-quarter prefix")
            .valid_rows(),
        QM31::from_i64(-5)
    );
}

#[test]
fn accepts_signed_rows_and_excludes_padding_with_a_separate_selector() {
    let table =
        Table::generate(Descriptor::new("exp_q/direct", 1, &[7, 10, 12]).expect("descriptor"))
            .expect("complete table");
    for row in [0usize, 128, 129, 255] {
        let point: Vec<QM31> = (0..8)
            .map(|bit| QM31::from_i64(((row >> (7 - bit)) & 1) as i64))
            .collect();
        let value = table.evaluate(&point).expect("evaluation");
        assert_eq!(
            value.columns(),
            &[
                QM31::from_i64(i64::from(table.entries()[row * 2])),
                QM31::from_i64(i64::from(table.entries()[row * 2 + 1]))
            ]
        );
        assert_eq!(value.valid_rows(), QM31::from_i64(i64::from(row < 129)));
    }
}

#[test]
fn rejects_wrong_point_dimension_before_evaluation() {
    let table = Table::range(8).expect("range");
    for dimension in [0, 1, 7, 9, 16, 17, 32] {
        let point = vec![QM31::ONE; dimension];
        assert_eq!(table.evaluate(&point), Err(Error::PointDimension));
        assert!(point.iter().all(|v| *v == QM31::ONE));
    }
}

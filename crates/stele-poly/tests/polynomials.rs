//! RFC-0006 §5: compare kernels with the explicit multilinear definition.
use stele_field::{Field, CM31, M31, OM31, QM31};
use stele_poly::{eq_evaluate, eq_table, Error, Mle, SmallMle, Strategy};

fn same<K: Field>(a: &[K], b: &[K]) {
    assert_eq!(a.len(), b.len());
    for (a, b) in a.iter().zip(b) {
        assert_eq!(a.to_le_bytes().as_ref(), b.to_le_bytes().as_ref());
    }
}

fn reference<K: Field>(values: &[i16], point: &[K]) -> Vec<K> {
    let columns = 1 << point.len();
    values
        .chunks_exact(columns)
        .map(|row| {
            row.iter()
                .enumerate()
                .fold(K::from_i64(0), |sum, (index, value)| {
                    let coefficient =
                        point
                            .iter()
                            .enumerate()
                            .fold(K::from_i64(1), |p, (bit, r)| {
                                p * if (index >> (point.len() - 1 - bit)) & 1 == 1 {
                                    *r
                                } else {
                                    K::from_i64(1) - *r
                                }
                            });
                    sum + K::from_i64(i64::from(*value)) * coefficient
                })
        })
        .collect()
}

fn next(seed: &mut u64) -> u32 {
    *seed ^= *seed << 13;
    *seed ^= *seed >> 7;
    *seed ^= *seed << 17;
    (*seed >> 32) as u32
}
fn qm(seed: &mut u64) -> QM31 {
    QM31(
        CM31(
            M31::from_i64(i64::from(next(seed))),
            M31::from_i64(i64::from(next(seed))),
        ),
        CM31(
            M31::from_i64(i64::from(next(seed))),
            M31::from_i64(i64::from(next(seed))),
        ),
    )
}

fn check<K: Field>(values: &[i16], point: &[K], small: &SmallMle) {
    let expected = reference(values, point);
    let naive = small
        .partial_evaluate(point, Strategy::Naive)
        .expect("valid polynomial input");
    let bucketed = small
        .partial_evaluate(point, Strategy::Bucketed)
        .expect("valid polynomial input");
    same(naive.values(), &expected);
    same(bucketed.values(), &expected);
    let mle = Mle::new(values.iter().map(|v| K::from_i64(i64::from(*v))).collect())
        .expect("valid polynomial input");
    same(
        mle.partial_evaluate(point)
            .expect("valid polynomial input")
            .values(),
        &expected,
    );
}

#[test]
fn matches_reference_seeded_small_values_in_challenge_fields() {
    let mut seed = 0x99d1_317a_b387_2d0f;
    for instance in 0..1000 {
        let vars = instance % 7;
        let suffix = if vars == 0 { 0 } else { instance % (vars + 1) };
        for bits in [4, 8] {
            let values: Vec<i16> = (0..1 << vars)
                .map(|_| ((next(&mut seed) % (1 << bits)) as i32 - (1 << (bits - 1))) as i16)
                .collect();
            let narrow: Vec<i8> = values.iter().map(|v| *v as i8).collect();
            let small = if bits == 4 {
                SmallMle::int4(narrow).expect("valid polynomial input")
            } else {
                SmallMle::int8(narrow).expect("valid polynomial input")
            };
            let point: Vec<QM31> = (0..suffix).map(|_| qm(&mut seed)).collect();
            check(&values, &point, &small);
            let point: Vec<OM31> = (0..suffix)
                .map(|_| OM31(qm(&mut seed), qm(&mut seed)))
                .collect();
            check(&values, &point, &small);
        }
    }
    // Exercise every signed int16 value and both endpoints, without repeating a 65536-bucket scan per tiny row.
    let values: Vec<i16> = (i16::MIN..=i16::MAX).collect();
    let small = SmallMle::int16(values.clone()).expect("valid polynomial input");
    let point: Vec<OM31> = (0..16)
        .map(|_| OM31(qm(&mut seed), qm(&mut seed)))
        .collect();
    check(&values, &point, &small);
    for _ in 0..16 {
        let values = vec![
            i16::MIN,
            i16::MAX,
            next(&mut seed) as i16,
            next(&mut seed) as i16,
        ];
        check(
            &values,
            &[qm(&mut seed)],
            &SmallMle::int16(values.clone()).expect("valid polynomial input"),
        );
    }
}

#[test]
fn matches_reference_boolean_indices_and_suffix_composition() {
    let values = vec![-8, 7, -3, 4, 0, 1, -1, 6];
    let small = SmallMle::int4(values.clone()).expect("valid polynomial input");
    for index in 0..8 {
        let point: Vec<_> = (0..3)
            .rev()
            .map(|bit| M31::from_i64((index >> bit) & 1))
            .collect();
        let table = eq_table(&point).expect("valid polynomial input");
        for (i, value) in table.iter().enumerate() {
            assert_eq!(*value, M31::from_i64(i64::from(i == index as usize)));
        }
        same(
            small
                .partial_evaluate(&point, Strategy::Bucketed)
                .expect("valid polynomial input")
                .values(),
            &[M31::from_i64(i64::from(values[index as usize]))],
        );
    }
    let p = [M31::from_i64(17), M31::from_i64(29), M31::from_i64(53)];
    let once = small
        .partial_evaluate(&p, Strategy::Naive)
        .expect("valid polynomial input");
    let tail = small
        .partial_evaluate(&p[1..], Strategy::Bucketed)
        .expect("valid polynomial input");
    same(
        tail.partial_evaluate(&p[..1])
            .expect("valid polynomial input")
            .values(),
        once.values(),
    );
    check(
        &[i16::MIN],
        &[] as &[QM31],
        &SmallMle::int16(vec![i16::MIN]).expect("valid polynomial input"),
    );
    assert_eq!(small.payload_bytes(), 4);
    assert_eq!(
        SmallMle::int4(vec![-8])
            .expect("valid polynomial input")
            .payload_bytes(),
        1
    );
    assert_eq!(
        SmallMle::int8(vec![0; 8])
            .expect("valid polynomial input")
            .payload_bytes(),
        8
    );
    assert_eq!(
        SmallMle::int16(vec![0; 8])
            .expect("valid polynomial input")
            .payload_bytes(),
        16
    );
}

#[test]
fn rejects_invalid_shapes_ranges_and_dimensions() {
    for values in [vec![], vec![0; 3]] {
        assert_eq!(
            SmallMle::int4(values.clone()).expect_err("invalid polynomial input"),
            Error::InvalidLength
        );
        assert_eq!(
            SmallMle::int8(values).expect_err("invalid polynomial input"),
            Error::InvalidLength
        );
    }
    assert_eq!(
        SmallMle::int16(vec![]).expect_err("invalid polynomial input"),
        Error::InvalidLength
    );
    assert_eq!(
        Mle::<M31>::new(vec![]).expect_err("invalid polynomial input"),
        Error::InvalidLength
    );
    for value in [-128, -9, 8, 127] {
        for lane in 0..4 {
            let mut values = vec![0; 4];
            values[lane] = value;
            assert_eq!(
                SmallMle::int4(values).expect_err("invalid polynomial input"),
                Error::Int4Range
            );
        }
    }
    let point = [M31::from_i64(2); 2];
    let small = SmallMle::int8(vec![0, 1]).expect("valid polynomial input");
    for strategy in [Strategy::Naive, Strategy::Bucketed] {
        assert_eq!(
            small
                .partial_evaluate(&point, strategy)
                .expect_err("invalid polynomial input"),
            Error::PointDimension
        );
    }
    assert_eq!(
        Mle::new(vec![M31::from_i64(0)])
            .expect("valid polynomial input")
            .partial_evaluate(&point)
            .expect_err("invalid polynomial input"),
        Error::PointDimension
    );
    assert_eq!(
        eq_table(&vec![M31::from_i64(0); usize::BITS as usize])
            .expect_err("invalid polynomial input"),
        Error::Capacity
    );
}

#[test]
fn matches_reference_verifier_eq_on_10000_points() {
    let mut seed = 0x862a_b18f_971d_aeb3;
    for instance in 0..10000 {
        let dimension = instance % 8;
        let left: Vec<_> = (0..dimension)
            .map(|_| OM31(qm(&mut seed), qm(&mut seed)))
            .collect();
        let right: Vec<_> = (0..dimension)
            .map(|_| OM31(qm(&mut seed), qm(&mut seed)))
            .collect();
        let table = eq_table(&left).expect("bounded shape");
        let expected = table
            .iter()
            .enumerate()
            .fold(OM31::from_i64(0), |sum, (index, value)| {
                let weight = right
                    .iter()
                    .enumerate()
                    .fold(OM31::from_i64(1), |p, (bit, r)| {
                        p * if (index >> (dimension - 1 - bit)) & 1 == 1 {
                            *r
                        } else {
                            OM31::from_i64(1) - *r
                        }
                    });
                sum + *value * weight
            });
        same(
            &[eq_evaluate(&left, &right).expect("matching dimensions")],
            &[expected],
        );
    }
    assert_eq!(
        eq_evaluate(&[M31::from_i64(1)], &[]).expect_err("mismatched points"),
        Error::PointDimension
    );
}

//! Independent direct-basis oracle for RFC-0010 A2; no PCS acceptance claim.
use core::fmt::Debug;
use stele_code::{Circle, Error};
use stele_field::{Field, KoalaBear, CM31, M31, OM31, QM31};

const P: u64 = (1 << 31) - 1;

fn next(seed: &mut u64) -> u64 {
    *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
    *seed
}
fn base(seed: &mut u64) -> M31 {
    M31::from_u64(next(seed))
}
fn quadratic(seed: &mut u64) -> CM31 {
    CM31(base(seed), base(seed))
}
fn quartic(seed: &mut u64) -> QM31 {
    QM31(quadratic(seed), quadratic(seed))
}
fn octic(seed: &mut u64) -> OM31 {
    OM31(quartic(seed), quartic(seed))
}

// Integer arithmetic and per-point exponentiation share no production twiddle code.
fn product(a: (u64, u64), b: (u64, u64)) -> (u64, u64) {
    (
        (a.0 * b.0 + P * P - a.1 * b.1) % P,
        (a.0 * b.1 + a.1 * b.0) % P,
    )
}
fn point(log: u32, index: usize) -> (u64, u64) {
    let mut exponent = (2 * index as u64 + 1) << (30 - log);
    let (mut g, mut out) = ((1717986917, 1288490189), (1, 0));
    while exponent != 0 {
        if exponent & 1 != 0 {
            out = product(out, g);
        }
        g = product(g, g);
        exponent >>= 1;
    }
    out
}
fn direct<K: Field>(coefficients: &[K], pt: (u64, u64)) -> K {
    let mut result = K::from_i64(0);
    for (index, coefficient) in coefficients.iter().enumerate() {
        let mut term = *coefficient;
        if index & 1 != 0 {
            term = term * K::from_i64(pt.1 as i64);
        }
        let (mut bits, mut x) = (index >> 1, pt.0);
        while bits != 0 {
            if bits & 1 != 0 {
                term = term * K::from_i64(x as i64);
            }
            x = (2 * x * x + P - 1) % P;
            bits >>= 1;
        }
        result = result + term;
    }
    result
}

fn parity<K: Field + Eq + Debug>(random: fn(&mut u64) -> K) {
    let mut seed = 402;
    for m in 0..=6 {
        for blowup in [1, 2] {
            let code = Circle::new(m, blowup).expect("valid dimensions");
            for case in 0..8 {
                let coefficients: Vec<_> = (0..code.message_len())
                    .map(|j| match case {
                        0 => K::from_i64(0),
                        1 => K::from_i64(1),
                        2 => K::from_i64(-1),
                        3 => K::from_i64(i64::from(j == code.message_len() - 1)),
                        _ => random(&mut seed),
                    })
                    .collect();
                let row: Vec<_> = (0..code.message_len())
                    .map(|j| direct(&coefficients, point(m, j)))
                    .collect();
                let expected: Vec<_> = (0..code.codeword_len())
                    .map(|j| direct(&coefficients, point(m + blowup, j)))
                    .collect();
                let encoded = code.encode(&row).expect("encode");
                assert_eq!(encoded, expected, "m={m}, blowup={blowup}, case={case}");
                let columns = [code.codeword_len() - 1, 0, 1, 0];
                assert_eq!(
                    code.eval_row(&row, &columns).expect("columns"),
                    columns.map(|j| expected[j])
                );
                assert!(code.eval_row(&row, &[]).expect("empty request").is_empty());
                let scale = random(&mut seed);
                let other: Vec<_> = (0..row.len()).map(|_| random(&mut seed)).collect();
                let combined: Vec<_> = row
                    .iter()
                    .zip(&other)
                    .map(|(a, b)| *a + scale * *b)
                    .collect();
                let other_encoded = code.encode(&other).expect("other row");
                assert_eq!(
                    code.encode(&combined).expect("linear combination"),
                    encoded
                        .iter()
                        .zip(other_encoded)
                        .map(|(a, b)| *a + scale * b)
                        .collect::<Vec<_>>()
                );
            }
        }
    }
}

#[test]
fn matches_reference_m31_circle_encoding() {
    parity(base);
}
#[test]
fn matches_reference_cm31_circle_encoding() {
    parity(quadratic);
}
#[test]
fn matches_reference_qm31_circle_encoding() {
    parity(quartic);
}
#[test]
fn matches_reference_om31_circle_encoding() {
    parity(octic);
}

#[test]
fn accepts_maximum_dimensions_without_allocating() {
    for (m, b) in [(29, 1), (28, 2)] {
        let code = Circle::new(m, b).expect("maximum size");
        assert_eq!(code.message_len(), 1 << m);
        assert_eq!(code.codeword_len(), 1 << 30);
        let mut expected = b"stele/circle-m31/v1".to_vec();
        expected.extend([m as u8, b as u8]);
        assert_eq!(code.code_id().as_slice(), expected);
    }
}

#[test]
fn rejects_invalid_sizes_rows_columns_and_characteristic() {
    for (m, b) in [
        (0, 0),
        (1, 3),
        (30, 1),
        (29, 2),
        (u32::MAX, 1),
        (1, u32::MAX),
    ] {
        assert!(matches!(Circle::new(m, b), Err(Error::InvalidSize)));
    }
    let code = Circle::new(2, 1).expect("valid");
    for len in [0, 1, 3, 5] {
        assert_eq!(code.encode(&vec![M31::ZERO; len]), Err(Error::RowShape));
        assert_eq!(
            code.eval_row(&vec![M31::ZERO; len], &[]),
            Err(Error::RowShape)
        );
    }
    assert_eq!(code.eval_row(&[M31::ZERO; 4], &[0, 8]), Err(Error::Column));
    assert_eq!(
        code.eval_row(&[M31::ZERO; 4], &[usize::MAX]),
        Err(Error::Column)
    );
    assert_eq!(
        code.encode(&[KoalaBear::from_i64(0); 4]),
        Err(Error::FieldMismatch)
    );
    assert_eq!(
        code.eval_row(&[KoalaBear::from_i64(0); 4], &[]),
        Err(Error::FieldMismatch)
    );
}

#[test]
fn accepts_constant_and_non_mds_distance_example() {
    let mut seed = 5;
    let value = OM31(quartic(&mut seed), QM31::ONE);
    for b in [1, 2] {
        let c = Circle::new(0, b).expect("constant code");
        assert_eq!(c.encode(&[value]).expect("constant"), vec![value; 1 << b]);
    }
    let y = M31::from_u64(point(2, 0).1);
    let code = Circle::new(1, 1).expect("code");
    let row: Vec<_> = (0..2).map(|j| M31::from_u64(point(1, j).1) - y).collect();
    let encoded = code.encode(&row).expect("encode");
    assert_eq!(encoded.iter().filter(|v| **v != M31::ZERO).count(), 2);
}

#[test]
fn matches_reference_python_vectors() {
    let parse = |text: &str| -> Vec<M31> {
        text.split(',')
            .map(|v| M31::from_canonical(v.parse().expect("integer")).expect("canonical limb"))
            .collect()
    };
    let mut count = 0;
    for line in include_str!("../../../research/circle-code/vectors.txt").lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        assert_eq!(fields.len(), 4);
        let code = Circle::new(
            fields[0].parse().expect("log"),
            fields[1].parse().expect("rate"),
        )
        .expect("shape");
        assert_eq!(
            code.encode(&parse(fields[2])).expect("encode"),
            parse(fields[3])
        );
        count += 1;
    }
    assert_eq!(count, 12);
}

//! RFC-0014 A2. Direct multilinear evaluation of both original batch factors.
use stele_field::{Field, CM31, M31, QM31};
use stele_kernels::{Backend, Error, Scalar, SourceGeometry, WeightedClaim};

fn m(x: i64) -> M31 {
    M31::from_i64(x)
}

fn q(x: i64) -> QM31 {
    QM31(CM31(m(x), m(x + 3)), CM31(m(-x), m(2 * x + 1)))
}

fn evaluate(table: &[QM31], point: &[QM31]) -> QM31 {
    table
        .iter()
        .enumerate()
        .fold(QM31::ZERO, |sum, (index, x)| {
            let weight = point.iter().enumerate().fold(QM31::ONE, |w, (k, r)| {
                w * if index >> (point.len() - 1 - k) & 1 == 0 {
                    QM31::ONE - *r
                } else {
                    *r
                }
            });
            sum + weight * *x
        })
}

#[test]
fn matches_reference_original_dense_batches_and_finals() {
    let mut checked = 0;
    for case in 0..1000usize {
        let backend = Scalar::<QM31>::new();
        let rows = 2 << (case % 2);
        let cols = 2 << (case / 2 % 3);
        let g = SourceGeometry {
            id: 7,
            rows,
            columns: cols,
        };
        let half = rows * cols / 4;
        let message: Vec<M31> = (0..rows * cols)
            .map(|i| m((case + i * 17) as i64))
            .collect();
        let owner = backend
            .original(g, &message)
            .expect("valid reference fixture");
        let mut w = vec![QM31::ZERO; 2 * half];
        // Deterministic, distinct seeds for the ordered positions, field limbs and folds.
        let mut seed = (case as u64 + 1) ^ 0x41d2_ba77;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            (seed as u32 & 0x3fff_ffff) as i64
        };
        let pos = next() as usize % half;
        let a = q(next());
        let b = q(next());
        let first = [(pos, a), (pos, b)];
        let last = [(half - 1, q(-3))];
        let claims = [
            WeightedClaim {
                weights: &first,
                value: a,
                gamma: b,
            },
            WeightedClaim {
                weights: &[],
                value: b,
                gamma: a,
            },
            WeightedClaim {
                weights: &last,
                value: q(4),
                gamma: a,
            },
        ];
        w[pos] = b * a + b * b;
        w[half - 1] = w[half - 1] + a * q(-3);
        let face: Vec<_> = message
            .chunks_exact(cols)
            .flat_map(|r| r.iter().take(cols / 2))
            .map(|x| QM31::from_i64(i64::from(x.as_u32())))
            .collect();
        let (mut state, value) = backend
            .dense_batch(g, &owner, &claims)
            .expect("valid reference fixture");
        assert_eq!(value, b * a + a * b + a * q(4));
        let n = (2 * half).ilog2() as usize;
        let mut point = Vec::new();
        for axis in 0..n {
            let got = Scalar::dense_round(&mut state).expect("valid reference fixture");
            for (s, actual) in got.into_iter().enumerate() {
                let mut expected = QM31::ZERO;
                for tail in 0..1usize << (n - axis - 1) {
                    let mut p = point.clone();
                    p.push(QM31::from_i64(s as i64));
                    p.extend(
                        (0..n - axis - 1)
                            .rev()
                            .map(|bit| QM31::from_i64(((tail >> bit) & 1) as i64)),
                    );
                    expected = expected + evaluate(&w, &p) * evaluate(&face, &p);
                }
                assert_eq!(actual, expected);
            }
            let r = q(next());
            Scalar::dense_fold(&mut state, r).expect("valid reference fixture");
            point.push(r);
        }
        assert_eq!(
            Scalar::dense_finals(&state).expect("valid reference fixture"),
            [evaluate(&w, &point), evaluate(&face, &point)]
        );
        checked += 1;
    }
    eprintln!("ordinary_scalar_cases={checked}");
}

#[test]
fn rejects_stale_equal_geometry_and_invalid_state() {
    let a = Scalar::<QM31>::new();
    let b = Scalar::<QM31>::new();
    let g = SourceGeometry {
        id: 1,
        rows: 2,
        columns: 2,
    };
    let words = [
        m(0),
        m(1),
        m(-1),
        M31::from_lazy(M31::MODULUS).expect("valid reference fixture"),
    ];
    assert!(matches!(a.original(g, &words[..3]), Err(Error::Shape)));
    let x = a.original(g, &words).expect("valid reference fixture");
    assert!(matches!(a.original(g, &words), Err(Error::DuplicateSource)));
    let _other = b.original(g, &[m(13); 4]).expect("valid reference fixture");
    assert!(matches!(b.dense_batch(g, &x, &[]), Err(Error::Source)));
    assert!(matches!(
        a.dense_batch(SourceGeometry { id: 2, ..g }, &x, &[]),
        Err(Error::Source)
    ));
    let bad = [WeightedClaim {
        weights: &[(1, q(3))],
        value: q(0),
        gamma: q(1),
    }];
    assert!(matches!(a.dense_batch(g, &x, &bad), Err(Error::Shape)));
    let (mut state, _) = a.dense_batch(g, &x, &[]).expect("valid reference fixture");
    assert!(matches!(
        Scalar::dense_fold(&mut state, q(1)),
        Err(Error::Phase)
    ));
    assert!(matches!(Scalar::dense_finals(&state), Err(Error::Phase)));
    Scalar::dense_round(&mut state).expect("valid reference fixture");
    assert!(matches!(Scalar::dense_round(&mut state), Err(Error::Phase)));
    Scalar::dense_fold(&mut state, q(1)).expect("valid reference fixture");
    assert!(matches!(Scalar::dense_round(&mut state), Err(Error::Phase)));
    assert!(matches!(
        Scalar::dense_fold(&mut state, q(1)),
        Err(Error::Phase)
    ));
}

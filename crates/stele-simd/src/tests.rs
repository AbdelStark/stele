//! Byte-exact scalar/native parity, including lazy inputs (RFC-0003 §§1,6).
use crate::{Backend, Op, PackedM31, PackedQM31};
const P: u32 = (1 << 31) - 1;

fn next(state: &mut u64) -> u32 {
    *state = state.wrapping_add(0x9e3779b97f4a7c15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
    ((z ^ (z >> 31)) % (2 * u64::from(P))) as u32
}

fn backends() -> Vec<Backend> {
    let all = [
        Backend::Scalar,
        Backend::Neon,
        Backend::Avx2,
        Backend::Avx512,
    ];
    for backend in all {
        if !backend.available() {
            let x = PackedM31::from_lazy([0; 16]).expect("valid input");
            assert!(backend.m31(Op::Mul, x, x).is_err());
            let q = PackedQM31::from_lazy([[0; 16]; 4]).expect("valid input");
            assert!(backend.qm31(Op::Mul, q, q).is_err());
        }
    }
    let available: Vec<_> = all.into_iter().filter(|b| b.available()).collect();
    eprintln!("executed backends: {available:?}");
    if let Ok(required) = std::env::var("STELE_REQUIRE_SIMD") {
        for name in required.split(',') {
            assert!(
                available
                    .iter()
                    .any(|b| format!("{b:?}").eq_ignore_ascii_case(name)),
                "required backend unavailable: {name}"
            );
        }
    }
    assert!(available.contains(&Backend::detect()));
    available
}

#[test]
fn matches_reference_100000_lazy_vectors() {
    let backends = backends();
    let mut seed = 0x5354_454c_4500_0004;
    for _ in 0..100_000 {
        let raw_a = std::array::from_fn(|_| std::array::from_fn(|_| next(&mut seed)));
        let raw_b = std::array::from_fn(|_| std::array::from_fn(|_| next(&mut seed)));
        let a = PackedQM31::from_lazy(raw_a).expect("lazy input");
        let b = PackedQM31::from_lazy(raw_b).expect("lazy input");
        let ma = PackedM31::from_lazy(raw_a[0]).expect("lazy input");
        let mb = PackedM31::from_lazy(raw_b[0]).expect("lazy input");
        for op in [Op::Add, Op::Sub, Op::Mul] {
            let expected_m = Backend::Scalar.m31(op, ma, mb).expect("scalar").to_array();
            let expected_q = Backend::Scalar.qm31(op, a, b).expect("scalar").to_array();
            for backend in &backends {
                let packed_m = backend.m31(op, ma, mb).expect("available");
                let packed_q = backend.qm31(op, a, b).expect("available");
                assert!(packed_m
                    .0
                    .iter()
                    .chain(packed_q.0.iter().flatten())
                    .all(|x| *x < P));
                let m = packed_m.to_array();
                let q = packed_q.to_array();
                assert_eq!(m.map(u32::to_le_bytes), expected_m.map(u32::to_le_bytes));
                assert_eq!(
                    q.map(|c| c.map(u32::to_le_bytes)),
                    expected_q.map(|c| c.map(u32::to_le_bytes))
                );
                assert!(m.iter().chain(q.iter().flatten()).all(|x| *x < P));
            }
        }
    }
}

#[test]
fn matches_reference_lazy_boundaries_and_lane_order() {
    let backends = backends();
    let edges = [0, 1, P - 1, P, P + 1, 2 * P - 1];
    for a in edges {
        for b in edges {
            let x = PackedM31::from_lazy([a; 16]).expect("valid");
            let y = PackedM31::from_lazy([b; 16]).expect("valid");
            for op in [Op::Add, Op::Sub, Op::Mul] {
                for backend in &backends {
                    assert_eq!(
                        backend.m31(op, x, y).expect("available").0,
                        Backend::Scalar.m31(op, x, y).expect("scalar").to_array()
                    );
                }
            }
        }
    }
    for lane in 0..16 {
        for column in 0..4 {
            let mut input = [[0; 16]; 4];
            input[column][lane] = P + 1;
            let a = PackedQM31::from_lazy(input).expect("valid");
            let b = PackedQM31::from_lazy(std::array::from_fn(|c| {
                std::array::from_fn(|i| (17 * c + i + 1) as u32)
            }))
            .expect("valid");
            for backend in &backends {
                assert_eq!(
                    backend.qm31(Op::Mul, a, b).expect("available").0,
                    Backend::Scalar
                        .qm31(Op::Mul, a, b)
                        .expect("scalar")
                        .to_array()
                );
            }
        }
    }
}

#[test]
fn rejects_invalid_lazy_limb_in_every_position() {
    for invalid in [2 * P, u32::MAX] {
        for lane in 0..16 {
            let mut m = [0; 16];
            m[lane] = invalid;
            assert!(PackedM31::from_lazy(m).is_none());
            for column in 0..4 {
                let mut q = [[0; 16]; 4];
                q[column][lane] = invalid;
                assert!(PackedQM31::from_lazy(q).is_none());
            }
        }
    }
    assert_eq!(
        PackedM31::from_lazy([P; 16]).expect("valid").to_array(),
        [0; 16]
    );
}

fn element(state: &mut u64, edge: bool) -> stele_field::QM31 {
    use stele_field::{CM31, M31, QM31};
    const EDGES: [u32; 4] = [0, 1, P - 1, P - 2];
    let mut limb = || {
        let raw = next(state);
        M31::from_canonical(if edge {
            EDGES[(raw & 3) as usize]
        } else {
            raw % P
        })
        .expect("canonical")
    };
    QM31(CM31(limb(), limb()), CM31(limb(), limb()))
}

#[test]
fn matches_reference_qm31_fold_on_seeded_and_edge_tables() {
    let backends = backends();
    let mut seed = 0x5354_454c_4500_0020;
    // 1000 seeded tables: every length across a vector boundary, with edge limbs and
    // edge challenges in a quarter of them.
    for case in 0..1000usize {
        let n = case % 41;
        let edge = case % 4 == 0;
        let lo: Vec<_> = (0..n).map(|_| element(&mut seed, edge)).collect();
        let hi: Vec<_> = (0..n).map(|_| element(&mut seed, edge)).collect();
        let c = element(&mut seed, case % 8 == 0);
        let mut expected = lo.clone();
        crate::fold_reference(&mut expected, &hi, c);
        for backend in &backends {
            let mut folded = lo.clone();
            backend.fold(&mut folded, &hi, c).expect("available");
            assert_eq!(folded, expected, "{backend:?} case {case}");
        }
        let mut folded = lo.clone();
        crate::fold(&mut folded, &hi, c);
        assert_eq!(folded, expected, "detected backend, case {case}");
    }
    // A longer low half than high half folds the common prefix only.
    let lo: Vec<_> = (0..9).map(|_| element(&mut seed, false)).collect();
    let hi: Vec<_> = (0..5).map(|_| element(&mut seed, false)).collect();
    let c = element(&mut seed, false);
    let mut expected = lo.clone();
    crate::fold_reference(&mut expected, &hi, c);
    for backend in &backends {
        let mut folded = lo.clone();
        backend.fold(&mut folded, &hi, c).expect("available");
        assert_eq!(folded, expected);
        assert_eq!(folded[5..], lo[5..]);
    }
    for backend in [Backend::Neon, Backend::Avx2, Backend::Avx512] {
        if !backend.available() {
            assert!(backend.fold(&mut [], &[], c).is_err());
        }
    }
}

#[test]
fn matches_reference_qm31_layer_round_on_seeded_and_edge_tables() {
    let backends = backends();
    let mut seed = 0x5354_454c_4500_0021;
    // 1000 seeded layers: halves across a vector boundary, sub-ranges that start and end
    // off a vector boundary, edge limbs and an edge γ in a quarter of them.
    for case in 0..1000usize {
        let half = case % 23;
        let edge = case % 4 == 0;
        let tables: Vec<Vec<_>> = (0..4)
            .map(|_| (0..2 * half).map(|_| element(&mut seed, edge)).collect())
            .collect();
        let e: Vec<_> = (0..half).map(|_| element(&mut seed, edge)).collect();
        let gamma = element(&mut seed, case % 8 == 0);
        let start = if half == 0 { 0 } else { case / 23 % (half + 1) };
        let end = start + (case / 7 % (half - start + 1));
        let view = [
            &tables[0][..],
            &tables[1][..],
            &tables[2][..],
            &tables[3][..],
        ];
        let expected = crate::layer_round_reference(view, &e, gamma, start..end);
        for backend in &backends {
            assert_eq!(
                backend
                    .layer_round(view, &e, gamma, start..end)
                    .expect("available"),
                expected,
                "{backend:?} case {case}"
            );
        }
        assert_eq!(crate::layer_round(view, &e, gamma, start..end), expected);
    }
    let zero = element(&mut seed, false);
    for backend in [Backend::Neon, Backend::Avx2, Backend::Avx512] {
        if !backend.available() {
            assert!(backend
                .layer_round([&[], &[], &[], &[]], &[], zero, 0..0)
                .is_err());
        }
    }
}

#[test]
fn matches_reference_m31_butterflies_on_seeded_and_edge_rows() {
    use stele_field::M31;
    let backends = backends();
    let mut seed = 0x5354_454c_4500_0022;
    const EDGES: [u32; 4] = [0, 1, P - 1, P - 2];
    // 1000 seeded levels: every length across a vector boundary, edge limbs in a quarter.
    for case in 0..1000usize {
        let n = case % 67;
        let mut limbs = |edge: bool| -> Vec<M31> {
            (0..n)
                .map(|_| {
                    let raw = next(&mut seed);
                    let limb = if edge {
                        EDGES[(raw & 3) as usize]
                    } else {
                        raw % P
                    };
                    M31::from_canonical(limb).expect("canonical")
                })
                .collect()
        };
        let (low, high, twiddles) = (
            limbs(case % 4 == 0),
            limbs(case % 4 == 0),
            limbs(case % 8 == 0),
        );
        let (mut expected_low, mut expected_high) = (low.clone(), high.clone());
        crate::butterflies_reference(&mut expected_low, &mut expected_high, &twiddles);
        for backend in &backends {
            let (mut l, mut h) = (low.clone(), high.clone());
            backend
                .butterflies(&mut l, &mut h, &twiddles)
                .expect("available");
            assert_eq!(
                (l, h),
                (expected_low.clone(), expected_high.clone()),
                "{backend:?} case {case}"
            );
        }
        let (mut l, mut h) = (low.clone(), high.clone());
        crate::butterflies(&mut l, &mut h, &twiddles);
        assert_eq!((l, h), (expected_low, expected_high));
    }
}

#[test]
fn matches_reference_qm31_products_on_seeded_and_edge_slices() {
    let backends = backends();
    let mut seed = 0x5354_454c_4500_0023;
    for case in 0..1000usize {
        let n = case % 41;
        let edge = case % 4 == 0;
        let a: Vec<_> = (0..n).map(|_| element(&mut seed, edge)).collect();
        let b: Vec<_> = (0..n).map(|_| element(&mut seed, case % 8 == 0)).collect();
        let mut expected = a.clone();
        crate::mul_assign_reference(&mut expected, &b);
        for backend in &backends {
            let mut product = a.clone();
            backend.mul_assign(&mut product, &b).expect("available");
            assert_eq!(product, expected, "{backend:?} case {case}");
        }
        let mut product = a.clone();
        crate::mul_assign(&mut product, &b);
        assert_eq!(product, expected);
    }
}

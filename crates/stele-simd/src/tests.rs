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

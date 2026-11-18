//! RFC-0014 A3. Compare genuine device GKR operations against the field-only scalar backend.
use crate::{Cuda, Error, Session};
use stele_kernels::gkr::{
    GkrBackend, GkrConstruction, GkrFactor, GkrMask, GkrMember, GkrSelector, Term,
};
use stele_kernels::{Field, Scalar, CM31, M31, QM31};

#[test]
#[ignore = "requires a real CUDA device; invoked explicitly by the hardware gate"]
fn matches_reference_cuda_gkr() {
    for raw in [false, true] {
        RAW.set(raw);
        compare_representatives();
    }
    RAW.set(false);
    println!("cuda_gkr_cases=1000 raw_cuda_gkr_cases=1000 field_rounds=8000 field_folds=8000 field_finals=2000");
}

std::thread_local! { pub(crate) static RAW: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }

fn compare_representatives() {
    let cuda = Cuda::new().expect("required CUDA device");
    let mut rounds = 0;
    let mut seed = 0xc0590425a1u64;
    let mut base = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        match seed % 7 {
            0 => M31::ZERO,
            1 => M31::ONE,
            2 => M31::from_i64(-1),
            3 => M31::from_lazy(M31::MODULUS).expect("valid GKR fixture"),
            4 => M31::from_lazy(2 * M31::MODULUS - 1).expect("valid GKR fixture"),
            _ => M31::from_u64(seed),
        }
    };
    for id in 0..1000 {
        let gpu = cuda.session();
        let cpu = Scalar::new();
        let n = 2 + id % 5;
        let layer_bits = n - id % 2;
        let half = 1usize << layer_bits;
        let component = id % 2;
        let side = id / 2 % 2;
        let point = QM31(CM31(base(), base()), CM31(base(), base()));
        let values: Vec<_> = (0..2 * half)
            .map(|_| {
                [
                    QM31(CM31(base(), base()), CM31(base(), base())),
                    QM31(CM31(base(), base()), CM31(base(), base())),
                ]
            })
            .collect();
        let mask = GkrMask {
            coordinates: &[0],
            vanishing: id % n,
            values: vec![base(), base()],
        };
        let period = 1usize << (id % (layer_bits + 1));
        let coords = [0];
        let columns = [point, QM31::ONE];
        let column_mask = || GkrMask {
            coordinates: &coords,
            vanishing: (id + 1) % n,
            values: vec![M31::ONE, M31::ZERO],
        };
        let rows = [vec![id as i64, -1], vec![1, id as i64]];
        let selected = [-1, id as i64];
        let at = [point];
        let mut input = GkrConstruction {
            num_vars: n as u32,
            layer_variables: layer_bits,
            degree: 6,
            terms: vec![
                Term {
                    coefficient: QM31::ONE,
                    factors: vec![0, 1],
                },
                Term {
                    coefficient: point,
                    factors: vec![],
                },
            ],
            factors: vec![
                GkrFactor::Layer {
                    values: &values,
                    component,
                    side,
                    mask,
                },
                GkrFactor::Block {
                    values: (0..2 * period).map(|_| base()).collect(),
                    point,
                },
                GkrFactor::Equality {
                    point: &at,
                    scale: point,
                    offset: (1 << n) - 2,
                },
                GkrFactor::Column {
                    values: &columns,
                    coordinates: vec![n - 1],
                    mask: column_mask(),
                },
                GkrFactor::Combined {
                    members: vec![GkrMember {
                        range: 0..half,
                        values: &columns,
                        coordinates: &coords,
                        shift: -1,
                        mask: vec![M31::ONE, M31::from_i64(-1)],
                    }],
                    vanishing: id % n,
                },
                GkrFactor::Selector {
                    members: vec![GkrSelector {
                        range: 0..half,
                        values: Some((&selected, &coords)),
                    }],
                },
                GkrFactor::Table {
                    rows: &rows,
                    valid: 2,
                    alpha: point,
                    beta: point + QM31::ONE,
                },
                GkrFactor::Pad { variables: 1 },
            ],
        };
        for (a, b) in [(2, 3), (3, 4), (5, 6), (7, 7)] {
            input.terms.push(Term {
                coefficient: point + QM31::ONE,
                factors: vec![a, b],
            });
        }
        let mut reference = cpu.gkr_start(&input).expect("valid GKR fixture");
        let mut selected = gpu.gkr_start(&input).expect("valid GKR fixture");
        assert!(matches!(Session::gkr_finals(&selected), Err(Error::Phase)));
        assert!(matches!(
            Session::gkr_fold(&mut selected, point),
            Err(Error::Phase)
        ));
        for k in 0..n {
            assert_eq!(
                Scalar::gkr_round(&mut reference).expect("valid GKR fixture"),
                Session::gkr_round(&mut selected).expect("valid GKR fixture"),
                "round {k} of {id}"
            );
            assert!(matches!(
                Session::gkr_round(&mut selected),
                Err(Error::Phase)
            ));
            let c = QM31(CM31(base(), base()), CM31(base(), base()));
            Scalar::gkr_fold(&mut reference, c).expect("valid GKR fixture");
            Session::gkr_fold(&mut selected, c).expect("valid GKR fixture");
        }
        assert_eq!(
            Scalar::gkr_finals(&reference).expect("valid GKR fixture"),
            Session::gkr_finals(&selected).expect("valid GKR fixture")
        );
        assert!(matches!(
            Session::gkr_round(&mut selected),
            Err(Error::Phase)
        ));
        rounds += n;
        let counts = gpu.counts();
        assert_eq!(
            (
                counts.gkr_steps,
                counts.gkr_rounds,
                counts.gkr_folds,
                counts.gkr_finals
            ),
            (1, n, n, 1)
        );
        input.terms[0].factors.push(input.factors.len() as u32);
        assert!(matches!(gpu.gkr_start(&input), Err(Error::Geometry)));
    }
    assert_eq!(rounds, 4000);
}

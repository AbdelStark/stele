//! RFC-0014 A3. Compare genuine device GKR operations against the field-only scalar backend.
#![cfg(feature = "cuda")]
use stele_gpu::{Cuda, Error, Session};
use stele_kernels::gkr::{GkrBackend, GkrConstruction, GkrFactor, GkrMask, Term};
use stele_kernels::{Field, Scalar, CM31, M31, QM31};

#[test]
#[ignore = "requires a real CUDA device; invoked explicitly by the hardware gate"]
fn matches_reference_cuda_gkr() {
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
        let mut input = GkrConstruction {
            num_vars: n as u32,
            layer_variables: layer_bits,
            degree: 4,
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
            ],
        };
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
        input.terms[0].factors.push(2);
        assert!(matches!(gpu.gkr_start(&input), Err(Error::Geometry)));
    }
    println!("cuda_gkr_cases=1000 rounds={rounds} folds={rounds} finals=1000");
}

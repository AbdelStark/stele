//! RFC-0014 A4. Direct relation operands, masked projections and their field messages.
use crate::{Cuda, Error, Session};
use stele_kernels::gkr::{
    GkrBackend, GkrMask, Projected, RelationBackend, RelationConstruction, Term,
};
use stele_kernels::{Field, Scalar, CM31, M31, QM31};

#[test]
#[ignore = "requires a real CUDA device; invoked explicitly by the hardware gate"]
fn matches_reference_cuda_relations() {
    let device = Cuda::new().expect("required CUDA device");
    let mut total = 0;
    for raw in [false, true] {
        crate::gkr_tests::RAW.set(raw);
        for index in 0..1000 {
            let vars = 2 + index % 5;
            let v = index % vars;
            let q = |j: usize| {
                let a = M31::from_u64((index * 19 + j * 37) as u64);
                QM31(CM31(a, M31::from_i64(-1)), CM31(M31::ONE, a))
            };
            let values = [q(0), q(1), q(2), q(3)];
            let ones = [QM31::from_i64(-1)];
            let base = [QM31::ZERO, QM31::ONE];
            let mask_coords = [vars - 1];
            let mut input = RelationConstruction {
                num_vars: vars as u32,
                degree: 6,
                factors: vec![
                    Projected {
                        values: &values,
                        coordinates: vec![vars - 1, 0],
                        mask: Some(GkrMask {
                            coordinates: &mask_coords,
                            vanishing: v,
                            values: vec![M31::from_i64(-1), M31::from_u64(index as u64)],
                        }),
                    },
                    Projected {
                        values: &ones,
                        coordinates: vec![],
                        mask: None,
                    },
                    Projected {
                        values: &base,
                        coordinates: vec![0],
                        mask: None,
                    },
                ],
                terms: vec![
                    Term {
                        coefficient: q(4),
                        factors: vec![0, 0],
                    },
                    Term {
                        coefficient: QM31::ONE,
                        factors: vec![1, 2],
                    },
                    Term {
                        coefficient: q(7),
                        factors: vec![],
                    },
                ],
            };
            let gpu = device.session();
            let cpu = Scalar::new();
            let mut selected = gpu
                .relation_start(&input)
                .expect("valid masked projected source");
            let mut reference = cpu.relation_start(&input).expect("scalar relation");
            assert!(matches!(Session::gkr_finals(&selected), Err(Error::Phase)));
            for axis in 0..vars {
                assert_eq!(
                    Session::gkr_round(&mut selected).expect("device relation round"),
                    Scalar::gkr_round(&mut reference).expect("scalar relation round")
                );
                let point = q(12 + axis);
                Session::gkr_fold(&mut selected, point).expect("device relation fold");
                Scalar::gkr_fold(&mut reference, point).expect("scalar relation fold");
            }
            assert_eq!(
                Session::gkr_finals(&selected).expect("device relation finals"),
                Scalar::gkr_finals(&reference).expect("scalar relation finals")
            );
            let c = gpu.counts();
            assert_eq!(
                (
                    c.relation_steps,
                    c.relation_rounds,
                    c.relation_folds,
                    c.relation_finals
                ),
                (1, vars, vars, 1)
            );
            assert_eq!(
                (c.gkr_steps, c.gkr_rounds, c.gkr_folds, c.gkr_finals),
                (0, 0, 0, 0)
            );
            assert_eq!(
                (c.uploaded_bytes, c.downloaded_bytes),
                (c.relation_uploaded_bytes, c.relation_downloaded_bytes)
            );
            input.factors[0].coordinates[0] = vars;
            assert!(matches!(gpu.relation_start(&input), Err(Error::Geometry)));
            total += vars;
        }
    }
    crate::gkr_tests::RAW.set(false);
    assert_eq!(total, 8000);
    println!("cuda_relation_cases=1000 raw_cuda_relation_cases=1000 field_rounds=8000 field_folds=8000 field_finals=2000");
}

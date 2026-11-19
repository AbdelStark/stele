//! RFC-0014 A3. Direct evaluations at the declared integer nodes and actual fold points.
use stele_kernels::gkr::{GkrBackend, GkrConstruction, GkrFactor, GkrMask, Term};
use stele_kernels::{Field, Scalar, CM31, M31, QM31};

fn q(n: i64) -> QM31 {
    QM31(
        CM31(M31::from_i64(n), M31::from_i64(n + 1)),
        CM31(M31::from_i64(2 * n), M31::ONE),
    )
}
fn lerp(a: QM31, b: QM31, x: QM31) -> QM31 {
    a + x * (b - a)
}

#[test]
fn matches_reference_live_gkr_masked_rounds() {
    for case in 0..1000 {
        let cpu = Scalar::<QM31>::new();
        let values = [q(case), q(-3), q(7), q(case + 1)];
        let mask = [M31::from_i64(-2), M31::from_i64(case + 2)];
        let r = [q(-7), q(13)];
        let fields = GkrConstruction {
            num_vars: 2,
            layer_variables: 2,
            degree: 4,
            factors: vec![
                GkrFactor::Equality {
                    point: &r,
                    scale: q(3),
                    offset: 0,
                },
                GkrFactor::Column {
                    values: &values,
                    coordinates: vec![0, 1],
                    mask: GkrMask {
                        values: mask.to_vec(),
                        coordinates: &[1],
                        vanishing: 0,
                    },
                },
            ],
            terms: vec![Term {
                coefficient: q(-1),
                factors: vec![0, 1],
            }],
        };
        let eval = |x: QM31, y: QM31| {
            let w = |a: QM31, b: QM31| (QM31::ONE - a) * (QM31::ONE - b) + a * b;
            let eq = q(3) * w(r[0], x) * w(r[1], y);
            let data = lerp(
                lerp(values[0], values[1], y),
                lerp(values[2], values[3], y),
                x,
            );
            let m = lerp(QM31::from_i64(-2), QM31::from_i64(case + 2), y);
            [eq, data + x * (QM31::ONE - x) * m]
        };
        let product = |x, y| {
            let p = eval(x, y);
            q(-1) * p[0] * p[1]
        };
        let mut state = cpu.gkr_start(&fields).expect("valid construction");
        assert!(Scalar::gkr_finals(&state).is_err());
        let first = Scalar::gkr_round(&mut state).expect("round 0");
        assert_eq!(
            first,
            (0..=4)
                .map(|k| product(QM31::from_i64(k), QM31::ZERO)
                    + product(QM31::from_i64(k), QM31::ONE))
                .collect::<Vec<_>>()
        );
        let x = q(case + 4);
        Scalar::gkr_fold(&mut state, x).expect("fold 0");
        assert_eq!(
            Scalar::gkr_round(&mut state).expect("round 1"),
            (0..=4)
                .map(|k| product(x, QM31::from_i64(k)))
                .collect::<Vec<_>>()
        );
        let y = q(-case - 1);
        Scalar::gkr_fold(&mut state, y).expect("fold 1");
        assert_eq!(Scalar::gkr_finals(&state).expect("finals"), eval(x, y));
    }
}

#[test]
fn rejects_understated_degree_and_invalid_factor_geometry() {
    let cpu = Scalar::<QM31>::new();
    let local = [q(7), q(-1)];
    let mask = |v| GkrMask {
        values: vec![M31::ONE, M31::ONE],
        coordinates: &[0],
        vanishing: v,
    };
    let mut input = GkrConstruction {
        num_vars: 1,
        layer_variables: 1,
        degree: 3,
        factors: vec![GkrFactor::Column {
            values: &local,
            coordinates: vec![0],
            mask: mask(0),
        }],
        terms: vec![Term {
            coefficient: QM31::ONE,
            factors: vec![0],
        }],
    };
    assert!(cpu.gkr_start(&input).is_ok());
    for degree in [0, 1, 2, 32] {
        input.degree = degree;
        assert!(cpu.gkr_start(&input).is_err());
    }
    input.degree = 3;
    input.factors[0] = GkrFactor::Column {
        values: &local,
        coordinates: vec![0],
        mask: mask(1),
    };
    assert!(cpu.gkr_start(&input).is_err());
    input.factors[0] = GkrFactor::Equality {
        point: &local[..1],
        scale: QM31::ONE,
        offset: 1,
    };
    assert!(cpu.gkr_start(&input).is_err());
    input.factors[0] = GkrFactor::Equality {
        point: &local[..1],
        scale: QM31::ONE,
        offset: 0,
    };
    input.terms[0].factors = vec![0, 0];
    input.degree = 1;
    assert!(cpu.gkr_start(&input).is_err());
    input.degree = 2;
    assert!(cpu.gkr_start(&input).is_ok());
}

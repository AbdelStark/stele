//! RFC-0014 A4. Compare the relation state to direct polynomial evaluation on the Boolean cube.
use stele_kernels::gkr::{
    GkrBackend, GkrMask, Projected, RelationBackend, RelationConstruction, Term,
};
use stele_kernels::{Field, Scalar, CM31, M31, QM31};

fn q(x: i64) -> QM31 {
    QM31(
        CM31(M31::from_i64(x), M31::ONE),
        CM31(M31::from_i64(3 * x), M31::from_i64(-x)),
    )
}
fn mix(a: QM31, b: QM31, t: QM31) -> QM31 {
    a + t * (b - a)
}

#[test]
fn matches_reference_projected_relation_rounds_and_finals() {
    let mut seed = 0x9d01_f3a5_197b_0143u64;
    let mut random = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        i64::from(seed as i32)
    };
    for case in 0..1000 {
        let values = [q(random()), q(random())];
        let publics = [q(random()), q(random())];
        let mask = [M31::from_i64(random()), M31::from_i64(random())];
        let v = case % 2;
        let axis = (case / 2) % 2;
        let inputs = RelationConstruction {
            num_vars: 2,
            degree: 7,
            factors: vec![
                Projected {
                    values: &values,
                    coordinates: vec![axis],
                    mask: Some(GkrMask {
                        values: mask.to_vec(),
                        coordinates: &[1],
                        vanishing: v,
                    }),
                },
                Projected {
                    values: &publics,
                    coordinates: vec![1 - axis],
                    mask: None,
                },
            ],
            terms: vec![Term {
                coefficient: QM31::ONE,
                factors: vec![0, 1, 0],
            }],
        };
        let expected = |x: QM31, y: QM31| {
            let point = [x, y];
            let m = mix(
                QM31::from_i64(mask[0].as_u32().into()),
                QM31::from_i64(mask[1].as_u32().into()),
                y,
            );
            [
                mix(values[0], values[1], point[axis]) + point[v] * (QM31::ONE - point[v]) * m,
                mix(publics[0], publics[1], point[1 - axis]),
            ]
        };
        let product = |x, y| {
            let [a, b] = expected(x, y);
            a * b * a
        };
        let session = Scalar::new();
        let mut state = session
            .relation_start(&inputs)
            .expect("valid projected relation");
        let nodes = (0..=7).map(QM31::from_i64);
        assert_eq!(
            Scalar::gkr_round(&mut state).expect("first round"),
            nodes
                .clone()
                .map(|x| product(x, QM31::ZERO) + product(x, QM31::ONE))
                .collect::<Vec<_>>()
        );
        let x = q(random());
        Scalar::gkr_fold(&mut state, x).expect("fold x");
        assert_eq!(
            Scalar::gkr_round(&mut state).expect("second round"),
            nodes.map(|y| product(x, y)).collect::<Vec<_>>()
        );
        let y = q(random());
        Scalar::gkr_fold(&mut state, y).expect("fold y");
        assert_eq!(
            Scalar::gkr_finals(&state).expect("final values"),
            expected(x, y)
        );
    }
    eprintln!("projected_relation_scalar_cases=1000");
}

#[test]
fn rejects_relation_geometry_degree_and_mask_extent() {
    let session = Scalar::new();
    let values = [q(3), q(-2)];
    let mut input = RelationConstruction {
        num_vars: 2,
        degree: 3,
        factors: vec![Projected {
            values: &values,
            coordinates: vec![0],
            mask: Some(GkrMask {
                values: vec![M31::ONE, M31::ONE],
                coordinates: &[1],
                vanishing: 1,
            }),
        }],
        terms: vec![Term {
            coefficient: QM31::ONE,
            factors: vec![0],
        }],
    };
    assert!(session.relation_start(&input).is_ok());
    input.degree = 2;
    assert!(session.relation_start(&input).is_err());
    input.degree = 3;
    input.terms[0].factors.push(1);
    assert!(session.relation_start(&input).is_err());
    input.terms[0].factors.pop();
    input.factors[0].coordinates[0] = 2;
    assert!(session.relation_start(&input).is_err());
    input.factors[0].coordinates[0] = 0;
    let mask = input.factors[0].mask.as_mut().expect("masked");
    mask.values.pop();
    assert!(session.relation_start(&input).is_err());
}

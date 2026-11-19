//! RFC-0014 A6. Check the selected top against explicitly expanded left and right branches.
use stele_kernels::lookup::{Column, Input, Key, Leg, LookupBackend, Member};
use stele_kernels::{Backend, Field, Scalar, SourceGeometry, M31, QM31 as K};

fn q(x: i64) -> K {
    K::from_i64(x)
}
fn merge(left: [K; 2], right: [K; 2]) -> [K; 2] {
    [left[0] * right[1] + right[0] * left[1], left[1] * right[1]]
}

#[test]
fn matches_reference_lookup_parents_and_rejects_wrong_original() {
    let dev = Scalar::<K>::new();
    let geom = SourceGeometry {
        id: 7,
        rows: 8,
        columns: 4,
    };
    for id in 0..1000 {
        let dev = if id == 0 { &dev } else { &Scalar::new() };
        let geom = SourceGeometry { id: 7 + id, ..geom };
        let mut physical = [M31::from_i64(-19); 32];
        for (i, x) in [1, 2, 3, 4, 2, 1, 0, 0].into_iter().enumerate() {
            physical[4 * (i / 2) + i % 2] = M31::from_i64(x);
        }
        let owner = dev.original(geom, &physical).expect("valid lookup fixture");
        let other = Scalar::new();
        let foreign = other
            .original(geom, &physical)
            .expect("valid lookup fixture");
        let multiplicity = Column {
            owner: 0,
            geometry: geom,
            offset: 4,
            len: 4,
        };
        let leg = Column {
            offset: 0,
            ..multiplicity
        };
        let coords = if id % 2 == 0 { [1, 0] } else { [0, 1] };
        let alpha = q(7 + id as i64);
        let beta = q(5 - id as i64);
        let table = vec![vec![0, 0], vec![1, 2], vec![3, 4], vec![9, 9]];
        let members = [Member {
            range: 0..4,
            selector: Some((&[1, 0], &[0])),
            tuple: vec![
                Leg {
                    column: leg,
                    coordinates: &coords,
                    shift: -1,
                },
                Leg {
                    column: leg,
                    coordinates: &[0, 1],
                    shift: 1,
                },
            ],
        }];
        let key = Key {
            id,
            variables: 2,
            top_variables: 1,
            beta,
            alpha,
        };
        let mut input = Input {
            key,
            multiplicity,
            members: &members,
            table: &table,
            valid: 3,
        };
        let parents: Vec<_> = (0..4)
            .map(|x| {
                let s = q(i64::from(x < 2));
                let j = if id % 2 == 0 { 2 * (x % 2) + x / 2 } else { x };
                let tuple = q(j as i64) + beta * q(2 + x as i64);
                let qt = if x < 3 {
                    alpha - q(table[x][0]) - beta * q(table[x][1])
                } else {
                    K::ONE
                };
                merge([s, alpha - s * tuple], [q(-[2, 1, 0, 0][x]), qt])
            })
            .collect();
        assert_eq!(
            dev.lookup_top(&input, &[&owner])
                .expect("valid lookup fixture"),
            vec![merge(parents[0], parents[1]), merge(parents[2], parents[3])]
        );
        assert!(dev.lookup_top(&input, &[&foreign]).is_err());
        input.multiplicity.offset += 1;
        assert!(dev.lookup_top(&input, &[&owner]).is_err());
    }
}

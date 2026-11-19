//! RFC-0014 A6. Compare original expanded leaves, all internal pairs and every child field round.
use crate::{packing::canonical, Cuda, Session};
use stele_kernels::{
    gkr::{GkrBackend, GkrConstruction, GkrFactor, GkrMask, Term},
    lookup::{Column, Input, Key, Leg, LookupBackend, Member, Visit},
    Backend, Field, Scalar, SourceGeometry, CM31, M31, QM31 as K,
};

fn join([a, b]: [K; 2], [c, d]: [K; 2]) -> [K; 2] {
    [a * d + c * b, b * d]
}
fn q(i: i64) -> K {
    K::from_i64(i)
}
fn reverse(x: usize, bits: usize) -> usize {
    x.reverse_bits() >> (usize::BITS as usize - bits)
}

fn compare(cuda: &Cuda, id: usize, seed: &mut u64) {
    let gpu = cuda.session();
    let foreign = cuda.session();
    let cpu = Scalar::<K>::new();
    let bits = 3 + id % 4;
    let n = 1 << bits;
    let top_bits = 1 + id % 2;
    let geom = SourceGeometry {
        id: 0,
        rows: n,
        columns: 16,
    };
    let other = SourceGeometry { id: 1, ..geom };
    let len = n / 2;
    let mut base = || {
        *seed ^= *seed << 13;
        *seed ^= *seed >> 7;
        *seed ^= *seed << 17;
        M31::from_u64(*seed)
    };
    let mut physical = vec![M31::from_i64(-927); geom.rows * geom.columns];
    let mut counts = physical.clone();
    let mut values = vec![];
    let mut mult = vec![];
    for x in 0..len {
        let val = base();
        let count = base();
        values.push(K::from_i64(val.as_u32().into()));
        mult.push(K::from_i64(count.as_u32().into()));
        // Deliberately cross physical rows and leave surrounding mask cells poisoned.
        let at = 3 + x;
        physical[at / 8 * 16 + at % 8] = val;
        counts[at / 8 * 16 + at % 8] = count;
    }
    let owner = gpu.original(geom, &physical).expect("original");
    let count_owner = gpu.original(other, &counts).expect("multiplicity");
    let wrong = foreign
        .original(geom, &physical)
        .expect("different session");
    let col = Column {
        owner: 0,
        geometry: geom,
        offset: 3,
        len,
    };
    let multiplicity = Column {
        owner: 1,
        geometry: other,
        ..col
    };
    let mut ext = || K(CM31(base(), base()), CM31(base(), base()));
    let key = Key {
        id: id as u64,
        variables: bits,
        top_variables: top_bits,
        beta: ext(),
        alpha: ext(),
    };
    let forward: Vec<_> = (1..bits).collect();
    let backward: Vec<_> = (1..bits).rev().collect();
    let selected_axes = [bits - 1];
    let member = |range: std::ops::Range<usize>, swap: bool| Member {
        range,
        selector: if swap {
            None
        } else {
            Some((&[0, 1][..], &selected_axes[..]))
        },
        tuple: vec![
            Leg {
                column: col,
                coordinates: if swap { &backward } else { &forward },
                shift: -3,
            },
            Leg {
                column: col,
                coordinates: if swap { &forward } else { &backward },
                shift: 8,
            },
        ],
    };
    let members = vec![member(0..len, false), member(len..len + len / 2, true)];
    let table: Vec<_> = (0..len)
        .map(|x| vec![x as i64 - 3, -4 * x as i64])
        .collect();
    let valid = len - 1;
    let mut input = Input {
        key,
        multiplicity,
        members: &members,
        table: &table,
        valid,
    };
    let owners = [&owner, &count_owner];
    if id == 0 {
        assert!(gpu.lookup_top(&input, &[&wrong, &count_owner]).is_err());
        assert!(gpu.lookup_top(&input, &[&count_owner, &owner]).is_err());
        input.valid = len + 1;
        assert!(gpu.lookup_top(&input, &owners).is_err());
        input.valid = valid;
        input.multiplicity.offset = geom.rows * geom.columns / 4 - len + 1;
        assert!(gpu.lookup_top(&input, &owners).is_err());
        input.multiplicity = multiplicity;
    }
    let mut leaves = Vec::new();
    for x in 0..n {
        let at = x % len;
        let reversed = reverse(at, bits - 1);
        let (selected, a, b) = if x < len {
            (q((x % 2) as i64), at, reversed)
        } else if x < len + len / 2 {
            (K::ONE, reversed, at)
        } else {
            (K::ZERO, 0, 0)
        };
        let tuple = values[a] - q(3) + key.beta * (values[b] + q(8));
        leaves.push([selected, key.alpha - selected * tuple]);
        let qt = if let Some(row) = table[..valid].get(x) {
            key.alpha - q(row[0]) - key.beta * q(row[1])
        } else {
            K::ONE
        };
        leaves.push([K::ZERO - mult.get(x).copied().unwrap_or(K::ZERO), qt]);
    }
    let mut layers = vec![leaves];
    for _ in 0..=bits {
        let parents = layers
            .last()
            .expect("children")
            .chunks_exact(2)
            .map(|p| join(p[0], p[1]))
            .collect();
        layers.push(parents);
    }
    layers.reverse();
    assert_eq!(
        gpu.lookup_top(&input, &owners).expect("top"),
        layers[top_bits]
    );
    let tree = gpu.lookup_tree(&input, &owners).expect("rebuild");
    let raw = cuda
        .complete_transfer(cuda.stream.clone_dtoh(&tree.pairs))
        .expect("qualification download");
    let actual: Vec<_> = raw
        .chunks_exact(8)
        .map(|p| {
            [
                canonical(p[..4].try_into().expect("four limbs")).expect("canonical"),
                canonical(p[4..].try_into().expect("four limbs")).expect("canonical"),
            ]
        })
        .collect();
    assert_eq!(actual, layers[..=bits].concat());
    let mut tree = Some(tree);
    for (level, layer) in layers.iter().enumerate().take(bits + 1).skip(top_bits + 1) {
        let axis = level - 1;
        let construction = |retained| {
            let mut factors = vec![];
            for component in 0..2 {
                for side in 0..2 {
                    let mask = GkrMask {
                        values: vec![M31::from_i64(3), M31::from_i64(-7)],
                        coordinates: &[0],
                        vanishing: 0,
                    };
                    factors.push(if retained {
                        GkrFactor::RetainedLayer {
                            layer: level,
                            component,
                            side,
                            mask,
                        }
                    } else {
                        GkrFactor::Layer {
                            values: layer,
                            component,
                            side,
                            mask,
                        }
                    });
                }
            }
            GkrConstruction {
                num_vars: axis as u32,
                layer_variables: axis,
                degree: 3,
                terms: (0..4)
                    .map(|i| Term {
                        coefficient: q(i as i64 + 3),
                        factors: vec![i],
                    })
                    .collect(),
                factors,
            }
        };
        let mut retained = construction(true);
        if id == 0 && level < bits {
            let current = tree.as_ref().expect("live tree");
            assert!(foreign
                .lookup_gkr(key, Visit::Borrow(current), &retained)
                .is_err());
            assert!(gpu
                .lookup_gkr(
                    Key {
                        id: key.id + 1,
                        ..key
                    },
                    Visit::Borrow(current),
                    &retained
                )
                .is_err());
            retained.factors.swap(0, 1);
            assert!(gpu
                .lookup_gkr(key, Visit::Borrow(current), &retained)
                .is_err());
            retained.factors.swap(0, 1);
        }
        let visit = if level == bits {
            Visit::Last(tree.take().expect("last child"))
        } else {
            Visit::Borrow(tree.as_ref().expect("live child"))
        };
        let mut actual = gpu
            .lookup_gkr(key, visit, &retained)
            .expect("actual children");
        let mut expected = cpu
            .gkr_start(&construction(false))
            .expect("independent child rows");
        for _ in 0..axis {
            assert_eq!(
                Session::gkr_round(&mut actual).expect("device round"),
                Scalar::<K>::gkr_round(&mut expected).expect("reference round")
            );
            let point = ext();
            Session::gkr_fold(&mut actual, point).expect("device fold");
            Scalar::<K>::gkr_fold(&mut expected, point).expect("reference fold");
        }
        assert_eq!(
            Session::gkr_finals(&actual).expect("device finals"),
            Scalar::<K>::gkr_finals(&expected).expect("reference finals")
        );
    }
    let counts = gpu.counts();
    assert_eq!(
        (
            counts.lookup_tops,
            counts.lookup_rebuilds,
            counts.lookup_child_views,
            counts.lookup_child_released
        ),
        (1, 1, 4 * (bits - top_bits), 1)
    );
}

#[test]
#[ignore = "requires a real CUDA device"]
fn matches_reference_cuda_lookup() {
    let cuda = Cuda::new().expect("required real CUDA device");
    for raw in [false, true] {
        crate::gkr_tests::RAW.set(raw);
        let mut seed = 0x1e6470002f5u64;
        for id in 0..1000 {
            compare(&cuda, id, &mut seed);
        }
    }
    crate::gkr_tests::RAW.set(false);
    println!("cuda_lookup_cases=1000 raw_cuda_lookup_cases=1000 complete_trees=2000 checked_child_views=24000 last_child_releases=2000");
}

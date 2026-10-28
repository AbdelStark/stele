//! RFC-0006 A7 — independent Boolean-table oracle; no source authentication.
use std::fmt::Debug;
use stele_field::{Field, CM31, M31, OM31, QM31};
use stele_gkr::public_mle::{Axis, Coefficient, Error, Kind};
fn next(s: &mut u64) -> u64 {
    *s ^= *s << 13;
    *s ^= *s >> 7;
    *s ^= *s << 17;
    *s
}
fn qm(s: &mut u64) -> QM31 {
    let mut limb = || M31::from_i64((next(s) % u64::from(M31::MODULUS)) as i64);
    QM31(CM31(limb(), limb()), CM31(limb(), limb()))
}
fn om(s: &mut u64) -> OM31 {
    OM31(qm(s), qm(s))
}
// Explicit integer predicates and eq products share no DP/vector helper with production.
fn oracle<K: Field>(axes: &[Axis], selectors: &[Option<&[K]>], kind: Kind<'_>, r: &[K]) -> K {
    let one = K::from_i64(1);
    let mut result = K::from_i64(0);
    for index in 0..1usize << r.len() {
        let mut coords = Vec::new();
        let mut shift = r.len();
        for axis in axes {
            shift -= usize::from(axis.bits);
            coords.push((index >> shift) as u64 & ((1u64 << axis.bits) - 1));
        }
        if axes.iter().zip(&coords).any(|(axis, x)| *x >= axis.real) {
            continue;
        }
        let value = match kind {
            Kind::Eq => 1,
            Kind::CausalMask { row, column } => i64::from(coords[column] <= coords[row]),
            Kind::WindowMask { row, column, width } => {
                i64::from(coords[column] <= coords[row] && coords[row] - coords[column] < width)
            }
            Kind::OnehotSparse {
                row,
                column,
                indices,
            } => i64::from(coords[column] == indices[coords[row] as usize]),
            Kind::GqaBroadcast { head, group } => {
                i64::from(coords[group] == coords[head] / (axes[head].real / axes[group].real))
            }
            Kind::RopeTables {
                axes: chosen,
                values,
            } => {
                let mut at = 0;
                for a in chosen {
                    at = at * axes[*a].real as usize + coords[*a] as usize;
                }
                values[at]
                    .to_i64_signed()
                    .expect("valid coefficient fixture")
            }
        };
        let mut term = K::from_i64(value);
        let mut at = 0;
        for (axis, selector) in axes.iter().zip(selectors) {
            for bit in 0..usize::from(axis.bits) {
                let is_one = index >> (r.len() - 1 - at) & 1 == 1;
                term = term * if is_one { r[at] } else { one - r[at] };
                if let Some(z) = selector {
                    term = term * if is_one { z[bit] } else { one - z[bit] };
                }
                at += 1;
            }
        }
        result = result + term;
    }
    result
}
fn agreement<K: Field + PartialEq + Debug>(random: fn(&mut u64) -> K) {
    let mut seed = 0x7192_6028_abcd_0667;
    for case in 0..10_000 {
        let bits = (next(&mut seed) % 3) as u8;
        let n = 1u64 << bits;
        let mut axes = [
            Axis {
                bits: 1,
                real: 1 + next(&mut seed) % 2,
            },
            Axis {
                bits,
                real: 1 + next(&mut seed) % n,
            },
            Axis {
                bits,
                real: 1 + next(&mut seed) % n,
            },
        ];
        let points: Vec<Vec<K>> = axes
            .iter()
            .map(|a| (0..a.bits).map(|_| random(&mut seed)).collect())
            .collect();
        let selectors: Vec<_> = points
            .iter()
            .map(|p| {
                if next(&mut seed) & 1 == 0 {
                    None
                } else {
                    Some(p.as_slice())
                }
            })
            .collect();
        let m = axes.iter().map(|a| usize::from(a.bits)).sum();
        let point: Vec<_> = (0..m)
            .map(|i| {
                if case % 7 == 0 {
                    K::from_i64((i % 2) as i64)
                } else {
                    random(&mut seed)
                }
            })
            .collect();
        let (row, column) = if case % 2 == 0 { (1, 2) } else { (2, 1) };
        let indices: Vec<_> = (0..axes[row].real)
            .map(|_| next(&mut seed) % axes[column].real)
            .collect();
        let values: Vec<_> = (0..axes[0].real * axes[2].real)
            .map(|_| M31::from_i64(next(&mut seed) as i64))
            .collect();
        let kinds = [
            Kind::Eq,
            Kind::CausalMask { row, column },
            Kind::WindowMask {
                row,
                column,
                width: 1 + next(&mut seed) % (n + 2),
            },
            Kind::OnehotSparse {
                row,
                column,
                indices: &indices,
            },
            Kind::RopeTables {
                axes: &[0, 2],
                values: &values,
            },
        ];
        for kind in kinds {
            let c =
                Coefficient::new(&axes, &selectors, kind, 100).expect("valid coefficient fixture");
            assert_eq!(
                c.evaluate(&point).expect("valid coefficient fixture"),
                oracle(&axes, &selectors, kind, &point),
                "case {case}, {kind:?}"
            );
        }
        axes[row].real = if bits == 2 && case % 3 == 0 { 3 } else { n };
        axes[column].real = if case % 3 == 0 { 1 } else { n };
        let kind = Kind::GqaBroadcast {
            head: row,
            group: column,
        };
        assert_eq!(
            Coefficient::new(&axes, &selectors, kind, 100)
                .expect("valid coefficient fixture")
                .evaluate(&point)
                .expect("valid coefficient fixture"),
            oracle(&axes, &selectors, kind, &point)
        );
    }
    // Unequal category width, zero-bit broadcast and a source on all axes.
    let axes = [
        Axis { bits: 1, real: 2 },
        Axis { bits: 3, real: 7 },
        Axis { bits: 0, real: 1 },
    ];
    let values: Vec<_> = (0..14).map(|x| M31::from_i64(x - 7)).collect();
    let z: Vec<_> = (0..4).map(|_| random(&mut seed)).collect();
    let selectors = [Some(&z[..1]), Some(&z[1..]), Some(&[][..])];
    let r: Vec<_> = (0..4).map(|_| random(&mut seed)).collect();
    for kind in [
        Kind::OnehotSparse {
            row: 0,
            column: 1,
            indices: &[6, 6],
        },
        Kind::RopeTables {
            axes: &[0, 1, 2],
            values: &values,
        },
    ] {
        assert_eq!(
            Coefficient::new(&axes, &selectors, kind, 11)
                .expect("source")
                .evaluate(&r)
                .expect("point"),
            oracle(&axes, &selectors, kind, &r)
        );
    }
}
#[test]
fn matches_reference_qm31_all_kinds() {
    agreement(qm);
}
#[test]
fn matches_reference_om31_all_kinds() {
    agreement(om);
}
#[test]
fn rejects_invalid_descriptors_and_resource_limits() {
    assert_eq!(
        Coefficient::<stele_field::KoalaBear>::new(
            &[Axis { bits: 0, real: 1 }],
            &[None],
            Kind::Eq,
            0
        )
        .err(),
        Some(Error::FieldMismatch)
    );
    let axes = [Axis { bits: 2, real: 3 }, Axis { bits: 2, real: 2 }];
    let selectors: [Option<&[QM31]>; 2] = [None, None];
    let check = |kind, error| {
        assert_eq!(
            Coefficient::new(&axes, &selectors, kind, 8).err(),
            Some(error)
        )
    };
    check(
        Kind::WindowMask {
            row: 0,
            column: 1,
            width: 0,
        },
        Error::Shape,
    );
    check(Kind::CausalMask { row: 0, column: 0 }, Error::Shape);
    check(Kind::CausalMask { row: 0, column: 2 }, Error::Shape);
    check(Kind::GqaBroadcast { head: 0, group: 1 }, Error::Shape);
    for indices in [&[0, 1][..], &[0, 1, 2]] {
        check(
            Kind::OnehotSparse {
                row: 0,
                column: 1,
                indices,
            },
            Error::Shape,
        );
    }
    for chosen in [&[][..], &[1, 0], &[0, 0], &[2], &[0, 1]] {
        check(
            Kind::RopeTables {
                axes: chosen,
                values: &[M31::ONE],
            },
            Error::Shape,
        );
    }
    for invalid in [
        vec![],
        vec![Axis { bits: 64, real: 1 }],
        vec![Axis { bits: 0, real: 0 }],
        vec![Axis { bits: 1, real: 3 }],
        vec![Axis { bits: 32, real: 1 }; 2],
        vec![Axis { bits: 0, real: 1 }; 65],
    ] {
        let absent = vec![None::<&[QM31]>; invalid.len()];
        assert_eq!(
            Coefficient::new(&invalid, &absent, Kind::Eq, 0).err(),
            Some(Error::Shape)
        );
    }
    assert_eq!(
        Coefficient::<QM31>::new(&axes, &[], Kind::Eq, 0).err(),
        Some(Error::Shape)
    );
    assert_eq!(
        Coefficient::new(&axes, &[Some(&[QM31::ONE][..]), None], Kind::Eq, 0).err(),
        Some(Error::Shape)
    );
    let kind = Kind::OnehotSparse {
        row: 0,
        column: 1,
        indices: &[0, 1, 0],
    };
    assert_eq!(
        Coefficient::new(&axes, &selectors, kind, 7).err(),
        Some(Error::Capacity)
    );
    assert_eq!(
        Coefficient::new(&axes, &selectors, kind, 8)
            .expect("valid coefficient fixture")
            .evaluate(&[]),
        Err(Error::PointDimension)
    );
    let unequal = [Axis { bits: 1, real: 1 }, Axis { bits: 2, real: 1 }];
    assert_eq!(
        Coefficient::new(
            &unequal,
            &selectors,
            Kind::CausalMask { row: 0, column: 1 },
            0
        )
        .err(),
        Some(Error::Shape)
    );
}
#[test]
fn accepts_large_masks_and_scalar_axes_without_domain_allocation() {
    let mut seed = 99;
    let axes = [Axis {
        bits: 31,
        real: 1 << 31,
    }; 2];
    let r: Vec<_> = (0..62).map(|_| om(&mut seed)).collect();
    let absent = [None, None];
    let forward = Coefficient::new(&axes, &absent, Kind::CausalMask { row: 0, column: 1 }, 0)
        .expect("valid coefficient fixture")
        .evaluate(&r)
        .expect("valid coefficient fixture");
    let reverse = Coefficient::new(&axes, &absent, Kind::CausalMask { row: 1, column: 0 }, 0)
        .expect("valid coefficient fixture")
        .evaluate(&r)
        .expect("valid coefficient fixture");
    let diagonal = r[..31].iter().zip(&r[31..]).fold(OM31::ONE, |v, (a, b)| {
        v * ((OM31::ONE - *a) * (OM31::ONE - *b) + *a * *b)
    });
    assert_eq!(forward + reverse, OM31::ONE + diagonal);
    for width in [1 << 31, u64::MAX] {
        assert_eq!(
            Coefficient::new(
                &axes,
                &absent,
                Kind::WindowMask {
                    row: 0,
                    column: 1,
                    width
                },
                0
            )
            .expect("valid coefficient fixture")
            .evaluate(&r)
            .expect("valid coefficient fixture"),
            forward
        );
    }
    for _ in 0..64 {
        let rows = 1 + next(&mut seed) % (1 << 31);
        let columns = 1 + next(&mut seed) % (1 << 31);
        let i = next(&mut seed) % (1 << 31);
        let j = next(&mut seed) % (1 << 31);
        let width = 1 + next(&mut seed) % (1 << 31);
        let axes = [
            Axis {
                bits: 31,
                real: rows,
            },
            Axis {
                bits: 31,
                real: columns,
            },
        ];
        let r: Vec<_> = [i, j]
            .iter()
            .flat_map(|v| {
                (0..31)
                    .rev()
                    .map(move |bit| OM31::from_i64((v >> bit & 1) as i64))
            })
            .collect();
        let expected = i < rows && j < columns && j <= i && i - j < width;
        assert_eq!(
            Coefficient::new(
                &axes,
                &absent,
                Kind::WindowMask {
                    row: 0,
                    column: 1,
                    width
                },
                0
            )
            .expect("large descriptor")
            .evaluate(&r)
            .expect("Boolean point"),
            OM31::from_i64(i64::from(expected))
        );
    }
    let axes = [Axis {
        bits: 63,
        real: 1 << 63,
    }];
    assert_eq!(
        Coefficient::new(&axes, &[None], Kind::Eq, 0)
            .expect("valid coefficient fixture")
            .evaluate(&[QM31::from_i64(2); 63])
            .expect("valid coefficient fixture"),
        QM31::ONE
    );
    let axes = [Axis { bits: 0, real: 1 }; 64];
    assert_eq!(
        Coefficient::<QM31>::new(&axes, &[Some(&[][..]); 64], Kind::Eq, 0)
            .expect("valid coefficient fixture")
            .evaluate(&[])
            .expect("valid coefficient fixture"),
        QM31::ONE
    );
}

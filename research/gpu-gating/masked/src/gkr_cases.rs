//! RFC-0008 A7 / RFC-0014 §5: genuine seeded GKR steps, including unused compact slots.
use crate::{cpu, gkr, lookup_cases::fixture, K};
use stele_reductions::stele_hash::Transcript;
use stele_reductions::zk::claims::{self, bench, bench::GkrCase, Geometry, Lifetime, ModelSecret};
use stele_reductions::zk::{Error, Seed};

pub(crate) const CASES: usize = 1000;
pub(crate) const SEED: u64 = 0x40_3000_0001;

pub(crate) fn observe(
    case: usize,
    mut check: impl FnMut(&GkrCase<'_, K>) -> Result<(), Error>,
) -> [usize; 4] {
    let seed = SEED + 2 * case as u64;
    let (statement, columns, _, _) = fixture(seed);
    let mut proof_seed = [0x6d; 32];
    proof_seed[..8].copy_from_slice(&seed.to_le_bytes());
    let mut model_seed = proof_seed;
    model_seed[31] ^= 1;
    let balanced = case.is_multiple_of(2);
    let life = Lifetime {
        geometry: if balanced {
            Geometry::Balanced
        } else {
            Geometry::Narrow
        },
        source: 0,
        proofs: 1,
        index: 0,
        blocks: claims::occurrence_counts(&statement).unwrap(),
    };
    let root = claims::lifetime_root(&statement, &columns, &life, &model_seed).unwrap();
    let model = ModelSecret {
        seed: &model_seed,
        revealed: vec![],
        root,
    };
    let transcript = || Transcript::<K>::new(b"E16-40m genuine GKR").unwrap();
    let mut seen = [0; 4];
    let observed = bench::observe_gkr(
        &statement,
        &columns,
        Seed::new(proof_seed),
        &mut transcript(),
        Some((&life, model)),
        &mut |step| {
            assert_eq!(step.step, seen[..3].iter().sum::<usize>());
            seen[if step.leaf {
                2
            } else if step.first {
                0
            } else {
                1
            }] += 1;
            seen[3] += usize::from(step.reference()?.is_compact());
            check(step)
        },
    )
    .expect("complete observed CPU proof");
    assert!(!observed.0.gkr.is_empty());
    assert_eq!(seen[..3].iter().sum::<usize>(), observed.0.gkr.len());
    claims::verify_lifetime(&statement, Some(&life), &observed.0, &mut transcript())
        .expect("ordinary observed CPU proof verifies");
    assert!(observed.1.is_some());
    seen
}

#[test]
fn matches_reference_genuine_gkr_shapes_and_finals() {
    let mut totals = [0; 4];
    let mut unused_control = false;
    for case in 0..CASES {
        let seen = observe(case, |step| {
            let mut reference = step.reference()?;
            let shape = gkr::shape(&reference).expect("unfolded production shape");
            assert_eq!(shape.n, step.point.len());
            let storage: Vec<_> = shape
                .factors
                .iter()
                .map(|f| {
                    let (r, v) = f.mask.as_ref().map_or((0, shape.n), |(r, v)| {
                        (if r.is_base() { 4 } else { 16 }, *v)
                    });
                    [if f.x.is_base() { 4 } else { 16 }, r, v]
                })
                .collect();
            let arities: Vec<_> = shape.terms.iter().map(|(_, t)| t.len()).collect();
            eprintln!("gkr_shape case={case} step={} variables={} degree={} factors={storage:?} terms={arities:?}", step.step, shape.n, shape.degree);
            let mut candidate = cpu(&shape);
            let tables = |s: &bench::Masked<K>| {
                s.tables()
                    .map(|(x, r)| (x.to_vec(), r.to_vec()))
                    .collect::<Vec<_>>()
            };
            assert_eq!(tables(&candidate), tables(&reference));
            for point in step.point {
                assert_eq!(candidate.round().unwrap(), reference.round().unwrap());
                candidate.fold(*point).unwrap();
                reference.fold(*point).unwrap();
                assert_eq!(tables(&candidate), tables(&reference));
            }
            let expected: Vec<_> = reference.tables().map(|(x, _)| x[0]).collect();
            let actual: Vec<_> = candidate.tables().map(|(x, _)| x[0]).collect();
            gkr::check_finals(step, &expected, &actual)
                .expect("all compact/expanded/routed finals");
            assert_eq!(reference.final_values().unwrap(), step.finals);
            if reference.is_compact() && !unused_control {
                for index in 0..actual.len() {
                    let mut changed = actual.clone();
                    changed[index] = changed[index] + K::ONE;
                    assert_eq!(
                        gkr::check_finals(step, &expected, &changed),
                        Err("compact finals")
                    );
                    if step.reference()?.expand_at(step.point, &changed).unwrap() == step.finals {
                        unused_control = true;
                    }
                }
            }
            Ok(())
        });
        for (total, n) in totals.iter_mut().zip(seen) {
            *total += n;
        }
    }
    assert!(totals.iter().all(|n| *n > 0));
    assert!(
        unused_control,
        "a changed ignored compact slot must be rejected"
    );
    eprintln!(
        "gkr_host_statements={CASES} first={} interior={} leaf={} compact={} seed={SEED}",
        totals[0], totals[1], totals[2], totals[3]
    );
}

#[test]
fn accepts_base_and_extension_factor_storage() {
    let reference = bench::Masked::new(
        vec![
            bench::Table {
                x: vec![K::ZERO; 4],
                r: vec![],
                v: None,
            },
            bench::Table {
                x: vec![crate::challenge(0); 4],
                r: vec![K::ONE; 4],
                v: Some(0),
            },
        ],
        vec![(K::ONE, vec![0, 1, 0])],
        5,
    );
    let s = gkr::shape(&reference).unwrap();
    assert_eq!((s.n, s.degree), (2, 5));
    assert!(s.factors[0].x.is_base());
    assert!(!s.factors[1].x.is_base());
    assert!(s.factors[1].mask.as_ref().unwrap().0.is_base());
    assert_eq!(s.terms, [(K::ONE, vec![0, 1, 0])]);
}

#[test]
fn rejects_malformed_or_folded_factor_tables() {
    for change in 0..8 {
        let mut table = bench::Table {
            x: vec![K::ONE; 4],
            r: vec![K::ONE; 4],
            v: Some(0),
        };
        let mut degree = 3;
        let mut terms = vec![(K::ZERO, vec![0])];
        match change {
            0 => table.x.clear(),
            1 => {
                table.x.pop();
            }
            2 => {
                table.r.pop();
            }
            3 => table.v = None,
            4 => table.v = Some(2),
            5 => table.r.clear(),
            6 => degree = 32,
            7 => terms[0].1 = vec![1],
            _ => unreachable!(),
        }
        assert!(
            gkr::shape(&bench::Masked::new(vec![table], terms, degree)).is_err(),
            "change {change}"
        );
    }
    let mut folded = bench::Masked::new(
        vec![bench::Table {
            x: vec![K::ONE; 4],
            r: vec![],
            v: None,
        }],
        vec![(K::ONE, vec![0])],
        1,
    );
    folded.fold(crate::challenge(0)).unwrap();
    assert!(gkr::shape(&folded).is_err());
}

#[test]
fn matches_reference_last_child_to_the_production_schedule() {
    use stele_reductions::zk::claims::bench::{GkrFactor, LookupCase};
    let mut single = 0;
    let mut transfers = 0;
    for case in 0..24 {
        let (statement, columns, beta, alpha) = fixture(SEED + 2 * case as u64);
        let lookup = LookupCase::new(&statement, &columns, 0).unwrap();
        let leaves = lookup
            .reference(beta, alpha)
            .unwrap()
            .layers
            .last()
            .unwrap()
            .len();
        let mut steps = Vec::new();
        observe(case, |step| {
            let input = step.construction()?;
            let widths: Vec<_> = input
                .factors
                .iter()
                .filter_map(|f| match f {
                    GkrFactor::Layer { values, .. } => Some(values.len()),
                    _ => None,
                })
                .collect();
            steps.push((step.first, step.leaf, input.layer_variables, widths));
            Ok(())
        });
        for (i, (first, leaf, vars, widths)) in steps.iter().enumerate() {
            if *leaf {
                assert!(widths.is_empty());
                assert_eq!(i + 1, steps.len());
                single += usize::from(*first);
            } else {
                let next_leaf = steps[i + 1].1;
                assert_eq!(next_leaf, leaves.ilog2() as usize == vars + 2);
                assert_eq!(widths.as_slice(), [2usize << vars; 4]);
                assert_eq!(next_leaf, widths[0] * 2 == leaves);
                transfers += usize::from(next_leaf);
            }
        }
    }
    assert!(single > 0 && transfers > 0);
}

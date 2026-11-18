//! RFC-0014 §5. The disposable installer exposes the actual lookup plan's original
//! member coordinates. Both paths compare with its independently materialized CPU tree.
use super::*;
use crate::lookup::{words, Error as LookupError};
use crate::lookup_cases::{fixture, lazy, CASES, SEED};
use crate::{Field, M31};
use stele_reductions::zk::claims::bench::LookupCase;

fn lift(p: &mut Packed) {
    lazy(&mut p.fields);
    for member in p.descriptors.chunks_exact_mut(5 + 4 * p.width as usize) {
        for col in member[5..].chunks_exact_mut(4) {
            col[3] += M31::MODULUS;
        }
    }
}

#[test]
fn matches_reference_compact_leaf_expressions() {
    let mut input = Vec::new();
    let mut reference = Vec::new();
    let mut edges = [false; 3];
    for index in 0..CASES {
        let (s, columns, beta, alpha) = fixture(SEED + 2 * index as u64);
        let case = LookupCase::new(&s, &columns, 0).unwrap();
        let parts = case.compact_parts(&columns).unwrap();
        let data = Input::from_parts(&parts, beta, alpha);
        let expected = case.reference(beta, alpha).unwrap();
        for raw in [false, true] {
            let mut p = Packed::new(&data).unwrap();
            if raw {
                for (present, edge) in edges.iter_mut().zip([0, 1, M31::MODULUS - 1]) {
                    *present |= p.fields.contains(&edge);
                }
                lift(&mut p)
            }
            input.extend([
                p.n as u32,
                p.width,
                p.members,
                p.valid,
                p.mults,
                p.fields.len() as u32,
                p.descriptors.len() as u32,
                p.shifts.len() as u32,
            ]);
            input.extend(p.fields);
            input.extend(p.descriptors);
            input.extend(p.shifts);
            reference.extend(
                expected
                    .layers
                    .last()
                    .unwrap()
                    .iter()
                    .flatten()
                    .flat_map(|v| words(*v)),
            );
        }
    }
    assert!(
        edges.into_iter().all(|seen| seen),
        "missing canonical field edge"
    );
    let program=format!("#include <cstdio>\n#include <vector>\n#define __device__\n#define __global__\n#define __forceinline__ inline\n{}\n#define GRID_STRIDE(i,n) for(u64 i=0;i<(n);++i)\n{}\n{}",crate::host_probe::helpers(),include_str!("lookup_compact.cu"),include_str!("lookup_compact_host.cuh"));
    let actual = crate::host_probe::run(&program, &input);
    assert_eq!(actual.len(), reference.len());
    assert!(
        actual == reference,
        "actual compact kernel differs from original CPU leaf"
    );
}

#[test]
#[ignore = "requires an allocated H100 with CUDA and NVRTC"]
fn matches_reference_compact_lookups_on_h100() {
    let dev = Device::new().expect("required CUDA device");
    assert!(dev.name.contains("H100"));
    let mut complete = 0;
    for index in 0..CASES {
        let (s, columns, beta, alpha) = fixture(SEED + 2 * index as u64);
        let case = LookupCase::new(&s, &columns, 0).unwrap();
        let parts = case.compact_parts(&columns).unwrap();
        let data = Input::from_parts(&parts, beta, alpha);
        let expected = case.reference(beta, alpha).unwrap();
        for raw in [false, true] {
            let normalize = |p: &mut Packed| {
                if raw {
                    lift(p)
                }
            };
            let (tree, _, count, t) = build(&dev, &data, true, normalize).unwrap();
            let (top, t) = select::finish_top(&dev, count, tree, t).unwrap();
            assert_eq!(top, expected.top);
            assert_eq!(t.download_bytes, 52 * count);
            let (tree, leaves, _, t) = build(&dev, &data, false, normalize).unwrap();
            assert_eq!(t.download_bytes, 0);
            let resident = select::finish_resident(&dev, index, leaves, tree);
            assert_eq!(
                resident.compare_all(&expected.layers).unwrap(),
                resident.bytes()
            );
            complete += 1;
        }
        // One changed original multiplicity must change the root. The same
        // read-only production checker defines every expected layer of the near miss.
        let mut changed = columns.clone();
        let m = s.lookups[0].multiplicity;
        changed[m][0] = changed[m][0] + M31::ONE;
        let near = LookupCase::new(&s, &changed, 0).unwrap();
        let parts = near.compact_parts(&changed).unwrap();
        let data = Input::from_parts(&parts, beta, alpha);
        let altered = near.reference(beta, alpha).unwrap();
        let (resident, _) = resident(&dev, index, &data).unwrap();
        resident.compare_all(&altered.layers).unwrap();
        assert!(matches!(
            resident.compare_all(&expected.layers),
            Err(Error::Value)
        ));
    }
    let (s, columns, _, _) = fixture(SEED);
    let case = LookupCase::new(&s, &columns, 0).unwrap();
    let parts = case.compact_parts(&columns).unwrap();
    let data = Input::from_parts(&parts, K::ZERO, K::ZERO);
    assert!(matches!(
        top(&dev, &data),
        Err(Error::Lookup(LookupError::DenominatorZero))
    ));
    assert_eq!(complete, 2 * CASES);
    eprintln!("compact_lookup_cases={CASES} raw_leaf_cases={CASES} raw_top_cases={CASES} complete_trees={complete} near_miss_cases={CASES} zero_denominator_cases=1 seed={SEED} device={}",dev.name);
}

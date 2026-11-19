//! RFC-0014 §5. Original masking quadrants, member IDs and full CPU tree as oracle.
use super::*;
use crate::{
    lookup_cases::{fixture, CASES, SEED},
    Field, M31,
};
use stele_reductions::zk::claims::bench::LookupCase;

#[test]
#[ignore = "requires an allocated H100 and CUDA"]
fn matches_reference_original_column_lookups_on_h100() {
    let dev = Device::new().expect("CUDA device");
    assert!(dev.name.contains("H100"));
    let mut trees = 0;
    for index in 0..CASES {
        let seed = SEED + 2 * index as u64;
        let (s, columns, beta, alpha) = fixture(seed);
        let case = LookupCase::new(&s, &columns, 0).unwrap();
        let parts = case.compact_parts(&columns).unwrap();
        let input = Input::from_parts(&parts, beta, alpha);
        let reference = case.reference(beta, alpha).unwrap();
        let (legs, messages) =
            LookupCase::original_lookup_inputs(&s, &columns, 0, [index as u8; 32]).unwrap();
        let mut owners = BTreeMap::new();
        for (id, (rows, cols, message)) in messages.iter().enumerate() {
            owners.insert(
                id as u64,
                OriginalMessage::upload(&dev, id as u64, *rows, *cols, message).unwrap(),
            );
        }
        for raw in [false, true] {
            if raw {
                for owner in owners.values_mut() {
                    owner.lift_original_test_words().unwrap();
                }
            }
            let views = OriginalViews {
                columns: &legs,
                owners: &owners,
            };
            let stage = |p: &mut Packed| {
                if raw {
                    for w in &mut p.fields {
                        *w += M31::MODULUS;
                    }
                    for d in p.descriptors.chunks_exact_mut(5 + 4 * p.width as usize) {
                        for r in d[5..].chunks_exact_mut(4) {
                            r[3] += M31::MODULUS;
                        }
                    }
                }
            };
            let (tree, _, count, t) = build_with(&dev, &input, true, Some(views), stage).unwrap();
            let (top, _) = select::finish_top(&dev, count, tree, t).unwrap();
            assert_eq!(top, reference.top);
            let (tree, leaves, _, _) = build_with(&dev, &input, false, Some(views), stage).unwrap();
            let resident = select::finish_resident(&dev, index, leaves, tree);
            assert_eq!(
                resident.compare_all(&reference.layers).unwrap(),
                resident.bytes()
            );
            trees += 1;
        }
        if index == 0 {
            let mut shifted = legs.clone();
            shifted[0][4] = usize::MAX;
            assert!(top_original(
                &dev,
                &input,
                OriginalViews {
                    columns: &shifted,
                    owners: &owners
                }
            )
            .is_err());
            let mut wrong = legs.clone();
            wrong[0][1] = usize::MAX;
            assert!(top_original(
                &dev,
                &input,
                OriginalViews {
                    columns: &wrong,
                    owners: &owners
                }
            )
            .is_err());
            // Keep dimensions and the actual claim/reduction fixed. One wrong original
            // multiplicity must disagree with the independently generated CPU tree.
            let mut message = messages[legs[0][1]].2.clone();
            let at = legs[0][4];
            let cols = legs[0][3];
            let width = cols / 2;
            let pos = (at / width) * cols + at % width;
            message[pos] = message[pos] + M31::ONE;
            let id = legs[0][1] as u64;
            owners.insert(
                id,
                OriginalMessage::upload(&dev, id, legs[0][2], cols, &message).unwrap(),
            );
            let (tree, leaves, _, _) = build_with(
                &dev,
                &input,
                false,
                Some(OriginalViews {
                    columns: &legs,
                    owners: &owners,
                }),
                |_| {},
            )
            .unwrap();
            assert!(select::finish_resident(&dev, index, leaves, tree)
                .compare_all(&reference.layers)
                .is_err());
        }
    }
    eprintln!(
        "original_lookup_cases={CASES} raw_original_cases={CASES} full_trees={trees} controls=3"
    );
}

//! RFC-0012 A3: canonical roots/paths and adversarial authentication boundaries.
use serde_json::Value;
use stele_hash::merkle::{verify, verify_batch, Descriptor, Error, Kind, Opening, Tree};
use stele_hash::{merkle, HashUsage};

fn bytes(v: &Value) -> Vec<u8> {
    let s = v.as_str().expect("valid fixture");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid fixture"))
        .collect()
}
fn build(spec: Descriptor, leaves: &[impl AsRef<[u8]>]) -> Result<Tree, Error> {
    Tree::new(spec, &leaves.iter().map(AsRef::as_ref).collect::<Vec<_>>())
}
fn descriptor(kind: Kind, count: u64, width: u64) -> Descriptor {
    Descriptor {
        kind,
        id: 17,
        count,
        width,
    }
}
#[test]
fn matches_reference_roots_paths_and_rejections() {
    let mut cases = 0;
    for line in include_str!("fixtures/merkle.jsonl").lines() {
        let v: Value = serde_json::from_str(line).expect("valid fixture");
        let d = &v["tree"];
        let kind = d["kind"].as_u64().expect("fixture kind");
        assert!(matches!(kind, 0 | 2));
        let spec = Descriptor {
            kind: if kind == 0 {
                Kind::Columns
            } else {
                Kind::Roots
            },
            id: d["id"].as_u64().expect("valid fixture"),
            count: d["count"].as_u64().expect("valid fixture"),
            width: d["width"].as_u64().expect("valid fixture"),
        };
        let leaves: Vec<_> = v["leaves"]
            .as_array()
            .expect("valid fixture")
            .iter()
            .map(bytes)
            .collect();
        let mut usage = HashUsage::default();
        let tree = Tree::new_with_usage(
            spec,
            &leaves.iter().map(Vec::as_slice).collect::<Vec<_>>(),
            &mut usage,
        )
        .expect("valid fixture");
        assert_eq!(
            usage.hash_evaluations,
            2 * spec.count.next_power_of_two() - 1
        );
        let root: [u8; 32] = bytes(&v["root"]).try_into().expect("valid fixture");
        assert_eq!(tree.root(), root);
        let paths: Vec<Vec<[u8; 32]>> = v["paths"]
            .as_array()
            .expect("valid fixture")
            .iter()
            .map(|p| {
                p.as_array()
                    .expect("valid fixture")
                    .iter()
                    .map(|s| bytes(s).try_into().expect("valid fixture"))
                    .collect()
            })
            .collect();
        let indices: Vec<_> = (0..spec.count).collect();
        let openings: Vec<_> = leaves
            .iter()
            .zip(&paths)
            .map(|(payload, siblings)| Opening { payload, siblings })
            .collect();
        assert_eq!(verify_batch(spec, &root, &indices, &openings), Ok(()));
        for (i, opening) in openings.iter().enumerate() {
            let index = i as u64;
            assert_eq!(tree.path(index).expect("valid fixture"), paths[i]);
            assert_eq!(verify(spec, &root, index, *opening), Ok(()));
            let mut wrong = leaves[i].clone();
            wrong[0] ^= 1;
            assert_eq!(
                verify(
                    spec,
                    &root,
                    index,
                    Opening {
                        payload: &wrong,
                        ..*opening
                    }
                ),
                Err(Error::RootMismatch)
            );
            let mut bad_root = root;
            bad_root[0] ^= 1;
            assert_eq!(
                verify(spec, &bad_root, index, *opening),
                Err(Error::RootMismatch)
            );
            assert_eq!(
                verify(Descriptor { id: 18, ..spec }, &root, index, *opening),
                Err(Error::RootMismatch)
            );
            for at in 0..paths[i].len() {
                let mut wrong = paths[i].clone();
                wrong[at][0] ^= 1;
                assert_eq!(
                    verify(
                        spec,
                        &root,
                        index,
                        Opening {
                            siblings: &wrong,
                            ..*opening
                        }
                    ),
                    Err(Error::RootMismatch)
                );
            }
            if spec.count > 1 {
                assert_eq!(
                    verify(spec, &root, (index + 1) % spec.count, *opening),
                    Err(Error::RootMismatch)
                );
                assert_eq!(
                    verify(
                        spec,
                        &root,
                        index,
                        Opening {
                            siblings: &paths[i][1..],
                            ..*opening
                        }
                    ),
                    Err(Error::InvalidPath)
                );
            }
            let mut extra = paths[i].clone();
            extra.push([0; 32]);
            assert_eq!(
                verify(
                    spec,
                    &root,
                    index,
                    Opening {
                        siblings: &extra,
                        ..*opening
                    }
                ),
                Err(Error::InvalidPath)
            );
            assert_eq!(
                verify(
                    spec,
                    &root,
                    index,
                    Opening {
                        payload: &leaves[i][1..],
                        ..*opening
                    }
                ),
                Err(Error::InvalidLeaf)
            );
        }
        assert_eq!(tree.path(spec.count), Err(Error::InvalidIndex));
        assert_eq!(
            verify(spec, &root, spec.count, openings[0]),
            Err(Error::InvalidIndex)
        );
        assert_eq!(
            verify_batch(spec, &root, &[], &[]),
            Err(Error::InvalidBatch)
        );
        assert_eq!(
            verify_batch(spec, &root, &indices, &openings[1..]),
            Err(Error::InvalidBatch)
        );
        assert_eq!(
            verify_batch(spec, &root, &[0, 0], &[openings[0]; 2]),
            Err(Error::InvalidBatch)
        );
        if spec.count > 1 {
            assert_eq!(
                verify_batch(spec, &root, &[1, 0], &[openings[1], openings[0]]),
                Err(Error::InvalidBatch)
            );
            let mut changed = openings.clone();
            changed[1] = openings[0];
            assert_eq!(
                verify_batch(spec, &root, &indices, &changed),
                Err(Error::RootMismatch)
            );
        }
        cases += 1;
    }
    assert_eq!(cases, 10);
}

#[test]
fn rejects_merkle_failures_with_usage() {
    let spec = descriptor(Kind::Columns, 3, 1);
    let tree = build(spec, &[[3], [5], [7]]).expect("tree");
    let path = tree.path(0).expect("path");
    let opening = Opening {
        payload: &[3],
        siblings: &path,
    };
    let mut usage = HashUsage::default();
    assert_eq!(
        merkle::verify_with_usage(spec, &tree.root(), 0, opening, &mut usage),
        Ok(())
    );
    assert_eq!(usage.hash_evaluations, 3);
    // Every invocation counts; equal queries are not deduplicated or cached.
    assert_eq!(
        merkle::verify_with_usage(spec, &tree.root(), 0, opening, &mut usage),
        Ok(())
    );
    assert_eq!(usage.hash_evaluations, 6);
    let before = usage;
    assert_eq!(
        merkle::verify_with_usage(spec, &tree.root(), 3, opening, &mut usage),
        Err(Error::InvalidIndex)
    );
    assert!(matches!(
        Tree::new_with_usage(spec, &[], &mut usage),
        Err(Error::InvalidLeaf)
    ));
    assert_eq!(usage, before);
    assert_eq!(
        merkle::verify_with_usage(spec, &[0; 32], 0, opening, &mut usage),
        Err(Error::RootMismatch)
    );
    assert_eq!(usage.hash_evaluations, 9);
    let next_path = tree.path(1).expect("path");
    let wrong = Opening {
        payload: &[6],
        siblings: &next_path,
    };
    assert_eq!(
        merkle::verify_batch_with_usage(spec, &tree.root(), &[0, 1], &[opening, wrong], &mut usage),
        Err(Error::RootMismatch)
    );
    assert_eq!(usage.hash_evaluations, 15);
    let before = usage;
    assert_eq!(
        merkle::verify_batch_with_usage(spec, &tree.root(), &[0, 0], &[opening; 2], &mut usage),
        Err(Error::InvalidBatch)
    );
    assert_eq!(usage, before);
    assert_eq!(
        usage,
        HashUsage {
            hash_evaluations: 15,
            ..HashUsage::default()
        }
    );
}
#[test]
fn rejects_descriptor_aliasing_and_invalid_shapes() {
    let spec = descriptor(Kind::Columns, 3, 32);
    let leaves = [[0; 32]; 3];
    let tree = build(spec, &leaves).expect("valid fixture");
    let path = tree.path(0).expect("valid fixture");
    let opening = Opening {
        payload: &leaves[0],
        siblings: &path,
    };
    for changed in [
        Descriptor {
            kind: Kind::Roots,
            ..spec
        },
        Descriptor { count: 4, ..spec },
    ] {
        assert_eq!(
            verify(changed, &tree.root(), 0, opening),
            Err(Error::RootMismatch)
        );
    }
    assert_eq!(
        verify(spec, &tree.root(), 1, opening),
        Err(Error::RootMismatch)
    );
    assert_ne!(
        tree.root(),
        build(Descriptor { count: 4, ..spec }, &[[0; 32]; 4])
            .expect("valid fixture")
            .root()
    );
    for changed in [
        Descriptor { count: 0, ..spec },
        Descriptor {
            count: (1 << 63) + 1,
            ..spec
        },
        Descriptor { width: 0, ..spec },
        descriptor(Kind::Roots, 3, 31),
    ] {
        assert_eq!(
            verify(changed, &tree.root(), 0, opening),
            Err(Error::InvalidTree)
        );
        assert!(matches!(build(changed, &leaves), Err(Error::InvalidTree)));
    }
    assert!(matches!(build(spec, &leaves[..2]), Err(Error::InvalidLeaf)));
    assert!(matches!(
        build(Descriptor { width: 31, ..spec }, &leaves),
        Err(Error::InvalidLeaf)
    ));
    let huge = descriptor(Kind::Columns, 1 << 63, 1);
    assert_eq!(
        verify(huge, &[0; 32], u64::MAX, opening),
        Err(Error::InvalidIndex)
    );
    assert_eq!(
        verify(
            huge,
            &[0; 32],
            0,
            Opening {
                payload: &[0],
                siblings: &[[0; 32]; 63]
            }
        ),
        Err(Error::RootMismatch)
    );
}
#[test]
fn accepts_authenticated_child_root_and_rejects_wrong_child() {
    let child_spec = descriptor(Kind::Columns, 2, 1);
    let child = build(child_spec, &[[3], [5]]).expect("valid fixture");
    let other = build(child_spec, &[[7], [11]]).expect("valid fixture");
    let parent_spec = descriptor(Kind::Roots, 2, 32);
    let parent = build(parent_spec, &[child.root(), other.root()]).expect("valid fixture");
    let root = child.root();
    assert_eq!(
        verify(
            parent_spec,
            &parent.root(),
            0,
            Opening {
                payload: &root,
                siblings: &parent.path(0).expect("valid fixture")
            }
        ),
        Ok(())
    );
    let path = child.path(1).expect("valid fixture");
    let opening = Opening {
        payload: &[5],
        siblings: &path,
    };
    assert_eq!(verify(child_spec, &root, 1, opening), Ok(()));
    assert_eq!(
        verify(child_spec, &other.root(), 1, opening),
        Err(Error::RootMismatch)
    );
}

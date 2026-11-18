//! RFC-0014 §5: explicit required-H100 tree/top qualification, never a skip.
use super::*;
use crate::lookup::{words, Error as LookupError};
use crate::lookup_cases::{fixture, inverse_inputs, lazy, verify_inverses, CASES, SEED};
use crate::{Field, M31};
use stele_reductions::zk::claims::bench::LookupCase;

fn device() -> Device {
    assert!(
        crate::gpu::available(),
        "required CUDA driver and NVRTC absent"
    );
    let dev = Device::new().expect("CUDA device");
    assert!(dev.name.contains("H100"), "H100 required: {}", dev.name);
    dev
}

#[test]
#[ignore = "requires an explicitly allocated H100 and CUDA/NVRTC"]
fn matches_reference_lookup_trees_on_h100() {
    let dev = device();
    for case in 0..CASES {
        let (s, data, beta, alpha) = fixture(SEED + 2 * case as u64);
        let c = LookupCase::new(&s, &data, 0).unwrap();
        let expected = c.reference(beta, alpha).unwrap();
        let input = c.inputs(beta, alpha);
        let (actual, timing) = prepare(&dev, &input).expect("complete GPU tree/top");
        assert_eq!(actual.layers, expected.layers, "all layers case {case}");
        assert_eq!(actual.top, expected.top, "all top columns case {case}");
        let mut p = Prepared::new(&input).unwrap();
        assert_eq!(timing.upload_bytes, 4 * (p.values.len() + p.selector.len()));
        assert_eq!(
            timing.buffer_peak_bytes,
            timing.upload_bytes + timing.download_bytes
        );
        let expected_words: Vec<u32> = expected
            .layers
            .iter()
            .flatten()
            .flatten()
            .flat_map(|v| words(*v))
            .collect();
        let mut raw_tree = expected_words.clone();
        lazy(&mut raw_tree);
        lazy(&mut p.values);
        lazy(&mut p.selector);
        let values = dev.stream().clone_htod(&p.values).unwrap();
        let selector = dev.stream().clone_htod(&p.selector).unwrap();
        let mut tree = Tree::new(&dev, &p).unwrap();
        tree.leaf(&values, &selector, &p).unwrap();
        let leaf = dev.stream().clone_dtoh(&tree.pairs).unwrap();
        assert_eq!(
            &leaf[8 * (p.leaves - 1)..],
            &expected_words[8 * (p.leaves - 1)..],
            "raw leaf {case}"
        );
        let mut count = p.leaves / 2;
        while count > 0 {
            dev.stream()
                .memcpy_htod(&raw_tree, &mut tree.pairs)
                .unwrap();
            tree.level(count).unwrap();
            let output = dev.stream().clone_dtoh(&tree.pairs).unwrap();
            let range = 8 * (count - 1)..8 * (2 * count - 1);
            assert_eq!(
                output[range.clone()],
                expected_words[range],
                "raw level {count}, case {case}"
            );
            count /= 2;
        }
        dev.stream()
            .memcpy_htod(&raw_tree, &mut tree.pairs)
            .unwrap();
        tree.divide().unwrap();
        assert_eq!(
            dev.stream().clone_dtoh(&tree.h).unwrap(),
            expected.top[2]
                .iter()
                .flat_map(|v| words(*v))
                .collect::<Vec<_>>(),
            "raw top {case}"
        );
        assert_eq!(
            dev.stream().clone_dtoh(&tree.flags).unwrap(),
            vec![0; p.top]
        );
        // A single changed multiplicity is faithfully returned, never repaired.
        let mut changed = data.clone();
        changed[s.lookups[0].multiplicity][0] = changed[s.lookups[0].multiplicity][0] + M31::ONE;
        let near = LookupCase::new(&s, &changed, 0).unwrap();
        let expected_near = near.reference(beta, alpha).unwrap();
        let (actual_near, _) = prepare(&dev, &near.inputs(beta, alpha)).unwrap();
        assert_eq!(actual_near.layers, expected_near.layers);
        assert_eq!(actual_near.top, expected_near.top);
        assert_ne!(actual_near.layers[0][0][0], K::ZERO);
    }
    let (s, data, _, _) = fixture(SEED);
    let c = LookupCase::new(&s, &data, 0).unwrap();
    assert!(matches!(
        prepare(&dev, &c.inputs(K::ZERO, K::ZERO)),
        Err(Error::Lookup(LookupError::DenominatorZero))
    ));
    eprintln!("lookup_device_cases={CASES} raw_leaf_cases={CASES} raw_level_cases={CASES} raw_top_cases={CASES} near_miss_cases={CASES} zero_denominator_cases=1 seed={SEED} device={}", dev.name);
}

#[test]
#[ignore = "requires an explicitly allocated H100 and CUDA/NVRTC"]
fn matches_reference_lookup_inverse_on_h100() {
    let dev = device();
    let input = inverse_inputs();
    let count = input.len() / 4;
    let mut pairs = vec![0; 8 * (2 * count - 1)];
    for (pair, q) in pairs[8 * (count - 1)..]
        .chunks_exact_mut(8)
        .zip(input.chunks_exact(4))
    {
        pair[..4].copy_from_slice(&words(K::ONE));
        pair[4..].copy_from_slice(q);
    }
    let tree = Tree {
        dev: &dev,
        pairs: dev.stream().clone_htod(&pairs).unwrap(),
        h: dev.stream().alloc_zeros(4 * count).unwrap(),
        flags: dev.stream().alloc_zeros(count).unwrap(),
    };
    tree.divide().unwrap();
    verify_inverses(&input, &dev.stream().clone_dtoh(&tree.h).unwrap());
    let flags = dev.stream().clone_dtoh(&tree.flags).unwrap();
    assert_eq!(flags.len(), count);
    for (raw, flag) in input.chunks_exact(4).zip(flags) {
        assert_eq!(flag, u32::from(raw.iter().all(|x| *x % M31::MODULUS == 0)));
    }
    eprintln!(
        "lookup_inverse_device_cases={count} seed={SEED} device={}",
        dev.name
    );
}

#[test]
#[ignore = "requires an allocated H100"]
fn matches_reference_selected_top_and_resident_layers_on_h100() {
    let dev = device();
    for index in 0..CASES {
        let (s, columns, beta, alpha) = fixture(SEED + 2 * index as u64);
        let case = LookupCase::new(&s, &columns, 0).unwrap();
        let input = case.inputs(beta, alpha);
        let expected = case.reference(beta, alpha).unwrap();
        let (top, timing) = super::select::top(&dev, &input).unwrap();
        assert_eq!(top, expected.top);
        assert_eq!(timing.download_bytes, 52 * top[0].len());
        let (tree, timing) = super::select::resident(&dev, index, &input).unwrap();
        assert_eq!(timing.download_bytes, 0);
        assert_eq!(tree.compare_all(&expected.layers).unwrap(), tree.bytes());
        assert!(tree.layer(&dev, index + 1, 1).is_err());
        assert!(tree.layer(&dev, index, 3).is_err());
        assert!(tree.layer(&dev, index, usize::MAX).is_err());
    }
    let (s, columns, _, _) = fixture(SEED);
    let case = LookupCase::new(&s, &columns, 0).unwrap();
    let input = case.inputs(K::ZERO, K::ZERO);
    assert!(matches!(
        super::select::top(&dev, &input),
        Err(Error::Lookup(LookupError::DenominatorZero))
    ));
}

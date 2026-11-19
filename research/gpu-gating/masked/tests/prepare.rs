//! RFC-0014 §5: the production shapes that stalled preparation in E16-40d/E16-40k.
//! Run under an external deadline; a hung driver call cannot be cancelled by Rust.
#![cfg(feature = "cuda")]
use std::time::{Duration, Instant};
use stele_masked_gpu_bench::{
    challenge, cpu,
    gpu::{available, Device},
    inventory::Inventory,
};

#[test]
#[ignore = "requires an explicitly allocated H100 and an external deadline"]
fn matches_reference_production_shape_after_bounded_preparation() {
    assert!(available(), "required CUDA driver and NVRTC absent");
    let dev = Device::new().expect("CUDA device");
    assert!(dev.name.contains("H100"), "H100 required");
    for (index, text, original, dimensions) in [
        (
            9,
            include_str!("fixtures/prepare-case-9.txt"),
            9,
            (2, 103, 204),
        ),
        (
            11,
            include_str!("fixtures/prepare-case-11.txt"),
            5,
            (3, 1851, 3454),
        ),
    ] {
        let inventory = Inventory::parse(text).unwrap();
        let seed = 0x40d0001 + 2 * index;
        let case = inventory.case(0, seed);
        assert_eq!(case.original_variables, original);
        let shape = case.shape;
        assert_eq!(
            (shape.n, shape.factors.len(), shape.terms.len()),
            dimensions
        );
        let (mut device, _, _) = dev.build(&shape).expect("device build");
        let mut reference = cpu(&shape);
        let tables = |r: &stele_reductions::zk::claims::bench::Masked<_>| -> Vec<_> {
            r.tables().map(|(x, r)| (x.to_vec(), r.to_vec())).collect()
        };
        assert_eq!(device.tables().expect("initial tables"), tables(&reference));
        let started = Instant::now();
        device.prepare().expect("prepare every round");
        assert!(
            started.elapsed() < Duration::from_secs(120),
            "preparation deadline"
        );
        for round in 0..shape.n {
            assert_eq!(device.round().unwrap(), reference.round().unwrap());
            device.fold(challenge(round)).unwrap();
            reference.fold(challenge(round)).unwrap();
            assert_eq!(device.tables().unwrap(), tables(&reference));
        }
        eprintln!(
            "production_prepare_case={index} seed={seed} rounds={} device={}",
            shape.n, dev.name
        );
    }
}

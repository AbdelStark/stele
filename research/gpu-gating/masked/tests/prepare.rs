//! RFC-0014 §5: the production shape that stalled preparation in E16-40d.
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
    // Original inventory case 9, same base storage and seed; only its row is retained.
    let inventory = Inventory::parse(include_str!("fixtures/prepare-case-9.txt")).unwrap();
    let case = inventory.case(0, 0x40d0001 + 2 * 9);
    assert_eq!(case.original_variables, 9);
    let shape = case.shape;
    assert_eq!(
        (shape.n, shape.factors.len(), shape.terms.len()),
        (2, 103, 204)
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
        "production_prepare_case=9 seed=67960851 rounds=2 device={}",
        dev.name
    );
}

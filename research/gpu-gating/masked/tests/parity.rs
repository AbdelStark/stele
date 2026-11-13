//! E16-35 parity (RFC-0014 §5): device round polynomials and folded tables equal the
//! production CPU summand's, element for element, at every round. Runs with
//! `--features cuda` on a host with a CUDA driver; skips (passes, with a note) without
//! one. Sizes: `STELE_E16_35_LOGN` (comma-separated log2 entries, default `20`).
#![cfg(feature = "cuda")]
use stele_masked_gpu_bench::gpu::{available, Device};
use stele_masked_gpu_bench::{challenge, cpu, gkr_layer, relation, Shape};

fn compare(dev: &Device, shape: &Shape) {
    let (mut device, _, _) = dev.build(shape).expect("device build");
    let mut reference = cpu(shape);
    let tables = |r: &stele_reductions::zk::claims::bench::Masked<_>| -> Vec<_> {
        r.tables().map(|(x, r)| (x.to_vec(), r.to_vec())).collect()
    };
    assert!(
        tables(&reference) == device.tables().expect("read"),
        "{} built tables",
        shape.name
    );
    for i in 0..shape.n {
        let round = device.round().expect("device round");
        assert!(
            reference.round().expect("cpu round") == round,
            "{} round {i}",
            shape.name
        );
        device.fold(challenge(i)).expect("device fold");
        reference.fold(challenge(i)).expect("cpu fold");
        assert!(
            tables(&reference) == device.tables().expect("read"),
            "{} fold {i}",
            shape.name
        );
    }
}

#[test]
fn matches_reference_masked_rounds_on_device() {
    if !available() {
        eprintln!("skipped: no CUDA driver or NVRTC on this host");
        return;
    }
    let dev = Device::new().expect("CUDA device 0");
    let sizes = std::env::var("STELE_E16_35_LOGN").unwrap_or_else(|_| "20".to_string());
    for n in sizes
        .split(',')
        .filter_map(|s| s.trim().parse::<usize>().ok())
    {
        for (seed, shape) in [(1u64, relation(n, 11)), (2, gkr_layer(n, 12))] {
            compare(&dev, &shape);
            eprintln!(
                "bit-equal: {} 2^{n} (case {seed}), {} rounds",
                shape.name, shape.n
            );
        }
    }
}

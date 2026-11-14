//! E16-36 parity (RFC-0014 §5): the device-prepared hiding source has the production
//! `PreparedSource` root (every encoded symbol, salt and digest enters it). Runs with
//! `--features cuda` on a host with a CUDA driver; skips without one. Sizes:
//! `STELE_E16_36_SOURCES` (`ell:m` pairs, comma-separated, default `4:10,6:12`).
#![cfg(feature = "cuda")]
use stele_masked_gpu_bench::gpu::{available, Device};
use stele_masked_gpu_bench::gpu_source::prepare;
use stele_masked_gpu_bench::source::{cpu, Shape};

#[test]
fn matches_reference_prepared_source_root_on_device() {
    if !available() {
        eprintln!("skipped: no CUDA driver or NVRTC on this host");
        return;
    }
    let dev = Device::new().expect("CUDA device 0");
    let sizes = std::env::var("STELE_E16_36_SOURCES").unwrap_or_else(|_| "4:10,6:12".to_string());
    for pair in sizes.split(',') {
        let Some((ell, m)) = pair.split_once(':') else {
            continue;
        };
        let (ell, m) = (
            ell.trim().parse::<u8>().expect("ell"),
            m.trim().parse::<u8>().expect("m"),
        );
        let shape = Shape::new(ell, m, 9);
        let message = shape.message();
        let (expected, _, _) = cpu(&shape, &message).expect("production preparation");
        let (root, _) = prepare(&dev, &shape, &message).expect("device preparation");
        assert_eq!(root, expected, "ell {ell}, m {m}");
        eprintln!("bit-equal root: ell {ell}, m {m}");
    }
}

//! RFC-0010 A9 / RFC-0012 A3: selected responses from resident device material.
#![cfg(feature = "cuda")]

use stele_masked_gpu_bench::gpu::{available, Device, Error};
use stele_masked_gpu_bench::gpu_source::prepare_resident;
use stele_masked_gpu_bench::source::{Shape, BLOWUP};
use stele_masked_gpu_bench::{Field, M31, QM31};
use stele_reductions::stele_hash::{merkle, HashUsage};
use stele_reductions::stele_pcs::{Policy, PreparedSource};
use std::time::Duration;

#[test]
#[ignore = "requires a CUDA device; explicit execution fails without one"]
fn matches_reference_resident_source_on_device() {
    assert!(available(), "required CUDA driver and NVRTC absent");
    let dev = Device::new().expect("CUDA device");
    let mut cases = 0;
    let mut queries = 0;
    for seed in 1..=1000 {
        let ell = if seed <= 2 { 7 + seed as u8 } else { 3 + (seed % 2) as u8 };
        let mut shape = Shape::new(ell, 9, seed);
        shape.id = seed;
        let mut message = shape.message();
        for (slot, value) in message.iter_mut().zip([0, 1, M31::MODULUS - 1]) {
            *slot = M31::from_canonical(value).unwrap();
        }
        let reference = PreparedSource::<QM31>::hiding_with(
            shape.id, shape.ell, shape.m, BLOWUP, &message, &shape.seed,
            &mut HashUsage::default(), Policy::Two,
        ).expect("production source");
        let (actual, mut time) = prepare_resident(&dev, &shape, &message).expect("resident source");
        assert_eq!(actual.root(), reference.source().root());
        let descriptor = reference.source().descriptor();
        let count = descriptor.count;
        let height = count.trailing_zeros() as usize;
        let per_query = shape.rows() * 4 + height * 32;
        assert_eq!(time.download_bytes, 32, "prepare downloads only the root");
        assert_eq!(time.download, Duration::ZERO);
        assert_eq!(time.assemble, Duration::ZERO);
        assert_eq!(time.retained_bytes, count as usize * shape.rows() * 4 + (2 * count as usize - 1) * 32);
        assert!(time.buffer_peak_bytes >= time.retained_bytes);
        let indices = [count - 1, 0, count / 2, 1, count - 1, 0, seed % count, count / 3];
        for (ordinal, index) in indices.into_iter().enumerate() {
            let (payload, siblings) = actual.response(index, &mut time).expect("device response");
            let expected = reference.response(index).expect("production response");
            assert_eq!(payload, expected.payload, "seed {seed} column {index}");
            assert_eq!(siblings, expected.siblings, "seed {seed} path {index}");
            assert_eq!(time.download_bytes, 32 + (ordinal + 1) * per_query);
            merkle::verify(descriptor, &actual.root(), index, merkle::Opening {
                payload: &payload, siblings: &siblings,
            }).expect("ordinary authentication");
            if ordinal == 0 {
                let mut changed = payload;
                changed[32] ^= 1;
                assert_eq!(merkle::verify(descriptor, &actual.root(), index, merkle::Opening {
                    payload: &changed, siblings: &siblings,
                }), Err(merkle::Error::RootMismatch));
            }
            queries += 1;
        }
        let before = (time.download_bytes, time.download, time.assemble);
        for index in [count, u64::MAX] {
            assert!(matches!(actual.response(index, &mut time), Err(Error::Value)));
        }
        assert_eq!((time.download_bytes, time.download, time.assemble), before);
        assert_eq!(actual.root(), reference.source().root());
        cases += 1;
    }
    assert_eq!(cases, 1000);
    assert_eq!(queries, 8000);
    eprintln!("resident_source_device_cases={cases} resident_source_device_queries={queries}");
}

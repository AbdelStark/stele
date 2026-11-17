//! RFC-0010 A9 / RFC-0012 A3: complete source material, not just a root.
use stele_masked_gpu_bench::source::{material, Material, Shape, BLOWUP};
use stele_masked_gpu_bench::{Field, M31, QM31};
use stele_reductions::stele_hash::{merkle, HashUsage};
use stele_reductions::stele_pcs::{Policy, PreparedSource};

fn compare(shape: &Shape, message: &[M31], actual: &Material) {
    let expected = PreparedSource::<QM31>::hiding_with(
        shape.id,
        shape.ell,
        shape.m,
        BLOWUP,
        message,
        &shape.seed,
        &mut HashUsage::default(),
        Policy::Two,
    )
    .expect("production source");
    assert_eq!(actual.root(), expected.source().root());
    let descriptor = expected.source().descriptor();
    for index in 0..descriptor.count {
        let (payload, siblings) = actual.response(index).expect("real leaf");
        let reference = expected.response(index).expect("production response");
        assert_eq!(payload, reference.payload, "column {index}");
        assert_eq!(siblings, reference.siblings, "path {index}");
    }
    assert!(actual.response(descriptor.count).is_none());
    let (payload, siblings) = actual.response(0).unwrap();
    let mut changed = payload.to_vec();
    changed[32] ^= 1;
    assert_eq!(
        merkle::verify(
            descriptor,
            &actual.root(),
            0,
            merkle::Opening {
                payload: &changed,
                siblings: &siblings
            }
        ),
        Err(merkle::Error::RootMismatch)
    );
}

fn fixture(ell: u8, m: u8, seed: u64) -> (Shape, Vec<M31>) {
    let shape = Shape::new(ell, m, seed);
    let mut message = shape.message();
    for (slot, value) in message.iter_mut().zip([0, 1, M31::MODULUS - 1]) {
        *slot = M31::from_canonical(value).unwrap();
    }
    (shape, message)
}

#[test]
fn matches_reference_complete_source_material() {
    for (ell, m, seed) in [(3, 9, 1), (4, 9, 2), (8, 9, 3)] {
        let (shape, message) = fixture(ell, m, seed);
        compare(
            &shape,
            &message,
            &material(&shape, &message).expect("material"),
        );
    }
}

#[cfg(feature = "cuda")]
#[test]
#[ignore = "requires a CUDA device; explicit execution fails without one"]
fn matches_reference_complete_source_material_on_device() {
    use stele_masked_gpu_bench::gpu::{available, Device};
    use stele_masked_gpu_bench::gpu_source::prepare_material;
    assert!(available(), "required CUDA driver and NVRTC absent");
    let dev = Device::new().expect("CUDA device");
    let mut cases = 0;
    for seed in 1..=1000 {
        let ell = if seed <= 2 {
            7 + seed as u8
        } else {
            3 + (seed % 2) as u8
        };
        let (shape, message) = fixture(ell, 9, seed);
        let (actual, _) = prepare_material(&dev, &shape, &message).expect("device material");
        compare(&shape, &message, &actual);
        cases += 1;
    }
    assert_eq!(cases, 1000);
    eprintln!("complete_source_device_cases={cases}");
}

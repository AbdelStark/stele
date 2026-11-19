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

#[test]
fn matches_reference_complete_source_material_threads() {
    const CHILD: &str = "STELE_MATERIAL_TEST_CHILD";
    if std::env::var_os(CHILD).is_some() {
        for (ell, m, seed) in [(3, 9, 1), (6, 12, 3), (8, 9, 5)] {
            let (shape, message) = fixture(ell, m, seed);
            let actual = material(&shape, &message).expect("complete material");
            compare(&shape, &message, &actual);
            println!("material-root {ell} {m} {:?}", actual.root());
        }
        return;
    }
    let mut reference = None;
    for threads in [1, 3, 16] {
        let output = std::process::Command::new(std::env::current_exe().expect("test binary"))
            .args([
                "--exact",
                "matches_reference_complete_source_material_threads",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env("RAYON_NUM_THREADS", threads.to_string())
            .env_remove("STELE_STAGE_TIMES")
            .output()
            .expect("material worker");
        assert!(
            output.status.success(),
            "threads={threads}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let roots: Vec<String> = String::from_utf8(output.stdout)
            .expect("worker output")
            .lines()
            .filter(|line| line.starts_with("material-root "))
            .map(str::to_owned)
            .collect();
        assert_eq!(roots.len(), 3, "all three shapes must run");
        if let Some(expected) = &reference {
            assert_eq!(&roots, expected, "threads={threads}");
        } else {
            reference = Some(roots);
        }
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
        let (actual, time) = prepare_material(&dev, &shape, &message).expect("device material");
        let count = shape.source().unwrap().descriptor().count as usize;
        assert_eq!(
            time.download_bytes,
            count * shape.rows() * 4 + (2 * count - 1) * 32
        );
        assert_eq!(time.retained_bytes, time.download_bytes);
        compare(&shape, &message, &actual);
        cases += 1;
    }
    assert_eq!(cases, 1000);
    eprintln!("complete_source_device_cases={cases}");
}

//! RFC-0014 §§4–5: actual GKR inputs, challenges and CPU compact finals.
//! The callback only returns success or failure to the normal proof producer.
use crate::{
    gpu::{available, Device, Error},
    K,
};
use std::{
    sync::OnceLock,
    time::{Duration, Instant},
};
use stele_reductions::zk::{
    claims::{
        bench::GkrCase,
        t32_gkr::{Record, OBSERVER},
    },
    Error as ProofError,
};

static DEVICE: OnceLock<Device> = OnceLock::new();
pub fn install() {
    let now = Instant::now();
    assert!(available(), "required CUDA libraries");
    let dev = Device::new().expect("required CUDA device");
    assert!(dev.name.contains("H100"), "H100 required");
    assert!(DEVICE.set(dev).is_ok() && OBSERVER.set(observe).is_ok());
    eprintln!("t32_gkr_cold ns={}", now.elapsed().as_nanos());
}

fn observe(step: &GkrCase<'_, K>, reference: Record) -> Result<(), ProofError> {
    let dev = DEVICE.get().expect("required device");
    assert!(reference.points == step.point && reference.polynomials.len() == step.point.len());
    assert!(reference.compact.is_some() && reference.rounds_wall >= reference.arithmetic);
    let now = Instant::now();
    let input = step.construction()?;
    let n = input.num_vars;
    assert_eq!(step.point.len(), n as usize);
    let built = dev.build_gkr_bounded(&input);
    drop(input);
    let build = now.elapsed();
    let (mut state, work) = match built {
        Err(Error::Budget {
            required,
            available,
        }) => {
            eprintln!("t32_gkr_skip step={} lookup={} variables={n} required_bytes={required} available_bytes={available} attempt_ns={} cpu_factors_ns={} cpu_wall_ns={}", step.step, step.lookup, build.as_nanos(), reference.factors.as_nanos(),reference.rounds_wall.as_nanos());
            return Ok(());
        }
        v => v.expect("device construction"),
    };
    let mut round = Duration::ZERO;
    let mut fold = Duration::ZERO;
    let mut downloaded = 0;
    let mut round_upload = 0;
    for (expected, &point) in reference.polynomials.iter().zip(step.point) {
        let now = Instant::now();
        let got = state.round().expect("actual GKR round");
        round += now.elapsed();
        assert!(
            got == *expected,
            "GKR polynomial mismatch at step {}",
            step.step
        );
        downloaded += 16 * got.len();
        round_upload += state.round_upload_bytes();
        let now = Instant::now();
        state.fold(point).expect("actual GKR fold");
        dev.sync().expect("synchronize GKR fold");
        fold += now.elapsed();
    }
    let now = Instant::now();
    let got = state.final_values().expect("actual compact finals");
    let retained = state.device_buffer_bytes();
    drop(state);
    dev.sync().expect("release GKR step");
    let finish = now.elapsed();
    assert!(
        Some(&got) == reference.compact.as_ref(),
        "GKR compact finals mismatch at step {}",
        step.step
    );
    downloaded += 16 * got.len();
    let m = dev.memory_sample().expect("actual device memory");
    eprintln!("t32_gkr_step step={} lookup={} variables={n} cpu_factors_ns={} cpu_arithmetic_ns={} cpu_wall_ns={} build_ns={} round_ns={} fold_ns={} finish_ns={} input_bytes={} descriptor_bytes={} round_h2d_bytes={round_upload} d2h_bytes={downloaded} planned_bytes={} construction_bytes={} first_fold_bytes={} released_bytes={} retained_bytes={retained} total_bytes={} free_bytes={} pool_reserved_bytes={} pool_used_bytes={} pool_reserved_high={} pool_used_high={}", step.step, step.lookup,reference.factors.as_nanos(),reference.arithmetic.as_nanos(),reference.rounds_wall.as_nanos(),build.as_nanos(),round.as_nanos(),fold.as_nanos(),finish.as_nanos(),work.input_bytes,work.descriptor_bytes,work.peak_bytes,work.construction_bytes,work.fold_bytes,work.released_bytes,m.total,m.free,m.reserved,m.used,m.reserved_high,m.used_high);
    Ok(())
}

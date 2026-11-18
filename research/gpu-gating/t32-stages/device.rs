//! RFC-0014 §5: side-by-side stage timings from actual CPU prover operands.
//! The H100 observer returns no proof material and prints only timings and sizes.
use crate::{
    gpu::{available, batch, Device, DeviceMasked},
    gpu_lookup, Field, K,
};
use std::{cell::RefCell, sync::OnceLock, time::Instant};
use stele_reductions::{
    stele_pcs::Source,
    zk::claims::t32_sample::{Event, OBSERVER},
};

static DEVICE: OnceLock<Device> = OnceLock::new();
struct Active {
    id: u64,
    sum: DeviceMasked<'static>,
    round: usize,
}

thread_local! { static ACTIVE:RefCell<Option<Active>> = const { RefCell::new(None) }; }

pub fn install() {
    let start = Instant::now();
    assert!(available(), "required CUDA libraries");
    let device = Device::new().expect("required CUDA device");
    assert!(device.name.contains("H100"), "required H100");
    let cold = start.elapsed();
    assert!(DEVICE.set(device).is_ok());
    assert!(OBSERVER.set(observe).is_ok());
    eprintln!("t32_cold ns={}", cold.as_nanos());
}

fn observe(event: Event<'_>) {
    let device = DEVICE.get().expect("required GPU");
    match event {
        Event::Lookup {
            id,
            input,
            layers,
            top,
            normalize,
        } => {
            let start = Instant::now();
            let (result, t) = gpu_lookup::prepare(device, input).expect("lookup on H100");
            let wall = start.elapsed();
            assert!(result.layers == layers, "tree mismatch at lookup {id}");
            if let Some(expected) = top {
                assert!(
                    expected.iter().zip(&result.top).all(|(a, b)| *a == b),
                    "top mismatch at lookup {id}"
                );
            }
            let release = Instant::now();
            drop(result);
            device.sync().unwrap();
            let wall = wall + release.elapsed();
            let kind = if top.is_some() { "top" } else { "rebuild" };
            eprintln!("t32_lookup kind={kind} id={id} normalize_ns={} wall_ns={} stage_ns={} upload_ns={} tree_ns={} top_ns={} download_ns={} assemble_ns={} h2d_bytes={} d2h_bytes={} buffers_bytes={}",normalize.as_nanos(),wall.as_nanos(),t.stage.as_nanos(),t.upload.as_nanos(),t.tree.as_nanos(),t.top.as_nanos(),t.download.as_nanos(),t.assemble.as_nanos(),t.upload_bytes,t.download_bytes,t.buffer_peak_bytes);
        }
        Event::Batch {
            id,
            descriptor,
            message,
            claims,
            gammas,
        } => {
            let start = Instant::now();
            let src = Source::<K>::from_bytes(descriptor).expect("actual hiding source");
            let (sum, device_claim, t) =
                batch::prepare_message(device, &src, message, claims, gammas)
                    .expect("batch on H100");
            device.sync().unwrap();
            let wall = start.elapsed();
            let expected = claims
                .iter()
                .zip(gammas)
                .fold(K::from_i64(0), |acc, (c, g)| acc + *g * c.value);
            assert!(
                device_claim == expected,
                "batch claimed sum mismatch id={id}"
            );
            let positions: usize = claims.iter().map(|c| c.weights.len()).sum();
            eprintln!("t32_batch id={id} rows={} columns={} claims={} positions={positions} tile={} runs={} run_checks={} host_pack_bytes={} device_build_bytes={} wall_ns={} index_ns={} group_ns={} upload_ns={} build_ns={} setup_ns={} h2d_bytes={} term_bytes={} round_h2d_bytes={}",src.rows(),src.columns(),claims.len(),crate::batch::TILE,t.scheduled_runs,t.schedule_checks,t.host_buffer_bytes,t.construction_peak_bytes,wall.as_nanos(),t.index_time.as_nanos(),t.stage.as_nanos(),t.upload.as_nanos(),t.build.as_nanos(),t.round_setup.as_nanos(),t.upload_bytes,sum.descriptor_upload_bytes(),sum.round_upload_bytes());
            ACTIVE.with(|active| {
                assert!(active.replace(Some(Active { id, sum, round: 0 })).is_none())
            });
        }
        Event::Round { values, cpu } => ACTIVE.with_borrow_mut(|state| {
            let a = state.as_mut().expect("round after batch setup");
            let start = Instant::now();
            let got = a.sum.round().expect("device batch polynomial");
            let wall = start.elapsed();
            assert!(
                got == values,
                "batch polynomial mismatch id={} round={}",
                a.id,
                a.round
            );
            eprintln!(
                "t32_round id={} index={} cpu_ns={} gpu_ns={} d2h_bytes={}",
                a.id,
                a.round,
                cpu.as_nanos(),
                wall.as_nanos(),
                got.len() * 16
            );
        }),
        Event::Fold { challenge, cpu } => ACTIVE.with_borrow_mut(|state| {
            let a = state.as_mut().expect("fold after batch setup");
            let start = Instant::now();
            a.sum.fold(challenge).expect("device batch fold");
            device.sync().unwrap();
            let wall = start.elapsed();
            eprintln!(
                "t32_fold id={} index={} cpu_ns={} gpu_ns={}",
                a.id,
                a.round,
                cpu.as_nanos(),
                wall.as_nanos()
            );
            a.round += 1;
        }),
        Event::Finals { values, cpu } => ACTIVE.with_borrow_mut(|state| {
            let a = state.take().expect("finals after batch setup");
            let start = Instant::now();
            let got = a.sum.final_values().expect("device batch finals");
            drop(a.sum);
            device.sync().unwrap();
            let wall = start.elapsed();
            assert!(got == values, "batch finals mismatch id={}", a.id);
            eprintln!(
                "t32_finals id={} rounds={} cpu_ns={} gpu_ns={} d2h_bytes={}",
                a.id,
                a.round,
                cpu.as_nanos(),
                wall.as_nanos(),
                got.len() * 16
            );
        }),
    }
}

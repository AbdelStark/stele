//! RFC-0014 A1. One resident encoding per actual query block, released before returning.
use crate::{gpu::Device, gpu_source::prepare_resident, source::Shape};
use std::sync::{Mutex, OnceLock};
use stele_reductions::stele_pcs::t32_source::{now, Visit, OBSERVER};

static DEVICE: OnceLock<Device> = OnceLock::new();
// Separate CPU certificate workers can finish their rows concurrently.
static GPU: Mutex<()> = Mutex::new(());

pub fn install() {
    let start = now();
    let device = Device::new().expect("CUDA device");
    assert!(device.name.contains("H100"));
    assert!(DEVICE.set(device).is_ok() && OBSERVER.set(visit).is_ok());
    eprintln!("t32_source_cold ns={}", now() - start);
}

fn visit(input: Visit<'_>) {
    let _exclusive = GPU.lock().expect("source visit");
    let start = now();
    let dev = DEVICE.get().expect("source CUDA device");
    assert!(input.rows.is_power_of_two() && input.cols.is_power_of_two());
    let shape = Shape {
        id: input.id,
        ell: u8::try_from(input.rows.trailing_zeros() - 1).expect("row exponent"),
        m: u8::try_from(input.cols.trailing_zeros() - 1).expect("column exponent"),
        seed: *input.seed,
    };
    let source = shape.source().expect("supported hiding source");
    assert!(
        source.code_id() == input.code
            && source.rows() == input.rows
            && source.columns() == input.cols
    );
    let before = dev.memory_sample().expect("device memory before visit");
    let outside = (before.total - before.free).saturating_sub(before.reserved);
    let (resident, mut time) =
        prepare_resident(dev, &shape, input.message).expect("bounded source preparation");
    assert!(resident.root() == input.root, "source root differs");
    let width = usize::try_from(source.descriptor().width).expect("column width");
    let depth = source.codeword_len().ilog2() as usize;
    let stride = width + 32 * depth;
    assert_eq!(input.responses.len(), stride * input.indices.len());
    let mut compare_ns = 0;
    for (&index, expected) in input
        .indices
        .iter()
        .zip(input.responses.chunks_exact(stride))
    {
        let (payload, path) = resident
            .response(index, &mut time)
            .expect("selected resident response");
        let comparison = now();
        assert!(payload == expected[..width], "salted column differs");
        assert!(
            path.len() == depth
                && path
                    .iter()
                    .zip(expected[width..].chunks_exact(32))
                    .all(|(sibling, cpu)| sibling == cpu),
            "Merkle path differs"
        );
        compare_ns += now() - comparison;
    }
    drop(resident);
    dev.sync().expect("release resident source");
    let after = dev.memory_sample().expect("device memory after release");
    assert_eq!(after.used, before.used);
    let stop = now();
    eprintln!("t32_source id={} opening={} rows={} cols={} queries={} h2d={} d2h={} response_bytes={} retained={} peak={} device_total={} reserved_high={} used_high={} outside_pool={} start={start} stop={stop} observe_ns={compare_ns} cpu_start={} cpu_stop={}", input.id, u8::from(input.opening), input.rows, input.cols, input.indices.len(), time.upload_bytes,time.download_bytes,input.responses.len(),time.retained_bytes,time.buffer_peak_bytes,after.total,after.reserved_high,after.used_high,outside,input.cpu_start,input.cpu_stop);
}

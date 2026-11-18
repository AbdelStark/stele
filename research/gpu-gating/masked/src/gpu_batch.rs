//! RFC-0013 A5 item 5: construct batch tables and keep them resident for dense rounds.
//! Consumes prepared message/claims; adds no commitment, mask, transcript or opening.
use super::{Buf, Device, DeviceMasked, Error, Factor, PushKernelArg};
use crate::{batch::Prepared, Field, K};
use std::time::{Duration, Instant};
use stele_reductions::stele_pcs::PreparedSource;
use stele_reductions::zk::claims::Claim;

#[cfg(test)]
#[path = "gpu_batch_tests.rs"]
mod tests;

/// Operation wall times and explicit allocations, excluding CUDA infrastructure.
pub struct Timing {
    pub stage: Duration,
    pub upload: Duration,
    pub build: Duration,
    pub round_setup: Duration,
    pub upload_bytes: usize,
    /// Host vector capacities during preparation, excluding the original prover inputs.
    pub host_buffer_bytes: usize,
    pub scheduled_runs: u64,
    /// Actual position/run range comparisons across the selected tiles.
    pub schedule_checks: u64,
    /// All upload buffers and both output tables coexist during construction.
    pub construction_peak_bytes: usize,
    /// Both tables, descriptors, coefficients and all round scratch capacities.
    pub initial_round_buffer_bytes: usize,
    /// First M31 fold's old face overlaps its newly allocated QM31 face.
    pub first_fold_peak_bytes: usize,
    pub retained_after_first_fold_bytes: usize,
}

/// Build the production weight/face tables and reuse the GPU round/fold kernels.
/// The returned sum is the unchanged CPU sum of gamma*claimed_value. This operation
/// does not bind masks or authenticate the source's final opening.
pub fn prepare<'a>(
    dev: &'a Device,
    source: &PreparedSource<'_, K>,
    claims: &[Claim<K>],
    gammas: &[K],
) -> Result<(DeviceMasked<'a>, K, Timing), Error> {
    prepare_message(dev, source.source(), source.message(), claims, gammas)
}

/// The same preparation from the source descriptor and its original message.
pub fn prepare_message<'a>(
    dev: &'a Device,
    source: &stele_reductions::stele_pcs::Source<K>,
    message: &[crate::M31],
    claims: &[Claim<K>],
    gammas: &[K],
) -> Result<(DeviceMasked<'a>, K, Timing), Error> {
    let start = Instant::now();
    let p = Prepared::new(source, message, claims, gammas).ok_or(Error::Value)?;
    let stage = start.elapsed();
    let (summand, mut timing) = build(dev, &p)?;
    timing.stage = stage;
    Ok((summand, p.claimed_sum, timing))
}

fn build<'a>(dev: &'a Device, p: &Prepared) -> Result<(DeviceMasked<'a>, Timing), Error> {
    let coefficients = vec![(K::from_i64(1), vec![0, 1])];
    let terms = crate::round::Terms::new(2, &coefficients, 3).map_err(Error::Shape)?;
    let start = Instant::now();
    let message = dev.stream.clone_htod(&p.message)?;
    let packed = dev.stream.clone_htod(&p.weights)?;
    let gammas = dev.stream.clone_htod(&p.gammas)?;
    let runs = dev.stream.clone_htod(&p.runs)?;
    let offsets = dev.stream.clone_htod(&p.offsets)?;
    let weights = dev.stream.alloc_zeros::<u32>(4 * p.len)?;
    let face = dev.stream.alloc_zeros::<u32>(p.len)?;
    dev.sync()?;
    let upload = start.elapsed();
    let start = Instant::now();
    let mp = dev.ptr(&message);
    let wp = dev.ptr(&weights);
    let fp = dev.ptr(&face);
    let columns = p.columns as u64;
    let len = p.len as u64;
    let half = len / 2;
    let tile = crate::batch::TILE as u64;
    let packed_ptr = dev.ptr(&packed);
    let gamma_ptr = dev.ptr(&gammas);
    let runs_ptr = dev.ptr(&runs);
    let offset_ptr = dev.ptr(&offsets);
    let f = dev.function("batch_weights")?;
    let mut b = dev.stream.launch_builder(&f);
    b.arg(&packed_ptr)
        .arg(&gamma_ptr)
        .arg(&runs_ptr)
        .arg(&offset_ptr)
        .arg(&wp)
        .arg(&tile)
        .arg(&half);
    // SAFETY: Prepared bounds each tile interval, weight span and claim index.
    // The launch visits only the data face. The zero-initialized mask face is retained.
    unsafe { b.launch(dev.grid(p.len / 2)) }?;
    let f = dev.function("batch_face")?;
    let mut b = dev.stream.launch_builder(&f);
    b.arg(&mp).arg(&fp).arg(&columns).arg(&len);
    // SAFETY: message has 2*len entries in rows of 2*columns; face has len.
    // Y=0 gathers are disjoint and stay within each row (RFC-0013 A5 item 5).
    unsafe { b.launch(dev.grid(p.len)) }?;
    dev.sync()?;
    let build = start.elapsed();
    drop((message, packed, gammas, runs, offsets));
    let start = Instant::now();
    let factors = vec![
        Factor {
            x: Buf::Ext(weights),
            r: None,
            v: None,
        },
        Factor {
            x: Buf::Base(face),
            r: None,
            v: None,
        },
    ];
    let state = dev.summand(factors, &coefficients, terms, 3, p.len)?;
    dev.sync()?;
    let round_setup = start.elapsed();
    let initial_round_buffer_bytes = state.device_buffer_bytes();
    Ok((
        state,
        Timing {
            stage: Duration::ZERO,
            upload,
            build,
            round_setup,
            upload_bytes: p.upload_bytes(),
            host_buffer_bytes: p.host_buffer_bytes(),
            scheduled_runs: p.offsets.last().copied().unwrap_or(0),
            schedule_checks: p.schedule_checks,
            construction_peak_bytes: p.upload_bytes() + 20 * p.len,
            initial_round_buffer_bytes,
            first_fold_peak_bytes: initial_round_buffer_bytes + 8 * p.len,
            retained_after_first_fold_bytes: initial_round_buffer_bytes + 4 * p.len,
        },
    ))
}

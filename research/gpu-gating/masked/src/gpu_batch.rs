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
    let start = Instant::now();
    let p = Prepared::new(source.source(), source.message(), claims, gammas).ok_or(Error::Value)?;
    let stage = start.elapsed();
    let (summand, mut timing) = build(dev, &p)?;
    timing.stage = stage;
    Ok((summand, p.claimed_sum, timing))
}

fn build<'a>(dev: &'a Device, p: &Prepared) -> Result<(DeviceMasked<'a>, Timing), Error> {
    let start = Instant::now();
    let message = dev.stream.clone_htod(&p.message)?;
    let pairs = dev.stream.clone_htod(&p.pairs)?;
    let offsets = dev.stream.clone_htod(&p.offsets)?;
    let weights = dev.stream.alloc_zeros::<u32>(4 * p.len)?;
    let face = dev.stream.alloc_zeros::<u32>(p.len)?;
    dev.sync()?;
    let upload = start.elapsed();
    let start = Instant::now();
    let (mp, pp, op, wp, fp, columns, len) = (
        dev.ptr(&message),
        dev.ptr(&pairs),
        dev.ptr(&offsets),
        dev.ptr(&weights),
        dev.ptr(&face),
        p.columns as u64,
        p.len as u64,
    );
    let f = dev.function("batch_weights")?;
    let mut b = dev.stream.launch_builder(&f);
    b.arg(&pp).arg(&op).arg(&wp).arg(&len);
    // SAFETY: Prepared bounds offsets by pairs and data positions by len/2.
    // Each thread owns one canonical output; claim order is fixed (RFC-0014 §1).
    unsafe { b.launch(dev.grid(p.len)) }?;
    let f = dev.function("batch_face")?;
    let mut b = dev.stream.launch_builder(&f);
    b.arg(&mp).arg(&fp).arg(&columns).arg(&len);
    // SAFETY: message has 2*len entries in rows of 2*columns; face has len.
    // Y=0 gathers are disjoint and stay within each row (RFC-0013 A5 item 5).
    unsafe { b.launch(dev.grid(p.len)) }?;
    dev.sync()?;
    let build = start.elapsed();
    drop((message, pairs, offsets));
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
    let state = dev.summand(factors, vec![(K::from_i64(1), vec![0, 1])], 3, p.len)?;
    dev.sync()?;
    let round_setup = start.elapsed();
    let scratch = 8 * (state.xs.len() + state.rs.len())
        + 4 * (state.coef.len() + state.partials.len() + state.out.len());
    let initial_round_buffer_bytes = 20 * p.len + scratch;
    Ok((
        state,
        Timing {
            stage: Duration::ZERO,
            upload,
            build,
            round_setup,
            upload_bytes: p.upload_bytes(),
            construction_peak_bytes: p.upload_bytes() + 20 * p.len,
            initial_round_buffer_bytes,
            first_fold_peak_bytes: initial_round_buffer_bytes + 8 * p.len,
            retained_after_first_fold_bytes: initial_round_buffer_bytes + 4 * p.len,
        },
    ))
}

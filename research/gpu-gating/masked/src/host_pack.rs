//! RFC-0013 A5 item 5. Measure host preparations on the original ragged claims.
//! Four alternating pairs run with one output live; exhaustive equality runs separately.
use crate::batch::{pack, Prepared};
use crate::{K, M31};
use std::{hint::black_box, mem::size_of_val, time::Instant};
use stele_reductions::{stele_pcs::Source, zk::claims::Claim};

struct Inputs<'a> {
    descriptor: &'a [u8],
    message: &'a [M31],
    claims: &'a [Claim<K>],
    gammas: &'a [K],
}

impl Inputs<'_> {
    fn sample<const PARALLEL: bool>(&self, id: u64, rep: usize, order: usize) {
        let start = Instant::now();
        let source = Source::from_bytes(self.descriptor).expect("original source descriptor");
        let decode = start.elapsed();
        let group = Instant::now();
        let (prepared, times) =
            pack::<PARALLEL>(&source, self.message, self.claims, self.gammas).expect("valid batch");
        let group = group.elapsed();
        let index = prepared.index_time;
        let output = prepared.host_buffer_bytes();
        let upload = prepared.upload_bytes();
        let release = Instant::now();
        drop(black_box(prepared));
        drop(source);
        let release = release.elapsed();
        let wall = start.elapsed();
        let method = if PARALLEL { "parallel" } else { "serial" };
        eprintln!("host_pack id={id} rep={rep} order={order} method={method} wall_ns={} decode_ns={} group_ns={} index_ns={} split_ns={} alloc_ns={} weights_ns={} runs_ns={} message_ns={} drop_ns={} scratch_bytes={} output_bytes={output} h2d_payload_bytes={upload}",
            wall.as_nanos(), decode.as_nanos(), group.as_nanos(), index.as_nanos(), times.split.as_nanos(),
            times.alloc.as_nanos(), times.weights.as_nanos(), times.runs.as_nanos(), times.message.as_nanos(), release.as_nanos(), times.scratch);
    }
}

/// Each timed pass reconstructs the source, prepares all CUDA input buffers and
/// drops them. Read-only qualification compares all buffer elements outside the samples.
/// This CPU-only operation does not request a CUDA context.
pub fn compare(id: u64, descriptor: &[u8], message: &[M31], claims: &[Claim<K>], gammas: &[K]) {
    let inputs = Inputs {
        descriptor,
        message,
        claims,
        gammas,
    };
    for rep in 0..4 {
        if (rep + id as usize).is_multiple_of(2) {
            inputs.sample::<false>(id, rep, 0);
            inputs.sample::<true>(id, rep, 1);
        } else {
            inputs.sample::<true>(id, rep, 0);
            inputs.sample::<false>(id, rep, 1);
        }
    }
    let source = Source::from_bytes(descriptor).unwrap();
    let reference = Prepared::new(&source, message, claims, gammas).unwrap();
    let (candidate, _) = pack::<true>(&source, message, claims, gammas).unwrap();
    assert!(
        reference.matches(&candidate),
        "batch input mismatch at {id}"
    );
    let positions: usize = claims.iter().map(|c| c.weights.len()).sum();
    let weight_cap: usize = claims.iter().map(|c| c.weights.capacity()).sum();
    let pair_bytes = size_of::<(usize, K)>();
    eprintln!("host_match id={id} rows={} columns={} claims={} positions={positions} runs={} offsets={} payload_bytes={} descriptor_bytes={} message_bytes={} claim_headers_bytes={} gamma_bytes={} tuples_bytes={} tuple_capacity_bytes={} tuple_width={pair_bytes}",
        source.rows(), source.columns(), claims.len(), reference.runs.len(), reference.offsets.len(),
        reference.upload_bytes(), descriptor.len(), size_of_val(message), size_of_val(claims),
        size_of_val(gammas), pair_bytes * positions, pair_bytes * weight_cap);
}

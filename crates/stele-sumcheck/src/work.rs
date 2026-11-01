//! RFC-0006 A1 and RFC-0007 A2 §6: observations, never proof authority.
//! Bytes are actual Vec capacities, including heap-resident nested Vec headers.
//! Excludes borrowed Instance/Proof, Summand internals, caller observation slots,
//! stack storage, allocator metadata and process memory; callers account for these.
use crate::Error;
use alloc::vec::Vec;
use core::mem::size_of;

/// One actual producer round, indexed in transcript order.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RoundWork {
    /// Round-vector headers and completed rounds, before calling the strategy.
    pub proof_prefix_bytes: usize,
    /// Returned current-round allocation; also present during its payload absorb.
    pub values_bytes: usize,
    /// Actual Round frame, dropped before folding the strategy.
    pub payload_bytes: usize,
}
/// Successful A1 producer allocations, excluding the strategy's owned storage.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProverWork {
    /// Outer round vector's heap storage for nested Vec headers.
    pub round_headers_bytes: usize,
    /// Instance frame, live with the empty reserved round vector.
    pub instance_bytes: usize,
    /// Actual returned final-value capacity.
    pub final_values_bytes: usize,
    /// Final frame, live with all proof buffers.
    pub final_payload_bytes: usize,
    /// Returned proof's nested headers, rounds and final values.
    pub proof_bytes: usize,
    /// Maximum simultaneously live A1-owned capacity; excludes strategy internals.
    pub peak_owned_bytes: usize,
}
/// Successful A1 verifier allocations; the borrowed proof is excluded.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VerifierWork {
    /// Instance frame capacity.
    pub instance_bytes: usize,
    /// Maximum actual Round frame capacity; zero when there are no rounds.
    pub round_payload_bytes: usize,
    /// Final frame capacity, including zero-round instances.
    pub final_payload_bytes: usize,
    /// Reserved returned point capacity, live throughout replay.
    pub point_bytes: usize,
    /// Reserved returned claim capacity, live throughout replay.
    pub claims_bytes: usize,
    /// Point and claim capacities plus the largest one live frame.
    pub peak_owned_bytes: usize,
}
pub(crate) fn bytes<T>(values: &Vec<T>) -> Result<usize, Error> {
    values
        .capacity()
        .checked_mul(size_of::<T>())
        .ok_or(Error::Capacity)
}
pub(crate) fn add(a: usize, b: usize) -> Result<usize, Error> {
    a.checked_add(b).ok_or(Error::Capacity)
}

//! RFC-0008 A3 / A5 §6: observations of the actual producer's field buffers.
use super::Error;
use alloc::vec::Vec;
use core::mem::size_of;

/// Actual field-buffer capacities at named producer boundaries, in bytes.
/// This is descriptive work, never an admission bound or verification record.
/// Counts the payloads of level, Dense, completed proof and point vectors.
/// Excludes borrowed inputs, Vec headers, descriptors, Instance/Accounting/claim
/// metadata, framing, and allocations inside A1 (including its in-flight proof).
/// Process RSS must be measured separately; these observations are not its peak.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Work {
    /// All actual retained tree-level payloads; zero for a selected product.
    pub levels_bytes: usize,
    /// Largest actual Dense table payload, before those same vectors move into A1.
    pub dense_bytes: usize,
    /// Largest completed proof payload capacity, distinct from serialized length.
    pub proof_bytes: usize,
    /// Largest simultaneous old/captured or old/returned point payloads observed.
    pub point_bytes: usize,
    /// Maximum simultaneous included capacities at the observed boundaries.
    /// A1-entry includes Dense and the prior completed proof; A1-return includes
    /// the new proof and excludes the already-dropped Dense. This is a lower
    /// observation of the stated scope, not a claim to its exact allocation peak.
    pub peak_observed_bytes: usize,
}

pub(super) fn add(a: usize, b: usize) -> Result<usize, Error> {
    a.checked_add(b).ok_or(Error::Capacity)
}
pub(super) fn bytes<T>(values: &Vec<T>) -> Result<usize, Error> {
    values
        .capacity()
        .checked_mul(size_of::<T>())
        .ok_or(Error::Capacity)
}
pub(super) fn tables<K>(values: &[Vec<K>]) -> Result<usize, Error> {
    values.iter().try_fold(0, |n, v| add(n, bytes(v)?))
}
pub(super) fn proof<K>(proof: &stele_sumcheck::Proof<K>) -> Result<usize, Error> {
    add(tables(&proof.rounds)?, bytes(&proof.final_values)?)
}
impl Work {
    pub(super) fn observe(
        &mut self,
        levels: usize,
        dense: usize,
        proof: usize,
        point: usize,
    ) -> Result<(), Error> {
        let live = add(add(levels, dense)?, add(proof, point)?)?;
        self.levels_bytes = self.levels_bytes.max(levels);
        self.dense_bytes = self.dense_bytes.max(dense);
        self.proof_bytes = self.proof_bytes.max(proof);
        self.point_bytes = self.point_bytes.max(point);
        self.peak_observed_bytes = self.peak_observed_bytes.max(live);
        Ok(())
    }
}

/// Captured before moving the actual tables into Dense; no replay or callback.
pub(super) struct DenseWork {
    pub tables: usize,
    pub point: usize,
}

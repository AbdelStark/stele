//! RFC-0008 A5 §6: actual producer capacities, with explicit partial scope.
use super::super::{mul, sum, Error};
use alloc::vec::Vec;
use core::mem::size_of;
use stele_lookup::fraction;
use stele_pcs::PreparationWork;

/// Observations from the three actual reductions in one repetition.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RepetitionWork {
    /// Actual grouped lookup tree; caller leaves are counted outside this work.
    pub lookup: fraction::Work,
    /// Actual canonical Table tree.
    pub table: fraction::Work,
    /// Actual selected product; caller lifts and selector are counted outside it.
    pub selected: fraction::Work,
}
/// Success-only observations, never proof data, authority or admission limits.
/// Local snapshots count actual index-entry, field-payload and wire capacities,
/// plus retained prepared columns/Merkle nodes. They exclude caller originals,
/// Table/selector inputs, vector headers, descriptor/record/claim metadata and
/// scratch inside certificate/opening, functional construction or A1 calls.
/// Internal Table/statement encoding, A3 framing and selector-evaluation scratch
/// are also unobserved; returned frames are counted only while actually retained.
/// Child observations retain their documented scopes. Whole-worker RSS and
/// complete timing remain necessary; no field claims an exact allocation peak.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProverWork {
    /// Capacity of the complete output packet, including its embedded certificates.
    pub proof_bytes: usize,
    /// Retained independent unit vectors.
    pub units_bytes: usize,
    /// Actual sorted (tuple key, row index) vector capacity.
    pub index_bytes: usize,
    /// Largest actual group-weight vector; previous ones have already dropped.
    pub group_weights_bytes: usize,
    /// All retained K multiplicity payloads.
    pub mu_values_bytes: usize,
    /// All retained M31 limb payloads, borrowed rather than copied by preparation.
    pub mu_limbs_bytes: usize,
    /// All retained original K lifts.
    pub originals_bytes: usize,
    /// Retained K selector lift.
    pub selector_bytes: usize,
    /// All retained prepared columns and Merkle nodes, excluding prior scratch.
    pub prepared_bytes: usize,
    /// Largest simultaneous returned piece row/column coefficient payloads.
    pub coefficients_bytes: usize,
    /// Largest observed temporary frame, certificate or serialized proof buffer.
    pub temporary_wire_bytes: usize,
    /// Maximum simultaneous included capacities at the outer observation points.
    pub local_peak_observed_bytes: usize,
    /// Maximum local or actual child observation plus its unchanged live outer base.
    /// This is a boundary observation, not the sum of independent category peaks.
    pub peak_observed_bytes: usize,
    /// Actual preparation used for each multiplicity; unused slots stay None.
    pub preparations: [Option<PreparationWork>; 2],
    /// Actual child execution observations; unused slots stay None.
    pub repetitions: [Option<RepetitionWork>; 2],
}
pub(super) fn bytes<T>(values: &Vec<T>) -> Result<usize, Error> {
    mul(values.capacity(), size_of::<T>())
}
pub(super) fn vectors<T>(values: &[Vec<T>]) -> Result<usize, Error> {
    values.iter().try_fold(0, |n, v| sum(&[n, bytes(v)?]))
}
pub(super) fn proof<K>(proof: &stele_sumcheck::Proof<K>) -> Result<usize, Error> {
    sum(&[vectors(&proof.rounds)?, bytes(&proof.final_values)?])
}
pub(super) fn tree<K: stele_hash::ChallengeField>(
    proof: &fraction::Proof<K>,
) -> Result<usize, Error> {
    proof
        .steps
        .iter()
        .try_fold(0, |n, step| sum(&[n, self::proof(step)?]))
}
impl ProverWork {
    pub(super) fn local(&mut self, parts: &[usize]) -> Result<(), Error> {
        let live = sum(parts)?;
        self.local_peak_observed_bytes = self.local_peak_observed_bytes.max(live);
        self.peak_observed_bytes = self.peak_observed_bytes.max(live);
        Ok(())
    }
    pub(super) fn child(&mut self, base: usize, peak: usize) -> Result<(), Error> {
        self.peak_observed_bytes = self.peak_observed_bytes.max(sum(&[base, peak])?);
        Ok(())
    }
    pub(super) fn wire(&mut self, capacity: usize) {
        self.temporary_wire_bytes = self.temporary_wire_bytes.max(capacity);
    }
}

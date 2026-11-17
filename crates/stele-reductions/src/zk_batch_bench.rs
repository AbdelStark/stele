//! RFC-0013 A5 item 5: production batch inputs for E16-40e qualification.
//! Available only with `bench`; no prover or verifier calls this adapter.
use super::{batch_instance, face, weight_table, Claim, Error};
use alloc::vec::Vec;
use stele_hash::ChallengeField;
use stele_pcs::PreparedSource;
use stele_sumcheck::Instance;

/// Actual dense batch inputs before bound masking and the authenticated opening.
/// These are witness values for a benchmark caller, never public proof metadata.
pub struct BatchInputs<K> {
    /// The production degree-two instance, including its weighted claimed sum.
    pub instance: Instance<K>,
    /// `(1-w) W`, with the complete `w=1` half zero, in `(w,row,col)` order.
    pub weights: Vec<K>,
    /// The source message on `Y=0`, in the same order, including mask rows.
    pub face: Vec<K>,
}

impl<K: ChallengeField> BatchInputs<K> {
    /// Call the ordinary producer's instance, weight and face builders.
    /// `gammas` are supplied benchmark inputs, not transcript challenges.
    /// Source preparation precedes this operation; charge these table builders,
    /// any later copies, rounds and authenticated openings separately.
    pub fn new(
        id: u64,
        prepared: &PreparedSource<'_, K>,
        claims: &[Claim<K>],
        gammas: &[K],
    ) -> Result<Self, Error> {
        let source = prepared.source();
        if !source.is_hiding() {
            return Err(Error::Statement);
        }
        // Validate counts and every position before the instance's zipped sum.
        let weights = weight_table(source, claims, gammas)?;
        Ok(Self {
            instance: batch_instance(id, source, claims, gammas),
            weights,
            face: face(prepared),
        })
    }
}

//! Unverified selected-product A1 payloads, RFC-0008 A3. No transcript or consumer.
use super::{read_values, reserve, Descriptor, Error};
use alloc::vec::Vec;
use stele_hash::ChallengeField;
use stele_sumcheck::Proof;

/// Borrowed immutable verifier-owned tree and ordered original source identities.
/// This validates wire shape only, not the selector, arithmetic or original claims.
#[derive(Clone, Copy, Debug)]
pub struct LeafDescriptor<'a, K: ChallengeField> {
    tree: &'a Descriptor<K>,
    sources: &'a [u64],
}
impl<'a, K: ChallengeField> LeafDescriptor<'a, K> {
    /// Check nonempty distinct original ids; local Eq/selector ids 0 and 1 are reserved.
    pub fn new(tree: &'a Descriptor<K>, sources: &'a [u64]) -> Result<Self, Error> {
        if sources.is_empty()
            || sources
                .iter()
                .enumerate()
                .any(|(i, id)| *id < 2 || sources[..i].contains(id))
        {
            return Err(Error::InvalidDescriptor);
        }
        // A1's complete ordered input count (Eq, sigma, originals) is a u32.
        let count = sources.len().checked_add(2).ok_or(Error::Capacity)?;
        u32::try_from(count).map_err(|_| Error::Capacity)?;
        let out = Self { tree, sources };
        out.proof_size()?;
        Ok(out)
    }
    /// The original validated tree descriptor, borrowed without cloning its units.
    pub fn tree(&self) -> &Descriptor<K> {
        self.tree
    }
    /// Original column identities in their fixed order, never supplied by proof bytes.
    pub fn source_ids(&self) -> &[u64] {
        self.sources
    }
    /// Exact bounded A1 byte count; does not materialize the source hypercube.
    pub fn proof_size(&self) -> Result<usize, Error> {
        (self.tree.m as usize)
            .checked_mul(4)
            .and_then(|n| n.checked_add(self.sources.len()))
            .and_then(|n| n.checked_add(2))
            .and_then(|n| n.checked_mul(4 * K::DEGREE))
            .ok_or(Error::Capacity)
    }
    fn validate(&self, proof: &Proof<K>) -> Result<(), Error> {
        if proof.rounds.len() != self.tree.m as usize
            || proof.final_values.len() != self.sources.len() + 2
            || proof.rounds.iter().any(|row| row.len() != 4)
        {
            return Err(Error::ProofShape);
        }
        Ok(())
    }
    /// Encode every field, including unused original finals, with no embedded counts.
    pub fn encode(&self, proof: &Proof<K>) -> Result<Vec<u8>, Error> {
        self.validate(proof)?;
        let mut out = Vec::new();
        reserve(&mut out, self.proof_size()?)?;
        for value in proof.rounds.iter().flatten().chain(&proof.final_values) {
            out.extend_from_slice(value.to_le_bytes().as_ref());
        }
        Ok(out)
    }
    /// Reject incorrect total length before allocation and every noncanonical field limb.
    pub fn decode(&self, bytes: &[u8]) -> Result<Proof<K>, Error>
    where
        for<'b> K::Bytes: TryFrom<&'b [u8]>,
    {
        if bytes.len() != self.proof_size()? {
            return Err(Error::ProofShape);
        }
        let mut cursor = 0;
        let mut rounds = Vec::new();
        reserve(&mut rounds, self.tree.m as usize)?;
        for _ in 0..self.tree.m {
            rounds.push(read_values::<K>(bytes, &mut cursor, 4)?);
        }
        Ok(Proof {
            rounds,
            final_values: read_values::<K>(bytes, &mut cursor, self.sources.len() + 2)?,
        })
    }
}

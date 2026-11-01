//! RFC-0010 A9 §6/A10: descriptive capacities and logical work, never authority.
//! Owned bytes are actual Vec capacities. Borrowed preparation, rows, weights and
//! proofs, stack, allocator metadata and process memory are excluded. Copy/read
//! volumes count named operations, including repeats, not physical memory traffic.
use crate::Error;
use alloc::vec::Vec;
use core::mem::size_of;

/// Successful certificate or retained-opening production in the shared path.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProverWork {
    /// Returned proof capacity.
    pub proof_bytes: usize,
    /// Functional frame capacity; certificate framing is on the stack.
    pub frame_bytes: usize,
    /// Owned certificate row weights; retained-opening weights are borrowed.
    pub weights_bytes: usize,
    /// Largest actual response path capacity, observed before moving it.
    pub path_peak_bytes: usize,
    /// Largest sum of simultaneously live owned vector capacities.
    pub peak_owned_bytes: usize,
    /// Original M31 elements read to form the certificate row; zero for retained u.
    pub source_elements: usize,
    /// Row values serialized and, for openings, used in the scalar check.
    pub row_values: usize,
    /// Responses copied, including repeated indices.
    pub responses: usize,
    /// Payload bytes copied from prepared columns to the proof.
    pub column_bytes_copied: usize,
    /// Sibling bytes copied into the proof, including repeats.
    pub path_bytes_copied: usize,
}
/// Successful certificate, functional or point verification in the shared path.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VerifierWork {
    /// Functional frame capacity; certificate framing is on the stack.
    pub frame_bytes: usize,
    /// Owned eq weights: certificate a, point a+b, or zero for a functional.
    pub weights_bytes: usize,
    /// Decoded K-valued row capacity.
    pub row_bytes: usize,
    /// Returned encoded-word capacity, already included in the encoder peak.
    pub encoded_bytes: usize,
    /// Observations from the actual encoding, including output and scratch.
    pub encoder: stele_code::EncoderWork,
    /// Largest sum of simultaneously live owned vector capacities.
    pub peak_owned_bytes: usize,
    /// Authenticated responses, including repeated indices.
    pub responses: usize,
    /// Column payload bytes passed to Merkle authentication.
    pub column_bytes_authenticated: usize,
    /// Column bytes canonically decoded after authentication.
    pub column_bytes_decoded: usize,
    /// Sibling bytes copied into the fixed stack path array.
    pub path_bytes_copied: usize,
    /// Encoded K values read for the column equations.
    pub encoded_values_read: usize,
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn matches_reference_capacity_observations() {
        let mut values = Vec::<u64>::with_capacity(37);
        values.push(1);
        assert_eq!(bytes(&values), Ok(values.capacity() * size_of::<u64>()));
        assert!(bytes(&values).expect("capacity") > core::mem::size_of_val(values.as_slice()));
        assert_eq!(add(usize::MAX, 1), Err(Error::Capacity));
        assert_eq!(add(0, usize::MAX), Ok(usize::MAX));
    }
}

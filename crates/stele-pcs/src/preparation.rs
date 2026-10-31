//! RFC-0010 A9 §§1,6,9: canonical prover storage, with no verifier acceptance.
use crate::{Error, Source};
use alloc::vec::Vec;
use core::mem::size_of;
use stele_code::Encoder;
use stele_field::{Serialize, M31};
use stele_hash::{merkle, ChallengeField, HashUsage};

/// Observed vector capacities for successful preparation; not a proof or budget.
/// Excludes stack values, allocator metadata and process/runtime memory.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PreparationWork {
    /// Borrowed row-major M31 input, excluded from owned peak.
    pub borrowed_message_bytes: usize,
    /// Owned transposed encoded column bytes.
    pub encoded_columns_bytes: usize,
    /// Maximum single-row encoder peak, including full output and scratch/twiddles.
    pub encoder_peak_bytes: usize,
    /// Temporary borrowed-leaf slice array, live during Merkle construction.
    pub leaf_references_bytes: usize,
    /// Owned Merkle digest-vector capacity.
    pub merkle_nodes_bytes: usize,
    /// Maximum sum of simultaneously live owned vector capacities.
    pub peak_owned_bytes: usize,
}

/// One producer response. These bytes acquire authority only at their verifier.
pub struct PreparedColumn<'a> {
    /// Canonical column bytes, borrowing the prepared storage.
    pub payload: &'a [u8],
    /// Owned bottom-up path; repeated responses retain individual full paths.
    pub siblings: Vec<merkle::Digest>,
}

/// Canonical prover material; its source context authenticates no external claim.
/// Borrowing prevents the message changing while this material is used:
/// ```compile_fail
/// use stele_field::{Field, M31, QM31};
/// use stele_hash::HashUsage;
/// use stele_pcs::PreparedSource;
/// let mut message = [M31::ONE];
/// let prepared = PreparedSource::<QM31>::new(1, 0, 0, 1, &message, &mut HashUsage::default()).unwrap();
/// message[0] = M31::ZERO;
/// let column = prepared.response(0);
/// ```
pub struct PreparedSource<'a, K: ChallengeField> {
    source: Source<K>,
    message: &'a [M31],
    columns: Vec<u8>,
    tree: merkle::Tree,
    work: PreparationWork,
}

fn checked_bytes<T>(count: usize) -> Result<usize, Error> {
    count
        .checked_mul(size_of::<T>())
        .filter(|bytes| *bytes <= isize::MAX as usize)
        .ok_or(Error::Capacity)
}

impl<'a, K: ChallengeField> PreparedSource<'a, K> {
    /// Encode exact canonical M31 rows and commit their columns under the source id.
    /// Checks shapes/sizes before allocation; hash usage survives construction errors.
    pub fn new(
        id: u64,
        ell: u8,
        m: u8,
        blowup: u8,
        message: &'a [M31],
        usage: &mut HashUsage,
    ) -> Result<Self, Error> {
        let source = Source::<K>::new(id, ell, m, blowup, [0; 32])?;
        let count = source
            .rows()
            .checked_mul(source.columns())
            .ok_or(Error::Capacity)?;
        if message.len() != count {
            return Err(Error::MessageShape);
        }
        let length = source.code().codeword_len();
        let width = usize::try_from(source.descriptor().width).map_err(|_| Error::Capacity)?;
        let bytes = checked_bytes::<u8>(width.checked_mul(length).ok_or(Error::Capacity)?)?;
        let refs = checked_bytes::<&[u8]>(length)?;
        let nodes = checked_bytes::<merkle::Digest>(
            length
                .checked_mul(2)
                .and_then(|n| n.checked_sub(1))
                .ok_or(Error::Capacity)?,
        )?;
        bytes
            .checked_add(refs)
            .and_then(|n| n.checked_add(nodes))
            .ok_or(Error::Capacity)?;
        let mut work = PreparationWork {
            borrowed_message_bytes: checked_bytes::<M31>(count)?,
            ..PreparationWork::default()
        };
        let encoder = Encoder::from_code_id(&source.code().code_id()).map_err(Error::Encoder)?;
        let mut columns = Vec::new();
        columns
            .try_reserve_exact(bytes)
            .map_err(|_| Error::Capacity)?;
        columns.resize(bytes, 0);
        work.encoded_columns_bytes = columns.capacity();
        for (row, message) in message.chunks_exact(source.columns()).enumerate() {
            let encoded = encoder.encode_measured(message).map_err(Error::Encoder)?;
            work.encoder_peak_bytes = work.encoder_peak_bytes.max(encoded.work.peak_owned_bytes);
            // A9 §1: all offsets lie within the checked 4*R*N column buffer.
            for (column, value) in encoded.values.iter().enumerate() {
                let offset = column * width + 4 * row;
                columns[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            }
        }
        let mut leaves = Vec::new();
        leaves
            .try_reserve_exact(length)
            .map_err(|_| Error::Capacity)?;
        leaves.extend(columns.chunks_exact(width));
        work.leaf_references_bytes = leaves.capacity() * size_of::<&[u8]>();
        let tree = merkle::Tree::new_with_usage(source.descriptor(), &leaves, usage)
            .map_err(Error::Merkle)?;
        work.merkle_nodes_bytes = tree.owned_bytes();
        work.peak_owned_bytes = work
            .encoded_columns_bytes
            .checked_add(
                work.encoder_peak_bytes.max(
                    work.leaf_references_bytes
                        .checked_add(work.merkle_nodes_bytes)
                        .ok_or(Error::Capacity)?,
                ),
            )
            .ok_or(Error::Capacity)?;
        let source = Source::new(id, ell, m, blowup, tree.root())?;
        Ok(Self {
            source,
            message,
            columns,
            tree,
            work,
        })
    }

    /// Computed context/root; the verifier must still own and check its expected source.
    pub fn source(&self) -> &Source<K> {
        &self.source
    }

    /// Original row-major input, retained by immutable borrow for row functionals.
    pub fn message(&self) -> &'a [M31] {
        self.message
    }

    /// Produce a complete individual response without hashing or changing storage.
    pub fn response(&self, index: u64) -> Result<PreparedColumn<'_>, Error> {
        let siblings = self.tree.path(index).map_err(Error::Merkle)?;
        // Tree checked index < N; construction checked N*width, so these offsets fit.
        let width = 4 * self.source.rows();
        let offset = index as usize * width;
        Ok(PreparedColumn {
            payload: &self.columns[offset..offset + width],
            siblings,
        })
    }

    /// Non-authorizing preparation observations, including complete encoder scratch.
    pub fn work(&self) -> PreparationWork {
        self.work
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_preparation_allocation_sizes() {
        assert_eq!(checked_bytes::<u8>(usize::MAX), Err(Error::Capacity));
        assert_eq!(
            checked_bytes::<merkle::Digest>(usize::MAX),
            Err(Error::Capacity)
        );
        assert_eq!(checked_bytes::<M31>(3), Ok(12));
    }
}

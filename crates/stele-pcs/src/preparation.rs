//! RFC-0010 A9 §§1,6,9: canonical prover storage, with no verifier acceptance.
use crate::{Error, Policy, Source};
use alloc::vec::Vec;
use core::mem::size_of;
use core::sync::atomic::{AtomicUsize, Ordering};
use stele_code::Encoder;
use stele_field::{Serialize, M31};
use stele_hash::mask::{MaskStream, SOURCE_SALT};
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
    borrows: AtomicUsize,
    openings: AtomicUsize,
    mask_polynomial: bool,
    /// RFC-0013 A6: a weight source's lifetime budget and the
    /// row-coefficient vectors its earlier openings revealed.
    lifetime: Option<(usize, Vec<Vec<K>>)>,
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
        Self::from_code_id(id, ell, source.code_id(), message, usage)
    }

    /// Same preparation for any identity `Source::from_code_id` admits (RFC-0010 A3 item 2).
    pub fn from_code_id(
        id: u64,
        ell: u8,
        code: &[u8],
        message: &'a [M31],
        usage: &mut HashUsage,
    ) -> Result<Self, Error> {
        Self::from_code_id_policy(id, ell, code, message, usage, Policy::One)
    }

    /// Same preparation under an explicit source policy (RFC-0010 A14); the committed
    /// columns and root do not depend on the policy.
    pub fn from_code_id_policy(
        id: u64,
        ell: u8,
        code: &[u8],
        message: &'a [M31],
        usage: &mut HashUsage,
        policy: Policy,
    ) -> Result<Self, Error> {
        let source = Source::<K>::from_code_id_policy(id, ell, code, [0; 32], policy)?;
        let rebuild = |root| Source::from_code_id_policy(id, ell, code, root, policy);
        Self::prepare(source, rebuild, message, None, usage)
    }

    /// [`Source::from_code_id_development`] prepared (RFC-0026 A10): the development
    /// tier's Policy 2 source; the committed columns and root are those of Policy 1.
    pub fn from_code_id_development(
        id: u64,
        ell: u8,
        code: &[u8],
        message: &'a [M31],
        usage: &mut HashUsage,
    ) -> Result<Self, Error> {
        let source = Source::<K>::from_code_id_development(id, ell, code, [0; 32])?;
        let rebuild = |root| Source::from_code_id_development(id, ell, code, root);
        Self::prepare(source, rebuild, message, None, usage)
    }

    /// Prepare a version-3 hiding source (RFC-0010 A15) over the full message
    /// `M'` of [`crate::hiding_message`], with leaf salts drawn from `seed`.
    /// The seed must be the one that produced `M'`, fresh and secret (RFC-0013 A2).
    pub fn hiding(
        id: u64,
        ell: u8,
        m: u8,
        blowup: u8,
        message: &'a [M31],
        seed: &[u8; 32],
        usage: &mut HashUsage,
    ) -> Result<Self, Error> {
        let source = Source::<K>::hiding(id, ell, m, blowup, [0; 32])?;
        let rebuild = |root| Source::hiding(id, ell, m, blowup, root);
        Self::prepare(source, rebuild, message, Some(seed), usage)
    }

    /// Prepare a lifetime hiding source (RFC-0013 A6): a weight source
    /// committed once from `seed` and opened at most `budget` times over its
    /// life, once per proof. `revealed` holds the row-coefficient vectors of its
    /// earlier openings, in order; the next opening's rank check covers them all,
    /// and the producer refuses past the budget (`MaskBudget`).
    ///
    /// # Security
    ///
    /// The caller persists the opening count and `revealed` across proofs; a
    /// restored or forked state that reopens an index breaks the budget.
    #[allow(clippy::too_many_arguments)]
    pub fn hiding_lifetime(
        id: u64,
        ell: u8,
        m: u8,
        blowup: u8,
        message: &'a [M31],
        seed: &[u8; 32],
        usage: &mut HashUsage,
        budget: usize,
        revealed: Vec<Vec<K>>,
    ) -> Result<Self, Error> {
        let mut prepared = Self::hiding(id, ell, m, blowup, message, seed, usage)?;
        if !prepared.source.admits_lifetime(budget) {
            return Err(Error::UnsupportedSource);
        }
        if revealed.len() >= budget {
            return Err(Error::MaskBudget);
        }
        prepared.lifetime = Some((budget, revealed));
        Ok(prepared)
    }

    /// The vectors a lifetime source revealed before this preparation.
    pub(crate) fn revealed(&self) -> &[Vec<K>] {
        self.lifetime.as_ref().map_or(&[], |(_, r)| r.as_slice())
    }

    /// Prepare the mask-polynomial source of RFC-0013 A4: a hiding source with
    /// `2D` data rows whose one opening has A4's two-block shape (enforced at the
    /// opening; anything else is `MaskRank`). Its row message is covered by A4's
    /// Lemma 5 instead of A2's rank check; the certificate keeps that check.
    ///
    /// # Security
    ///
    /// The seed must be fresh and used once per `(seed, id)` across all
    /// transcripts: two openings of the same mask at different points reveal
    /// both blocks, and with them the masked sumcheck's witness rounds. The
    /// one-opening counter only covers this object. After a refused opening,
    /// retry with a fresh seed only if nothing derived from this one was
    /// published. `scripts/gates/check.py` quarantines this constructor to
    /// `stele_reductions::zk`.
    pub fn hiding_mask(
        id: u64,
        ell: u8,
        m: u8,
        blowup: u8,
        message: &'a [M31],
        seed: &[u8; 32],
        usage: &mut HashUsage,
    ) -> Result<Self, Error> {
        if (1usize << ell) != 2 * K::DEGREE {
            return Err(Error::UnsupportedSource);
        }
        let mut prepared = Self::hiding(id, ell, m, blowup, message, seed, usage)?;
        prepared.mask_polynomial = true;
        Ok(prepared)
    }

    fn prepare<F: FnOnce(merkle::Digest) -> Result<Source<K>, Error>>(
        source: Source<K>,
        rebuild: F,
        message: &'a [M31],
        seed: Option<&[u8; 32]>,
        usage: &mut HashUsage,
    ) -> Result<Self, Error> {
        let count = source
            .rows()
            .checked_mul(source.columns())
            .ok_or(Error::Capacity)?;
        if message.len() != count {
            return Err(Error::MessageShape);
        }
        let length = source.codeword_len();
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
        let encoder = Encoder::from_code_id(source.code_id()).map_err(Error::Encoder)?;
        let mut columns = Vec::new();
        columns
            .try_reserve_exact(bytes)
            .map_err(|_| Error::Capacity)?;
        columns.resize(bytes, 0);
        work.encoded_columns_bytes = columns.capacity();
        // All rows at once, interleaved (symbol c of row r at c*R + r): the encoder
        // generates each sparse row once (RFC-0010 A4) and its interleaved codeword
        // is exactly the column-major 4*R*N buffer of A9 §1.
        let rows = source.rows();
        let mut transposed: Vec<M31> = Vec::new();
        transposed
            .try_reserve_exact(count)
            .map_err(|_| Error::Capacity)?;
        // Entry `c*R + r` is message entry `r*C + c`; disjoint blocks (task E16-23).
        transposed.resize(count, M31::default());
        let cols = source.columns();
        crate::opening::for_each_block(&mut transposed, |start, chunk| {
            for (i, out) in (start..).zip(chunk) {
                *out = message[(i % rows) * cols + i / rows];
            }
        });
        let encoded = encoder
            .encode_rows_measured(&transposed, rows)
            .map_err(Error::Encoder)?;
        work.encoder_peak_bytes = encoded
            .work
            .peak_owned_bytes
            .checked_add(checked_bytes::<M31>(count)?)
            .ok_or(Error::Capacity)?;
        if encoded.values.len() != rows * length {
            return Err(Error::MessageShape);
        }
        // A15: a hiding leaf is salt || column; other sources have no salt.
        let salt = source.salt_len();
        let mut salts = seed.map(|seed| MaskStream::new(seed, SOURCE_SALT, source.descriptor().id));
        for (leaf, symbols) in columns
            .chunks_exact_mut(width)
            .zip(encoded.values.chunks_exact(rows))
        {
            if let Some(stream) = &mut salts {
                stream.fill(&mut leaf[..salt]);
            }
            for (out, value) in leaf[salt..].chunks_exact_mut(4).zip(symbols) {
                out.copy_from_slice(&value.to_le_bytes());
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
        let source = rebuild(tree.root())?;
        Ok(Self {
            source,
            message,
            columns,
            tree,
            work,
            borrows: AtomicUsize::new(0),
            openings: AtomicUsize::new(0),
            mask_polynomial: false,
            lifetime: None,
        })
    }

    /// Computed context/root; the verifier must still own and check its expected source.
    pub fn source(&self) -> &Source<K> {
        &self.source
    }

    /// Original row-major input, retained by immutable borrow for row functionals.
    /// This is the only accessor; each call is charged as one full R*C read.
    pub fn message(&self) -> &'a [M31] {
        self.borrows.fetch_add(1, Ordering::Relaxed);
        self.message
    }

    /// RFC-0013 A2 item 1: a hiding source admits one opening over its lifetime.
    /// Every attempt counts, through any opening path, even if it later fails.
    /// A lifetime source (A6) admits one opening per preparation, within its budget.
    pub(crate) fn claim_opening(&self) -> Result<(), Error> {
        let earlier = self.revealed().len();
        let budget = self.lifetime.as_ref().map_or(1, |(b, _)| *b);
        if self.source.is_hiding()
            && (self.openings.fetch_add(1, Ordering::Relaxed) > 0 || earlier >= budget)
        {
            return Err(Error::MaskBudget);
        }
        Ok(())
    }

    /// True for an RFC-0013 A4 mask-polynomial source.
    pub(crate) fn is_mask_polynomial(&self) -> bool {
        self.mask_polynomial
    }

    /// RFC-0007 A1 item 4 counter: message() borrows times R*C, an upper bound on reads.
    pub fn message_reads(&self) -> usize {
        self.borrows
            .load(Ordering::Relaxed)
            .saturating_mul(self.message.len())
    }

    /// Produce a complete individual response without hashing or changing storage.
    pub fn response(&self, index: u64) -> Result<PreparedColumn<'_>, Error> {
        let siblings = self.tree.path(index).map_err(Error::Merkle)?;
        // Tree checked index < N; construction checked N*width, so these offsets fit.
        let width = self.source.descriptor().width as usize;
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

//! RFC-0010 A9 §§1,6,9: canonical prover storage, with no verifier acceptance.
use crate::{
    ColumnMaterial, ColumnResponse, Error, HidingUse, HostColumns, Policy, ProverWork, Source,
};
use alloc::borrow::Cow;
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
pub struct PreparedSource<'a, K: ChallengeField, M = HostColumns> {
    source: Source<K>,
    message: &'a [M31],
    material: M,
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

    /// [`Source::from_code_id_development`] prepared (RFC-0026 A11): the development
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
        Self::hiding_with(id, ell, m, blowup, message, seed, usage, Policy::One)
    }

    /// [`Self::hiding`] under `policy` ([`Source::hiding_with`], RFC-0013 A8).
    #[allow(clippy::too_many_arguments)]
    pub fn hiding_with(
        id: u64,
        ell: u8,
        m: u8,
        blowup: u8,
        message: &'a [M31],
        seed: &[u8; 32],
        usage: &mut HashUsage,
        policy: Policy,
    ) -> Result<Self, Error> {
        let source = Source::<K>::hiding_with(id, ell, m, blowup, [0; 32], policy)?;
        let rebuild = |root| Source::hiding_with(id, ell, m, blowup, root, policy);
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
        Self::hiding_lifetime_with(
            id,
            ell,
            m,
            blowup,
            message,
            seed,
            usage,
            budget,
            revealed,
            Policy::One,
        )
    }

    /// [`Self::hiding_lifetime`] under `policy` (RFC-0013 A8).
    #[allow(clippy::too_many_arguments)]
    pub fn hiding_lifetime_with(
        id: u64,
        ell: u8,
        m: u8,
        blowup: u8,
        message: &'a [M31],
        seed: &[u8; 32],
        usage: &mut HashUsage,
        budget: usize,
        revealed: Vec<Vec<K>>,
        policy: Policy,
    ) -> Result<Self, Error> {
        let mut prepared = Self::hiding_with(id, ell, m, blowup, message, seed, usage, policy)?;
        prepared.set_lifetime(budget, revealed)?;
        Ok(prepared)
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
        Self::hiding_mask_with(id, ell, m, blowup, message, seed, usage, Policy::One)
    }

    /// [`Self::hiding_mask`] under `policy` (RFC-0013 A8).
    #[allow(clippy::too_many_arguments)]
    pub fn hiding_mask_with(
        id: u64,
        ell: u8,
        m: u8,
        blowup: u8,
        message: &'a [M31],
        seed: &[u8; 32],
        usage: &mut HashUsage,
        policy: Policy,
    ) -> Result<Self, Error> {
        if 1usize.checked_shl(u32::from(ell)) != Some(2 * K::DEGREE) {
            return Err(Error::UnsupportedSource);
        }
        let mut prepared = Self::hiding_with(id, ell, m, blowup, message, seed, usage, policy)?;
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
        let salts = seed.map(|seed| MaskStream::new(seed, SOURCE_SALT, source.descriptor().id));
        // Leaf `i`'s salt is the stream's bytes `[i·salt, (i + 1)·salt)`, the same as
        // reading the stream leaf by leaf: leaves fill independently (E16-24).
        let mut slots: Vec<&mut [u8]> = columns.chunks_exact_mut(width).collect();
        crate::opening::for_each_block(&mut slots, |start, block| {
            for (index, leaf) in (start..).zip(block.iter_mut()) {
                if let Some(stream) = &salts {
                    stream.fill_at((index * salt) as u64, &mut leaf[..salt]);
                }
                let symbols = &encoded.values[index * rows..(index + 1) * rows];
                for (out, value) in leaf[salt..].chunks_exact_mut(4).zip(symbols) {
                    out.copy_from_slice(&value.to_le_bytes());
                }
            }
        });
        drop(slots);
        let mut leaves = Vec::new();
        leaves
            .try_reserve_exact(length)
            .map_err(|_| Error::Capacity)?;
        leaves.extend(columns.chunks_exact(width));
        work.leaf_references_bytes = leaves.capacity() * size_of::<&[u8]>();
        // Each tree level's digests are independent: hashed in blocks (E16-24).
        let tree = merkle::Tree::new_with_usage_filled(
            source.descriptor(),
            &leaves,
            usage,
            &|out, digest| {
                crate::opening::for_each_block(out, |start, block| {
                    for (index, slot) in (start..).zip(block) {
                        *slot = digest(index);
                    }
                })
            },
        )
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
        let material = HostColumns {
            descriptor: source.descriptor(),
            columns,
            tree,
            work,
        };
        Ok(Self::from_material(source, message, material))
    }

    /// Produce an individual response borrowing the existing scalar storage.
    pub fn response(&self, index: u64) -> Result<PreparedColumn<'_>, Error> {
        self.material.response(index)
    }

    /// Observed host preparation capacities.
    pub fn work(&self) -> PreparationWork {
        self.material.work
    }
}

impl<'a, K: ChallengeField, M: ColumnMaterial> PreparedSource<'a, K, M> {
    fn from_material(source: Source<K>, message: &'a [M31], material: M) -> Self {
        Self {
            source,
            message,
            material,
            borrows: AtomicUsize::new(0),
            openings: AtomicUsize::new(0),
            mask_polynomial: false,
            lifetime: None,
        }
    }

    /// Prepare a balanced development hiding source from the exact physical message.
    /// The factory observes the host-derived A15 context, seed and actual local hash
    /// usage. The host retains all A2/A4/A6 row, rank and lifetime decisions.
    #[allow(clippy::too_many_arguments)]
    pub fn hiding_material<F>(
        id: u64,
        ell: u8,
        m: u8,
        message: &'a [M31],
        seed: &[u8; 32],
        purpose: HidingUse<K>,
        usage: &mut HashUsage,
        prepare: F,
    ) -> Result<Self, Error>
    where
        F: FnOnce(&Source<K>, &'a [M31], &[u8; 32], &mut HashUsage) -> Result<M, Error>,
    {
        let context = |root| Source::<K>::hiding_with(id, ell, m, 2, root, Policy::Two);
        let source = context([0; 32])?;
        if source.rows().checked_mul(source.columns()) != Some(message.len()) {
            return Err(Error::MessageShape);
        }
        if matches!(purpose, HidingUse::MaskPolynomial) && source.rows() / 2 != 2 * K::DEGREE {
            return Err(Error::UnsupportedSource);
        }
        // A16 charges one full binary Merkle tree. The factory only sees its own
        // local observation, including work before failure, never the caller's totals.
        let mut local = HashUsage::default();
        let material = prepare(&source, message, seed, &mut local);
        let full_tree = source
            .descriptor()
            .count
            .checked_mul(2)
            .and_then(|n| n.checked_sub(1))
            .ok_or(Error::Capacity)?;
        let hashes = local.hash_evaluations;
        local.hash_evaluations = 0;
        if local != HashUsage::default()
            || hashes > full_tree
            || (material.is_ok() && hashes != full_tree)
        {
            return Err(Error::Merkle(merkle::Error::InvalidTree));
        }
        usage.hash_evaluations = usage
            .hash_evaluations
            .checked_add(hashes)
            .ok_or(Error::Merkle(merkle::Error::UsageOverflow))?;
        let material = material?;
        if material.descriptor() != source.descriptor() {
            return Err(Error::CertificateContext);
        }
        let mut result = Self::from_material(context(material.root())?, message, material);
        match purpose {
            HidingUse::Single => {}
            HidingUse::MaskPolynomial => result.mask_polynomial = true,
            HidingUse::Lifetime { budget, revealed } => result.set_lifetime(budget, revealed)?,
        }
        Ok(result)
    }

    fn set_lifetime(&mut self, budget: usize, revealed: Vec<Vec<K>>) -> Result<(), Error> {
        if !self.source.admits_lifetime(budget) {
            return Err(Error::UnsupportedSource);
        }
        if revealed.len() >= budget {
            return Err(Error::MaskBudget);
        }
        self.lifetime = Some((budget, revealed));
        Ok(())
    }

    /// The vectors a lifetime source revealed before this preparation.
    pub(crate) fn revealed(&self) -> &[Vec<K>] {
        self.lifetime.as_ref().map_or(&[], |(_, r)| r.as_slice())
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

    /// Append exactly one drawn column and path; only the verifier authenticates their contents.
    pub(crate) fn append_response(
        &self,
        index: u64,
        proof: &mut Vec<u8>,
        work: &mut ProverWork,
    ) -> Result<(), Error> {
        use crate::work::{add, bytes};
        if index >= self.source.descriptor().count {
            return Err(Error::Merkle(merkle::Error::InvalidIndex));
        }
        let (payload, siblings): ColumnResponse<'_> = self.material.selected(index)?;
        if u64::try_from(payload.len()).ok() != Some(self.source.descriptor().width) {
            return Err(Error::Merkle(merkle::Error::InvalidLeaf));
        }
        if siblings.len() != self.source.path_height() {
            return Err(Error::Merkle(merkle::Error::InvalidPath));
        }
        let path_bytes = bytes(&siblings)?;
        let col_bytes = match &payload {
            Cow::Owned(buffer) => bytes(buffer)?,
            Cow::Borrowed(_) => 0,
        };
        work.path_peak_bytes = work.path_peak_bytes.max(path_bytes);
        work.peak_owned_bytes = work
            .peak_owned_bytes
            .max(add(bytes(proof)?, add(path_bytes, col_bytes)?)?);
        work.responses = add(work.responses, 1)?;
        work.column_bytes_copied = add(work.column_bytes_copied, payload.len())?;
        proof.extend_from_slice(&payload);
        for sibling in siblings {
            work.path_bytes_copied = add(work.path_bytes_copied, sibling.len())?;
            proof.extend_from_slice(&sibling);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// E16-24 follow-up: a prepared hiding source's leaf salts are the salt stream read
    /// leaf by leaf (`MaskStream::fill`, `salt` bytes each, in leaf order).
    #[test]
    fn matches_reference_sequential_leaf_salts() {
        let (ell, m, id, seed) = (3u8, 9u8, 41u64, [9u8; 32]);
        let x: Vec<M31> = (0..1usize << (ell + m))
            .map(|i| M31::from_u64(i as u64 % 251))
            .collect();
        let message = crate::hiding_message(id, ell, m, &x, &seed).expect("message");
        let prepared = PreparedSource::<stele_field::QM31>::hiding(
            id,
            ell,
            m,
            2,
            &message,
            &seed,
            &mut HashUsage::default(),
        )
        .expect("prepare");
        let salt = prepared.source.salt_len();
        let width = usize::try_from(prepared.source.descriptor().width).expect("width");
        assert!(salt > 0);
        let mut stream = MaskStream::new(&seed, SOURCE_SALT, prepared.source.descriptor().id);
        let mut expected = alloc::vec![0u8; salt];
        for leaf in prepared.material.columns.chunks_exact(width) {
            stream.fill(&mut expected);
            assert_eq!(&leaf[..salt], expected.as_slice());
        }
    }

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

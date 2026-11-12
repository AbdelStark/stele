//! RFC-0012 A3 — byte-column and child-root authentication, not PCS validity.
use crate::HashUsage;
use alloc::vec::Vec;

/// Full BLAKE3-256 output; truncated roots/siblings are not representable.
pub type Digest = [u8; 32];
/// Writes one tree level: `fill(out, digest)` sets `out[i] = digest(i)` for every `i`
/// ([`Tree::new_with_usage_filled`]).
pub type LevelFill<'a> = dyn Fn(&mut [Digest], &(dyn Fn(usize) -> Digest + Sync)) + 'a;
/// Closed leaf domains from RFC-0012 A3.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    /// One fixed-width byte column; field decoding belongs to the consumer.
    Columns = 0,
    /// One 32-byte child root, ordered by the plan's shard index.
    Roots = 2,
}
/// Verifier-owned tree context, derived/checked against the authenticated plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Descriptor {
    /// Byte columns or child roots.
    pub kind: Kind,
    /// Tree role within the plan.
    pub id: u64,
    /// Real leaf count, excluding absent padding.
    pub count: u64,
    /// Exact payload width in bytes.
    pub width: u64,
}
/// Authentication or construction failure under RFC-0012 A3.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Empty/oversized tree, zero width, or non-32-byte child roots.
    InvalidTree,
    /// Payload count or width disagrees with the descriptor.
    InvalidLeaf,
    /// Requested index is outside the real leaves.
    InvalidIndex,
    /// Path depth disagrees with the descriptor.
    InvalidPath,
    /// Empty, incomplete, duplicate or unordered batch.
    InvalidBatch,
    /// Reconstructed digest differs from the expected root.
    RootMismatch,
    /// Construction/path storage cannot be represented or allocated.
    Capacity,
    /// A local work counter would overflow; abort before unrecorded hashing.
    UsageOverflow,
}
/// Borrowed payload and exact bottom-up sibling path; no proof-supplied index.
#[derive(Clone, Copy, Debug)]
pub struct Opening<'a> {
    /// Authenticated bytes; canonical field decoding is a consumer obligation.
    pub payload: &'a [u8],
    /// Full digests, one per level, nearest sibling first.
    pub siblings: &'a [Digest],
}
impl Descriptor {
    fn height(self) -> Result<u32, Error> {
        if self.count == 0
            || self.count > 1 << 63
            || self.width == 0
            || (self.kind == Kind::Roots && self.width != 32)
        {
            return Err(Error::InvalidTree);
        }
        Ok(64 - (self.count - 1).leading_zeros())
    }
    fn start(self, tag: u8) -> blake3::Hasher {
        let mut h = blake3::Hasher::new();
        for bytes in [
            &[tag][..],
            b"stele/v0.1/merkle",
            &[self.kind as u8],
            &self.id.to_le_bytes(),
            &self.count.to_le_bytes(),
            &self.width.to_le_bytes(),
        ] {
            h.update(bytes);
        }
        h
    }
    fn leaf(self, index: u64, payload: &[u8]) -> Digest {
        let mut h = self.start(self.kind as u8);
        h.update(&index.to_le_bytes());
        h.update(&[u8::from(index < self.count)]);
        h.update(payload);
        *h.finalize().as_bytes()
    }
    fn node(self, level: u32, index: u64, left: &Digest, right: &Digest) -> Digest {
        let mut h = self.start(1);
        h.update(&level.to_le_bytes());
        h.update(&index.to_le_bytes());
        h.update(left);
        h.update(right);
        *h.finalize().as_bytes()
    }
    fn shape(self, index: u64, opening: Opening<'_>, height: u32) -> Result<(), Error> {
        if index >= self.count {
            return Err(Error::InvalidIndex);
        }
        if u64::try_from(opening.payload.len()).ok() != Some(self.width) {
            return Err(Error::InvalidLeaf);
        }
        if opening.siblings.len() != height as usize {
            return Err(Error::InvalidPath);
        }
        Ok(())
    }
    fn authenticate(
        self,
        root: &Digest,
        mut index: u64,
        opening: Opening<'_>,
        usage: &mut HashUsage,
    ) -> Result<(), Error> {
        // A3: validated paths have at most 63 siblings; authentication hashes all.
        usage
            .hashes(1 + opening.siblings.len() as u64)
            .map_err(|_| Error::UsageOverflow)?;
        let mut current = self.leaf(index, opening.payload);
        for (depth, sibling) in opening.siblings.iter().enumerate() {
            let (left, right) = if index & 1 == 0 {
                (&current, sibling)
            } else {
                (sibling, &current)
            };
            // RFC-0012 A3: shape validation limits depth to 63 before authentication.
            current = self.node(depth as u32 + 1, index >> 1, left, right);
            index >>= 1;
        }
        if current == *root {
            Ok(())
        } else {
            Err(Error::RootMismatch)
        }
    }
}
/// Authenticate one real leaf at the caller's expected descriptor/root/index.
/// No allocation, transcript sampling, field decoding or codeword check occurs.
pub fn verify(
    spec: Descriptor,
    root: &Digest,
    index: u64,
    opening: Opening<'_>,
) -> Result<(), Error> {
    verify_with_usage(spec, root, index, opening, &mut HashUsage::default())
}
/// Authenticate one path and retain actual local hash work on success or failure (A10).
/// The observation is not a proof record or a bound on adversarial queries.
pub fn verify_with_usage(
    spec: Descriptor,
    root: &Digest,
    index: u64,
    opening: Opening<'_>,
    usage: &mut HashUsage,
) -> Result<(), Error> {
    let height = spec.height()?;
    spec.shape(index, opening, height)?;
    spec.authenticate(root, index, opening, usage)
}
/// Authenticate all requested leaves, in strict increasing index order, or fail.
/// The caller must separately establish the PCS query schedule and child-root use.
pub fn verify_batch(
    spec: Descriptor,
    root: &Digest,
    indices: &[u64],
    openings: &[Opening<'_>],
) -> Result<(), Error> {
    verify_batch_with_usage(spec, root, indices, openings, &mut HashUsage::default())
}
/// Authenticate a sorted unique batch, retaining work before any failure (A10).
/// PCS repeated-query schedules must instead use individual paths in draw order.
pub fn verify_batch_with_usage(
    spec: Descriptor,
    root: &Digest,
    indices: &[u64],
    openings: &[Opening<'_>],
    usage: &mut HashUsage,
) -> Result<(), Error> {
    let height = spec.height()?;
    if indices.is_empty()
        || indices.len() != openings.len()
        || u64::try_from(indices.len()).map_err(|_| Error::InvalidBatch)? > spec.count
        || indices.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(Error::InvalidBatch);
    }
    for (&index, &opening) in indices.iter().zip(openings) {
        spec.shape(index, opening, height)?;
    }
    for (&index, &opening) in indices.iter().zip(openings) {
        spec.authenticate(root, index, opening, usage)?;
    }
    Ok(())
}
/// Stored digest tree for producing paths; payloads remain caller-owned.
/// The private representation is nonempty and stores complete levels bottom-up.
pub struct Tree {
    spec: Descriptor,
    padded: usize,
    nodes: Vec<Digest>,
}
impl Tree {
    /// Hash exactly the descriptor's real payloads and canonical absent padding.
    pub fn new(spec: Descriptor, leaves: &[&[u8]]) -> Result<Self, Error> {
        Self::new_with_usage(spec, leaves, &mut HashUsage::default())
    }
    /// Construct a tree, reporting every real/padding leaf and node hash (A10).
    /// Descriptor, allocation and count checks precede all hashing.
    pub fn new_with_usage(
        spec: Descriptor,
        leaves: &[&[u8]],
        usage: &mut HashUsage,
    ) -> Result<Self, Error> {
        Self::new_with_usage_filled(spec, leaves, usage, &|out, digest| {
            for (index, slot) in out.iter_mut().enumerate() {
                *slot = digest(index);
            }
        })
    }
    /// [`Tree::new_with_usage`] with each level written by `fill(out, digest)`, which
    /// must set `out[i] = digest(i)` for every `i`, in any order and on any thread (a
    /// prover passes its work pool; E16-24). The digests, root and usage are those
    /// of the sequential build; a `fill` that skips an entry yields another root,
    /// which no verifier accepts for the committed data.
    pub fn new_with_usage_filled(
        spec: Descriptor,
        leaves: &[&[u8]],
        usage: &mut HashUsage,
        fill: &LevelFill<'_>,
    ) -> Result<Self, Error> {
        let height = spec.height()?;
        if u64::try_from(leaves.len()).ok() != Some(spec.count)
            || leaves
                .iter()
                .any(|leaf| u64::try_from(leaf.len()).ok() != Some(spec.width))
        {
            return Err(Error::InvalidLeaf);
        }
        let padded = 1usize.checked_shl(height).ok_or(Error::Capacity)?;
        let total = padded.checked_add(padded - 1).ok_or(Error::Capacity)?;
        let hashes = u64::try_from(total).map_err(|_| Error::Capacity)?;
        let mut nodes = Vec::new();
        nodes
            .try_reserve_exact(total)
            .map_err(|_| Error::Capacity)?;
        usage.hashes(hashes).map_err(|_| Error::UsageOverflow)?;
        // All indices are below total, already checked to fit u64; no fallible work remains.
        nodes.resize(total, [0; 32]);
        fill(&mut nodes[..padded], &|index| {
            spec.leaf(index as u64, leaves.get(index).copied().unwrap_or(&[]))
        });
        let (mut offset, mut width) = (0, padded);
        for level in 1..=height {
            let (done, rest) = nodes.split_at_mut(offset + width);
            let children = &done[offset..];
            fill(&mut rest[..width / 2], &|index| {
                spec.node(
                    level,
                    index as u64,
                    &children[2 * index],
                    &children[2 * index + 1],
                )
            });
            offset += width;
            width /= 2;
        }
        Ok(Self {
            spec,
            padded,
            nodes,
        })
    }
    /// Root of this nonempty, fully constructed tree.
    pub fn root(&self) -> Digest {
        self.nodes[self.nodes.len() - 1]
    }
    /// Actual owned digest-vector capacity in bytes (A10 resource observations).
    /// Excludes borrowed payloads, the Tree value, allocator metadata and process memory.
    pub fn owned_bytes(&self) -> usize {
        self.nodes.capacity() * core::mem::size_of::<Digest>()
    }
    /// Produce the exact sibling path for a real leaf; padding cannot be opened.
    pub fn path(&self, index: u64) -> Result<Vec<Digest>, Error> {
        if index >= self.spec.count {
            return Err(Error::InvalidIndex);
        }
        let mut index = usize::try_from(index).map_err(|_| Error::Capacity)?;
        let mut path = Vec::new();
        path.try_reserve_exact(self.spec.height()? as usize)
            .map_err(|_| Error::Capacity)?;
        let (mut offset, mut width) = (0, self.padded);
        while width > 1 {
            path.push(self.nodes[offset + (index ^ 1)]);
            offset += width;
            width /= 2;
            index >>= 1;
        }
        Ok(path)
    }
}

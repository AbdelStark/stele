//! RFC-0025 source §4: whole-file SHA-256 and bounded, revalidated consuming reads.
use super::{reserved, Error, SourceFile};
use alloc::vec::Vec;
use sha2::{Digest, Sha256};

pub(super) const CHUNK: u64 = 65536;

/// Original file bytes verified against a complete File declaration.
/// A private integrity index revalidates each later read; it is neither a
/// canonical frame nor a proof commitment. Container, selection, configuration
/// and independently expected source authority checks remain required.
/// ```compile_fail
/// fn change(s: &mut stele_cqis::model::SourceSnapshot<'_>) { s.chunks.clear(); }
/// ```
pub struct SourceSnapshot<'a> {
    file: SourceFile<'a>,
    chunks: Vec<[u8; 32]>,
}

impl<'a> SourceSnapshot<'a> {
    /// Hash every original byte and check exact length, EOF and expected SHA-256.
    /// `max_index_bytes` bounds retained digest bytes (32 per 65536-byte chunk),
    /// checked before I/O or allocation. The temporary buffer is at most 65536
    /// bytes; allocator bookkeeping is excluded. Short reads are supported.
    /// No complete file or tensor payload is retained by this object.
    pub fn read_from<E>(
        file: SourceFile<'a>,
        max_index_bytes: usize,
        mut read: impl FnMut(&mut [u8]) -> Result<usize, E>,
    ) -> Result<Self, Error> {
        let count = usize::try_from(file.length().div_ceil(CHUNK)).map_err(|_| Error::Capacity)?;
        let bytes = count.checked_mul(32).ok_or(Error::Capacity)?;
        if bytes > max_index_bytes {
            return Err(Error::Capacity);
        }
        let mut chunks = reserved(count)?;
        let mut buffer = buffer(file.length().min(CHUNK) as usize)?;
        let mut whole = Sha256::new();
        let mut offset = 0;
        while offset < file.length() {
            let length = (file.length() - offset).min(CHUNK) as usize;
            let raw = &mut buffer[..length];
            fill(raw, offset, &mut |_, out| read(out))?;
            // Both hashes consume exactly the same immutable slice (source §4).
            whole.update(&*raw);
            chunks.push(Sha256::digest(&*raw).into());
            offset = offset.checked_add(length as u64).ok_or(Error::FileLength)?;
        }
        let n = read(&mut [0; 1]).map_err(|_| Error::Read)?;
        if n > 1 {
            return Err(Error::Read);
        }
        if n != 0 {
            return Err(Error::FileLength);
        }
        let digest: [u8; 32] = whole.finalize().into();
        if digest != file.sha256() {
            return Err(Error::FileDigest);
        }
        Ok(Self { file, chunks })
    }

    /// The complete original-file declaration whose bytes were verified.
    pub fn file(&self) -> &SourceFile<'a> {
        &self.file
    }
    /// Number of fixed 65536-byte chunks, with a possibly shorter final chunk.
    pub fn chunk_count(&self) -> u64 {
        self.chunks.len() as u64
    }
    /// Retained integrity digest bytes, excluding allocator bookkeeping.
    pub fn index_bytes(&self) -> usize {
        self.chunks.len() * 32
    }

    /// Read and revalidate one complete chunk at checked absolute file offsets.
    /// No bytes escape until their SHA-256 matches the initial whole-file pass.
    /// Short reads are supported; each returned owned buffer is at most 65536
    /// bytes. The caller controls how many completed chunks it retains.
    pub fn chunk<E>(
        &self,
        index: u64,
        mut read_at: impl FnMut(u64, &mut [u8]) -> Result<usize, E>,
    ) -> Result<SourceChunk, Error> {
        let ordinal = usize::try_from(index).map_err(|_| Error::SourceOffset)?;
        let expected = self.chunks.get(ordinal).ok_or(Error::SourceOffset)?;
        let offset = index.checked_mul(CHUNK).ok_or(Error::SourceOffset)?;
        let length = self
            .file
            .length()
            .checked_sub(offset)
            .ok_or(Error::SourceOffset)?
            .min(CHUNK) as usize;
        let mut bytes = buffer(length)?;
        fill(&mut bytes, offset, &mut read_at)?;
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        if &digest != expected {
            return Err(Error::SnapshotData);
        }
        Ok(SourceChunk {
            bytes,
            offset,
            file_sha256: self.file.sha256(),
        })
    }
}

/// Immutable owned bytes from one revalidated original-file chunk.
/// ```compile_fail
/// fn change(c: &mut stele_cqis::model::SourceChunk) { c.bytes.clear(); }
/// ```
pub struct SourceChunk {
    bytes: Vec<u8>,
    offset: u64,
    file_sha256: [u8; 32],
}
impl SourceChunk {
    /// All bytes in this checked chunk.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Absolute offset in the original file.
    pub fn offset(&self) -> u64 {
        self.offset
    }
    /// Verified complete-file SHA-256, not a partial chunk digest.
    pub fn file_sha256(&self) -> [u8; 32] {
        self.file_sha256
    }
}

fn buffer(length: usize) -> Result<Vec<u8>, Error> {
    let mut out = reserved(length)?;
    out.resize(length, 0);
    Ok(out)
}

fn fill<E>(
    out: &mut [u8],
    base: u64,
    read_at: &mut impl FnMut(u64, &mut [u8]) -> Result<usize, E>,
) -> Result<(), Error> {
    let mut filled = 0;
    while filled < out.len() {
        let offset = base.checked_add(filled as u64).ok_or(Error::SourceOffset)?;
        let n = read_at(offset, &mut out[filled..]).map_err(|_| Error::Read)?;
        if n > out.len() - filled {
            return Err(Error::Read);
        }
        if n == 0 {
            return Err(Error::FileLength);
        }
        filled += n;
    }
    Ok(())
}

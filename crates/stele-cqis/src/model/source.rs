//! RFC-0025 source §§1,3–4: typed Source/Assets frames and checked file snapshots.
use super::{
    codec::{reserved, Reader},
    Error,
};
use alloc::vec::Vec;
mod file;
pub use file::SourceFile;
mod assets;
pub use assets::Assets;
mod snapshot;
pub use snapshot::{SourceChunk, SourceSnapshot};
mod container;
mod json;
pub use container::{SourceContainer, SourceTensor};

const PREFIX: &[u8] = b"stele/v0.1/cqis/source";
const LIMIT: usize = 1 << 29;
const INDEX_LIMIT: u64 = 100000000;

/// Complete checked Source metadata, borrowing its immutable original frame.
/// Whole-file hashes, container/index/selection checks and source authority remain
/// required before this declaration can authorize any source tensor view.
/// ```compile_fail
/// fn change(s: &mut stele_cqis::model::Source<'_>) { s.files.clear(); }
/// ```
#[derive(Debug, Eq, PartialEq)]
pub struct Source<'a> {
    raw: &'a [u8],
    index: Option<SourceFile<'a>>,
    files: Vec<SourceFile<'a>>,
    identity: [u8; 33],
    frame_identity: [u8; 32],
    total_length: u64,
}
impl<'a> Source<'a> {
    /// Check the complete closed Source frame without reading any described file.
    pub fn decode(raw: &'a [u8]) -> Result<Self, Error> {
        if raw.len() > LIMIT {
            return Err(Error::Capacity);
        }
        let mut r = Reader(raw);
        r.prefix(PREFIX)?;
        let kind = r.u8()?;
        let (index, files, total_length) = match kind {
            0 => {
                let file = SourceFile::read(&mut r)?;
                let mut files = reserved(1)?;
                files.push(file);
                (None, files, file.length())
            }
            1 => {
                let index = SourceFile::read(&mut r)?;
                if !index.name().ends_with(".json") {
                    return Err(Error::SourceIndex);
                }
                if index.length() > INDEX_LIMIT {
                    return Err(Error::Capacity);
                }
                let (files, size) =
                    file::files(&mut r, Some(index.length() / 16), Some(index.length()))?;
                if files.iter().any(|f| f.name() == index.name()) {
                    return Err(Error::FileSet);
                }
                let total = index.length().checked_add(size).ok_or(Error::FileLength)?;
                (Some(index), files, total)
            }
            _ => return Err(Error::SourceKind),
        };
        if files.is_empty() || files.iter().any(|f| !f.name().ends_with(".safetensors")) {
            return Err(Error::SourceFiles);
        }
        r.end()?;
        let frame_identity = *blake3::hash(raw).as_bytes();
        let mut identity = [0; 33];
        identity[0] = kind;
        let digest = if kind == 0 {
            files.first().ok_or(Error::SourceFiles)?.sha256()
        } else {
            frame_identity
        };
        identity[1..].copy_from_slice(&digest);
        Ok(Self {
            raw,
            index,
            files,
            identity,
            frame_identity,
            total_length,
        })
    }
    /// Complete parsing followed by an expected BLAKE3 hash of the entire Source
    /// frame. This binds file labels as well as the separate typed checkpoint id.
    pub fn decode_expected_frame(expected: &[u8; 32], raw: &'a [u8]) -> Result<Self, Error> {
        let source = Self::decode(raw)?;
        if &source.frame_identity != expected {
            return Err(Error::Identity);
        }
        Ok(source)
    }
    /// Exact complete canonical Source bytes.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.raw
    }
    /// Single-file=0 or indexed-shard=1; no inferred kind or fallback.
    pub fn kind(&self) -> u8 {
        self.identity[0]
    }
    /// Original index declaration, present only for kind 1.
    pub fn index(&self) -> Option<&SourceFile<'a>> {
        self.index.as_ref()
    }
    /// The single checkpoint or all sorted shards; the index is separate.
    pub fn files(&self) -> &[SourceFile<'a>] {
        &self.files
    }
    /// Kind byte followed by single-file SHA-256 or H(Source) for an indexed bundle.
    /// Single-file renaming preserves this identity; the full Source frame changes.
    pub fn identity(&self) -> [u8; 33] {
        self.identity
    }
    /// BLAKE3 of the entire Source frame, including every exact file label.
    pub fn frame_identity(&self) -> [u8; 32] {
        self.frame_identity
    }
    /// Checked sum of original file lengths, including the index when present.
    pub fn total_length(&self) -> u64 {
        self.total_length
    }
}

//! RFC-0025 source §4: immutable checked bytes restricted to a completed view.
use super::{Error, SourceFile, SourceSnapshot, CHUNK};
use crate::model::SourceChunk;

/// Borrowed raw tensor or auxiliary extent from a completed SourcePackage.
/// Every consuming read must revalidate the original snapshot chunk.
/// ```compile_fail
/// fn change(v: &mut stele_cqis::model::SourceView<'_, '_>) { v.offset = 0; }
/// ```
pub struct SourceView<'s, 'a> {
    snapshot: &'s SourceSnapshot<'a>,
    offset: u64,
    length: u64,
}
impl<'s, 'a> SourceView<'s, 'a> {
    pub(super) fn new(snapshot: &'s SourceSnapshot<'a>, offset: u64, length: u64) -> Self {
        Self {
            snapshot,
            offset,
            length,
        }
    }
    /// Original verified file containing this view.
    pub fn file(&self) -> &SourceFile<'a> {
        self.snapshot.file()
    }
    /// Absolute start in the original file, before source transforms.
    pub fn offset(&self) -> u64 {
        self.offset
    }
    /// Complete raw extent of this tensor or auxiliary file.
    pub fn length(&self) -> u64 {
        self.length
    }
    /// Revalidate the whole underlying snapshot chunk, returning only this view's
    /// bytes starting at a relative offset. A result ends at the chunk or view
    /// boundary. Offsets outside the view reject before allocation or reader calls.
    pub fn chunk<E>(
        &self,
        relative: u64,
        mut read_at: impl FnMut(&str, u64, &mut [u8]) -> Result<usize, E>,
    ) -> Result<SourceSlice, Error> {
        if relative >= self.length {
            return Err(Error::SourceOffset);
        }
        let absolute = self
            .offset
            .checked_add(relative)
            .ok_or(Error::SourceOffset)?;
        let chunk = self.snapshot.chunk(absolute / CHUNK, |offset, out| {
            read_at(self.file().name(), offset, out)
        })?;
        let start = usize::try_from(absolute - chunk.offset()).map_err(|_| Error::SourceOffset)?;
        let available = chunk
            .as_bytes()
            .len()
            .checked_sub(start)
            .ok_or(Error::SourceOffset)?;
        let length = (self.length - relative).min(available as u64) as usize;
        if length == 0 {
            return Err(Error::SourceOffset);
        }
        Ok(SourceSlice {
            chunk,
            start,
            end: start + length,
            offset: relative,
        })
    }
}
/// Owned immutable bytes confined to a checked source view's extent.
/// ```compile_fail
/// fn change(s: &mut stele_cqis::model::SourceSlice) { s.start = 0; }
/// ```
pub struct SourceSlice {
    chunk: SourceChunk,
    start: usize,
    end: usize,
    offset: u64,
}
impl SourceSlice {
    /// Checked bytes, excluding all surrounding header and other-tensor bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.chunk.as_bytes()[self.start..self.end]
    }
    /// Starting offset relative to the owning tensor or auxiliary view.
    pub fn offset(&self) -> u64 {
        self.offset
    }
}

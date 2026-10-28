//! RFC-0010 A4 — exact live heap-capacity accounting, excluding caller buffers.
use crate::{reserved, Error};
use alloc::vec::Vec;

#[derive(Default)]
pub(crate) struct Memory {
    live: usize,
    peak: usize,
}
impl Memory {
    pub(crate) fn add(&mut self, bytes: usize) -> Result<(), Error> {
        self.live = self.live.checked_add(bytes).ok_or(Error::Capacity)?;
        self.peak = self.peak.max(self.live);
        Ok(())
    }
    pub(crate) fn remove(&mut self, bytes: usize) {
        // Every removal follows one accounted owned allocation in this module's callers.
        self.live -= bytes;
    }
    pub(crate) fn reserve<T>(&mut self, len: usize) -> Result<Vec<T>, Error> {
        let values = reserved(len)?;
        self.add(bytes(&values))?;
        Ok(values)
    }
    pub(crate) fn peak(&self) -> usize {
        self.peak
    }
}
pub(crate) fn bytes<T>(values: &Vec<T>) -> usize {
    values.capacity() * size_of::<T>()
}

/// An exact encoding plus observed live heap-capacity peak for this invocation.
/// Excludes caller-owned buffers, stack, allocator bookkeeping and runtime memory.
pub struct Encoding<K> {
    /// Complete canonical codeword, or requested values for a column query.
    pub word: Vec<K>,
    /// Peak owned heap payload, including the retained graph and base transforms.
    pub peak_owned_heap_bytes: usize,
}

//! RFC-0010 A5 — descriptive observations, never encoder or PCS authority.
use crate::{reserved, Error};
use alloc::vec::Vec;

/// Logical work and actual owned vector capacities for one successful operation.
/// Excludes borrowed input, stack, allocator metadata and process/runtime memory.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EncoderWork {
    /// Peak sum of live owned Vec capacities, in bytes, including all overlap.
    pub peak_owned_bytes: usize,
    /// Actual fixed 74-byte setup hash calls, including rejection draws.
    pub hash_blocks: u64,
    /// Successfully generated sparse rows, including rows applied to zero values.
    pub generated_rows: u64,
    /// Base-limb additions in the sparse scatter loops, including zero edges.
    pub sparse_limb_additions: u64,
    /// Base-limb products in the sparse scatter loops, including zero edges.
    pub sparse_limb_products: u64,
    /// K slots explicitly initialized to zero (not allocator or machine writes).
    pub initialized_symbols: u64,
    /// K slots logically copied, including base and selected-column copies.
    pub copied_symbols: u64,
    /// Circle encodings executed, including a recursive base.
    pub circle_calls: u64,
    /// K additions/subtractions in Circle butterflies; excludes twiddle work.
    pub circle_transform_additions: u64,
    /// K products in Circle butterflies/normalization; excludes twiddle work.
    pub circle_transform_products: u64,
    /// Constructed base-field twiddle values, across both transforms.
    pub twiddle_elements: u64,
    /// Base-field prefix products allocated during twiddle inversion.
    pub inverse_prefix_elements: u64,
    /// Maximum live expander recursion frames; does not bound compiler stack bytes.
    pub max_recursive_frames: u8,
}
/// Canonical encoded values or requested coordinates, with non-authoritative work.
pub struct MeasuredEncoding<K> {
    /// Complete word for encode, or ordered values for a column query.
    pub values: Vec<K>,
    /// Observations from the same execution that produced these values.
    pub work: EncoderWork,
}
#[derive(Default)]
pub(crate) struct Measurement {
    pub(crate) work: EncoderWork,
    live: usize,
}
impl Measurement {
    pub(crate) fn reserve<T>(&mut self, len: usize) -> Result<Vec<T>, Error> {
        let values = reserved(len)?;
        self.live = self
            .live
            .checked_add(bytes(&values))
            .ok_or(Error::Capacity)?;
        self.work.peak_owned_bytes = self.work.peak_owned_bytes.max(self.live);
        Ok(values)
    }
    pub(crate) fn release(&mut self, bytes: usize) {
        // A5 liveness invariant: every release matches a currently owned reservation.
        self.live -= bytes;
    }
}
pub(crate) fn bytes<T>(values: &Vec<T>) -> usize {
    // Vec guarantees capacity*size fits its allocation layout; ZST payload is zero.
    values.capacity() * size_of::<T>()
}

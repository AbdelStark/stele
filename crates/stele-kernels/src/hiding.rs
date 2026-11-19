//! RFC-0014 A5. Untrusted producer buffers for byte-4 Circle columns and Merkle paths.
use crate::{Backend, SourceGeometry, M31, QM31};
use alloc::vec::Vec;

/// Symbols in physical row order. The PCS producer prepends the RFC-0013 source salt.
pub struct SourceColumn {
    pub symbols: Vec<M31>,
    pub siblings: Vec<[u8; 32]>,
}

/// A proof-local original supports the certificate visit and the opening revisit.
/// The host owns the original seed, root comparison, query order and authentication.
pub trait HidingBackend: Backend<QM31> {
    type Columns<'s>
    where
        Self: 's;

    /// Count completed leaf and node hashes, including levels completed before a later error.
    fn prepare_columns<'s>(
        &'s self,
        geometry: SourceGeometry,
        original: &Self::Original<'_>,
        seed: &[u8; 32],
        hashes: &mut u64,
    ) -> Result<(Self::Columns<'s>, [u8; 32]), Self::Error>;

    fn selected_column(
        &self,
        geometry: SourceGeometry,
        tree: &Self::Columns<'_>,
        index: usize,
    ) -> Result<SourceColumn, Self::Error>;
}

//! RFC-0014 A2. Field-only backend operations for balanced dev-zk ordinary batches.
#![no_std]
#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::float_arithmetic))]

extern crate alloc;
pub use stele_field::{Field, CM31, M31, QM31};
pub mod gkr;
mod hiding;
pub mod lookup;
pub use hiding::{HidingBackend, SourceColumn};
mod scalar;
pub use scalar::Scalar;

/// Physical dimensions of a hiding message in a single proof session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceGeometry {
    pub id: u64,
    pub rows: usize,
    pub columns: usize,
}

/// An ordered sparse claim and its independently drawn batch coefficient.
pub struct WeightedClaim<'a, K> {
    pub weights: &'a [(usize, K)],
    pub value: K,
    pub gamma: K,
}

/// A failed operation produces no proof or backend fallback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Shape,
    Source,
    DuplicateSource,
    Phase,
    Capacity,
}

impl SourceGeometry {
    /// Check the two hiding quadrants on each axis and the original limb count.
    pub fn word_count(self) -> Result<usize, Error> {
        if self.rows < 2
            || self.columns < 2
            || !self.rows.is_power_of_two()
            || !self.columns.is_power_of_two()
        {
            return Err(Error::Shape);
        }
        self.rows.checked_mul(self.columns).ok_or(Error::Capacity)
    }
}

/// Implement on a fresh session for each proof attempt. The driver context may be shared.
pub trait Backend<K: Field> {
    type Error;
    type Original<'s>
    where
        Self: 's;
    type Dense<'s>
    where
        Self: 's;

    /// Import the immutable hiding message once under its proof-local identifier.
    fn original<'s>(
        &'s self,
        geometry: SourceGeometry,
        words: &'s [M31],
    ) -> Result<Self::Original<'s>, Self::Error>;

    /// Derive the weights, original data face and claimed sum for one ordinary batch.
    fn dense_batch<'s>(
        &'s self,
        geometry: SourceGeometry,
        original: &'s Self::Original<'_>,
        claims: &[WeightedClaim<'_, K>],
    ) -> Result<(Self::Dense<'s>, K), Self::Error>;

    /// Evaluate the sum of products at zero, one and two on the next MSB.
    fn dense_round<'s>(state: &mut Self::Dense<'s>) -> Result<[K; 3], Self::Error>
    where
        Self: 's;
    /// Bind the coordinate from the preceding round at the supplied field element.
    fn dense_fold<'s>(state: &mut Self::Dense<'s>, point: K) -> Result<(), Self::Error>
    where
        Self: 's;
    /// Return the weight and face values after all coordinates have been bound.
    fn dense_finals<'s>(state: &Self::Dense<'s>) -> Result<[K; 2], Self::Error>
    where
        Self: 's;
}

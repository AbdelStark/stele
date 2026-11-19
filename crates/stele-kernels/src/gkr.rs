//! RFC-0014 A3. Field-only construction, rounds and folds for RFC-0008 A7 GKR.
use crate::{Backend, Field, M31};
use alloc::vec::Vec;
use core::ops::Range;
pub mod plan;
pub(crate) mod scalar;

/// One term in compact factor order.
pub struct Term<K> {
    pub coefficient: K,
    pub factors: Vec<u32>,
}

/// The GKR operations of the same proof-local field backend.
pub trait GkrBackend<K: Field>: Backend<K> {
    type Gkr<'s>
    where
        Self: 's;
    fn gkr_start<'s>(
        &'s self,
        input: &GkrConstruction<'_, K>,
    ) -> Result<Self::Gkr<'s>, Self::Error>;
    fn gkr_round<'s>(state: &mut Self::Gkr<'s>) -> Result<Vec<K>, Self::Error>
    where
        Self: 's;
    fn gkr_fold<'s>(state: &mut Self::Gkr<'s>, point: K) -> Result<(), Self::Error>
    where
        Self: 's;
    fn gkr_finals<'s>(state: &Self::Gkr<'s>) -> Result<Vec<K>, Self::Error>
    where
        Self: 's;
}

/// Unmaterialized inputs in the actual compact producer's order.
/// Construction borrows the actual operands before their full-domain expansion.
pub struct GkrConstruction<'a, K> {
    /// Full sumcheck domain, with the selector coordinate first when present.
    pub num_vars: u32,
    /// Variables in one layer half, excluding the leading selector coordinate.
    pub layer_variables: usize,
    /// Original declared round degree, including vanishing masks.
    pub degree: usize,
    /// Actual producer terms, from the production term builder.
    pub terms: Vec<Term<K>>,
    /// Original factor order; no full-domain table is allocated here.
    pub factors: Vec<GkrFactor<'a, K>>,
}

/// An occurrence's small mask block and original full-domain coordinates.
pub struct GkrMask<'a> {
    /// M31 block values, in MSB-first coordinate order.
    pub values: Vec<M31>,
    /// Domain coordinates indexing the block.
    pub coordinates: &'a [usize],
    /// Coordinate of `kappa(t) = t(1-t)`.
    pub vanishing: usize,
}

/// A concatenated selector member; the first containing range owns a position.
pub struct GkrSelector<'a> {
    /// Range in the layer half, after member padding.
    pub range: Range<usize>,
    /// Original public values and half-domain coordinates; `None` means one.
    pub values: Option<(&'a [i64], &'a [usize])>,
}

/// One member of a compact tuple factor, in production member order.
pub struct GkrMember<'a, K> {
    /// Range in the layer half, after member padding.
    pub range: Range<usize>,
    /// Original field-valued column; no domain expansion or shift is applied.
    pub values: &'a [K],
    /// MSB-first column-index coordinates in the layer half.
    pub coordinates: &'a [usize],
    /// Integer shift applied after gathering the column.
    pub shift: i64,
    /// Small mask block, indexed by the lowest `log2(mask.len())` half bits.
    pub mask: Vec<M31>,
}

/// A factor's exact construction, before masking and folding.
/// Half-domain values repeat across the leading selector bit. Equality factors
/// instead occupy only their specified interval and are zero elsewhere.
pub enum GkrFactor<'a, K> {
    /// `scale * eq(point, index-offset)` on `offset..offset+2^point.len()`.
    Equality {
        /// Original challenge point, MSB first.
        point: &'a [K],
        /// Incoming kappa coefficient, or one for the head.
        scale: K,
        /// Starting index in the full domain.
        offset: usize,
    },
    /// Interpolate the block's two halves at `point`, then tile the period.
    Block {
        /// Both M31 halves, first `T=0`, then `T=1`.
        values: Vec<M31>,
        /// Actual line-fold challenge.
        point: K,
    },
    /// Gather a committed column over the full domain.
    Column {
        /// Original field-valued column, borrowed without cloning.
        values: &'a [K],
        /// MSB-first column-index coordinates in the full domain.
        coordinates: Vec<usize>,
        /// Occurrence mask.
        mask: GkrMask<'a>,
    },
    /// Gather `values[2*x+side][component]` in each half.
    Layer {
        /// Original child-layer numerator/denominator pairs.
        values: &'a [[K; 2]],
        /// Zero for the numerator, one for the denominator.
        component: usize,
        /// Zero or one, the child coordinate.
        side: usize,
        /// Child's half of its layer mask block.
        mask: GkrMask<'a>,
    },
    /// A6. One of the four original children of level `layer`, held by an authenticated lookup tree.
    RetainedLayer {
        layer: usize,
        component: usize,
        side: usize,
        mask: GkrMask<'a>,
    },
    /// One when the half-domain index is below `2^variables`, else zero.
    Pad {
        /// Original multiplicity/table domain variables.
        variables: usize,
    },
    /// Concatenated public selector, zero off every member.
    Selector {
        /// Members in the original order, including padded ranges.
        members: Vec<GkrSelector<'a>>,
    },
    /// `alpha - sum(beta^i * row[i])` below `valid`; one on padding.
    Table {
        /// Original public rows; no compression or padding is materialized.
        rows: &'a [Vec<i64>],
        /// Valid row count, excluding padding.
        valid: usize,
        /// Actual table challenge.
        alpha: K,
        /// Actual tuple-compression challenge.
        beta: K,
    },
    /// Concatenated shifted column and mask, both zero off every member.
    /// Production writes column ranges first-to-last and mask owners last-to-first;
    /// validated member ranges are disjoint. No owner table is materialized.
    Combined {
        /// One entry per member for this tuple coordinate.
        members: Vec<GkrMember<'a, K>>,
        /// Shared vanishing coordinate in the full domain.
        vanishing: usize,
    },
}

/// RFC-0014 A4. A real A5 relation uses the same masked field arithmetic as A3.
pub trait RelationBackend<K: Field>: GkrBackend<K> {
    /// Construct ordered projected factors for a relation in this proof attempt.
    fn relation_start<'s>(
        &'s self,
        input: &RelationConstruction<'_, K>,
    ) -> Result<Self::Gkr<'s>, Self::Error>;
}

/// RFC-0014 A4. Every collection is in the original relation instance's order.
pub struct RelationConstruction<'a, K> {
    pub num_vars: u32,
    pub degree: usize,
    pub terms: Vec<Term<K>>,
    pub factors: Vec<Projected<'a, K>>,
}

/// An MSB-first projection into the full domain and its original occurrence mask, if any.
pub struct Projected<'a, K> {
    pub values: &'a [K],
    pub coordinates: Vec<usize>,
    pub mask: Option<GkrMask<'a>>,
}

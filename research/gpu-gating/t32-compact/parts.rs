//! RFC-0008 A7: borrowed compact inputs for the disposable benchmark.
use super::bench::{GkrMember, GkrSelector};
use alloc::vec::Vec;
use stele_field::M31;

pub struct CompactParts<'a> {
    pub variables: usize,
    pub top_variables: usize,
    pub tuples: Vec<Vec<GkrMember<'a, M31>>>,
    pub selectors: Vec<GkrSelector<'a>>,
    pub multiplicity: &'a [M31],
    pub table: &'a [Vec<i64>],
    pub valid: usize,
}

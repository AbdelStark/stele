//! Closed original field-source consumer for RFC-0006 A1, governed by RFC-0010 A9 §5.
#![forbid(unsafe_code)]
#![no_std]
#![cfg_attr(not(test), deny(clippy::float_arithmetic))]

extern crate alloc;
// RFC-0026 §8: stele-prover orchestrates the development profile through this crate only.
pub use {stele_cqis, stele_field, stele_hash, stele_ir, stele_pcs};
pub mod argmax;
pub mod byte_range;
pub mod development;
#[cfg(test)]
mod executor_fixtures;
mod field_sources;
pub mod finish;
pub mod integer_linear;
pub mod lookup;
pub mod matmul;
pub mod relation;
pub mod requant;
pub mod residual;
pub mod rope;
pub mod silu;
pub mod zk;
pub use field_sources::{verify_field_sources, Error, Failure, FieldSourceRecord};
mod stacked_sources;
pub use stacked_sources::{
    prove_stacked_sources, prove_stacked_sources_measured, verify_stacked_sources,
    Error as StackedError, Failure as StackedFailure, StackedProof, StackedSourceRecord,
};

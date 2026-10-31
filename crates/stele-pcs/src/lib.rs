//! Conditional field source bytes and unverified wire shapes, RFC-0010 A9.
//!
//! No certificate verifier or profile admission exists in this layer.
//! ```compile_fail
//! use stele_pcs::verify_certificate;
//! ```
#![forbid(unsafe_code)]
#![no_std]
#![cfg_attr(not(test), deny(clippy::float_arithmetic))]

mod source;
pub use source::{Error, Parameters, ProofKind, Response, Source, Wire};

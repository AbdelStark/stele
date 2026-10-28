//! Conditional fraction primitives governed by RFC-0008 A3.
//!
//! Codecs return unverified objects; the native reduction engine is not exported.
//! ```compile_fail
//! use stele_lookup::fraction::verify;
//! ```
#![forbid(unsafe_code)]
#![no_std]
#![cfg_attr(not(test), deny(clippy::float_arithmetic))]

extern crate alloc;
pub mod fraction;

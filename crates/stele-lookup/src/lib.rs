//! Conditional fraction primitives governed by RFC-0008 A3.
//!
//! Tree and selected-product arithmetic return conditional claims; full lookup is absent.
//! ```compile_fail
//! use stele_lookup::fraction::verify_lookup;
//! ```
#![forbid(unsafe_code)]
#![no_std]
#![cfg_attr(not(test), deny(clippy::float_arithmetic))]

extern crate alloc;
pub mod fraction;

//! stele-ir — governed by RFC-0005. No behaviour exists here that is not specified there (INV-1).
//! The development-profile relation set is governed by RFC-0026 §3.
#![forbid(unsafe_code)]
#![no_std]
#![cfg_attr(not(test), deny(clippy::float_arithmetic))]

extern crate alloc;

/// Relations over committed integer columns and their plain checker (RFC-0026 §3).
pub mod relation;

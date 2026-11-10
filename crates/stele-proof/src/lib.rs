//! stele-proof — governed by RFC-0016 §1 and, for `development`, RFC-0026 §4.1. No behaviour exists here that is not specified there (INV-1).
#![forbid(unsafe_code)]
#![no_std]
#![cfg_attr(not(test), deny(clippy::float_arithmetic))]

extern crate alloc;
pub mod development;

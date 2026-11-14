//! stele-verifier — governed by RFC-0016. No behaviour exists here that is not specified there (INV-1).
#![forbid(unsafe_code)]
#![no_std]
#![cfg_attr(not(test), deny(clippy::float_arithmetic))]

extern crate alloc;

pub mod accounting;
pub mod batch;
pub mod circle;
pub mod pcs;
pub mod sumcheck;
pub mod zerocheck;

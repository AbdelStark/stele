//! Conditional stacked field runtime governed by RFC-0006 A4/A7.
#![forbid(unsafe_code)]
#![no_std]
#![cfg_attr(not(test), deny(clippy::float_arithmetic))]

extern crate alloc;
pub mod public_mle;
pub mod stacked;

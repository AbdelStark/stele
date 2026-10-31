//! Closed original field-source consumer for RFC-0006 A1, governed by RFC-0010 A9 §5.
#![forbid(unsafe_code)]
#![no_std]
#![cfg_attr(not(test), deny(clippy::float_arithmetic))]

extern crate alloc;
mod field_sources;
pub use field_sources::{verify_field_sources, Error, Failure, FieldSourceRecord};

//! RFC-0014 A2. Optional CUDA execution for balanced development-ZK batches.
#![allow(unsafe_code)] // RFC-0014 A2 and AGENTS.md §6 permit documented CUDA driver boundaries.
#![deny(unsafe_op_in_unsafe_fn)]
#![cfg_attr(not(test), deny(clippy::float_arithmetic))]
#[cfg(feature = "cuda")]
mod device;
#[cfg(feature = "cuda")]
mod packing;
#[cfg(feature = "cuda")]
mod runtime;
#[cfg(feature = "cuda")]
pub use device::{Counts, Session};
#[cfg(feature = "cuda")]
pub use runtime::{Cuda, Error, Memory};

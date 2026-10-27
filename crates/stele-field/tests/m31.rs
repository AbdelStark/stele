//! M31 scalar property suite (RFC-0003 §§1,6).
use stele_field::M31 as Scalar;
const P: u64 = (1 << 31) - 1;

#[path = "common/scalar.rs"]
mod scalar;

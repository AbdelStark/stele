//! KoalaBear scalar property suite (RFC-0003 §§5,6).
use stele_field::KoalaBear as Scalar;
const P: u64 = (1 << 31) - (1 << 24) + 1;

#[path = "common/scalar.rs"]
mod scalar;

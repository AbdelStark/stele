//! Field arithmetic and canonical encoding governed by RFC-0003 §§1,2,5,6.
#![forbid(unsafe_code)]
#![no_std]
#![cfg_attr(not(test), deny(clippy::float_arithmetic))]

use core::ops::{Add, Mul, Neg, Sub};

mod m31;
pub use m31::M31;
mod koalabear;
pub use koalabear::KoalaBear;

/// Multiplicative inversion; zero has no inverse (RFC-0003 §6).
pub trait Inverse: Sized {
    /// Return the inverse, or `None` for zero.
    fn inverse(self) -> Option<Self>;
}

/// Canonical little-endian field encoding (RFC-0003 §2).
pub trait Serialize: Sized {
    /// Fixed-size byte representation, base limbs first.
    type Bytes: AsRef<[u8]>;
    /// Encode canonical limbs.
    fn to_le_bytes(self) -> Self::Bytes;
    /// Reject noncanonical limbs instead of reducing them.
    fn from_le_bytes(bytes: Self::Bytes) -> Option<Self>;
}

/// Scalar kernel contract (RFC-0003 §6).
pub trait Field:
    Copy
    + Add<Output = Self>
    + Sub<Output = Self>
    + Mul<Output = Self>
    + Neg<Output = Self>
    + Inverse
    + Serialize
{
    /// Base-field characteristic.
    const MODULUS: u32;
    /// Embed an integer modulo the characteristic.
    fn from_i64(value: i64) -> Self;
    /// Recover the centered signed representative (RFC-0003 §1).
    fn to_i64_signed(self) -> i64;
}

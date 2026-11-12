//! Field arithmetic and canonical encoding governed by RFC-0003 §§1,2,5,6.
#![forbid(unsafe_code)]
#![no_std]
#![cfg_attr(not(test), deny(clippy::float_arithmetic))]

use core::ops::{Add, Mul, Neg, Sub};

mod m31;
pub use m31::M31;
mod koalabear;
pub use koalabear::KoalaBear;
mod tower;
pub use tower::{CM31, OM31, QM31};

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
    /// Recover a prime-subfield element, or reject nonconstant coefficients (RFC-0003 A1).
    fn to_i64_signed(self) -> Option<i64>;
    /// `self · from_i64(x)` for the integer value of `x`; extension towers of M31
    /// multiply coefficient-wise (the same element, fewer products; E16-24).
    fn mul_m31(self, x: M31) -> Self {
        self * Self::from_i64(i64::from(x.as_u32()))
    }
}

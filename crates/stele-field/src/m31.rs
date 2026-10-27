//! Canonical Mersenne-31 arithmetic and lazy reduction (RFC-0003 §§1,6).
use crate::{Field, Inverse, Serialize};
use core::ops::{Add, Mul, Neg, Sub};

/// An element of F_p, p = 2^31 - 1. The private limb is always in `[0, p)`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct M31(u32);

impl M31 {
    /// Additive identity.
    pub const ZERO: Self = Self(0);
    /// Multiplicative identity.
    pub const ONE: Self = Self(1);

    /// Prime-field Frobenius is the identity (RFC-0003 §6).
    pub const fn frobenius(self) -> Self {
        self
    }

    /// Accept a canonical limb without modular reduction.
    pub const fn from_canonical(value: u32) -> Option<Self> {
        if value < Self::MODULUS {
            Some(Self(value))
        } else {
            None
        }
    }

    /// Return the canonical limb.
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// Canonicalise a lazy `[0, 2p)` limb; reject values outside that interval.
    pub const fn from_lazy(value: u32) -> Option<Self> {
        if value < 2 * Self::MODULUS {
            Some(Self::reduce_lazy(value))
        } else {
            None
        }
    }

    // INV: lazy — callers establish value < 2p (RFC-0003 §1).
    const fn reduce_lazy(value: u32) -> Self {
        Self(if value >= Self::MODULUS {
            value - Self::MODULUS
        } else {
            value
        })
    }

    /// Reduce any unsigned 64-bit integer modulo p.
    pub const fn from_u64(value: u64) -> Self {
        let p = Self::MODULUS as u64;
        // RFC-0003 §1: 2^31 = 1 mod p; two folds leave at most p+4 < 2p.
        let folded = (value & p) + (value >> 31);
        let folded = (folded & p) + (folded >> 31);
        Self::reduce_lazy(folded as u32)
    }

    /// Exponentiate with square-and-multiply, including `x^0 = 1`.
    pub fn pow(self, mut exponent: u64) -> Self {
        let mut result = Self::ONE;
        let mut base = self;
        while exponent != 0 {
            if exponent & 1 != 0 {
                result = result * base;
            }
            base = base * base;
            exponent >>= 1;
        }
        result
    }
}

impl Field for M31 {
    const MODULUS: u32 = (1 << 31) - 1;

    fn from_i64(value: i64) -> Self {
        Self(value.rem_euclid(i64::from(Self::MODULUS)) as u32)
    }

    fn to_i64_signed(self) -> Option<i64> {
        // RFC-0003 §1 uses the rational p/2; floor(p/2) remains positive.
        Some(if self.0 <= Self::MODULUS / 2 {
            i64::from(self.0)
        } else {
            i64::from(self.0) - i64::from(Self::MODULUS)
        })
    }
}

impl Add for M31 {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Self::reduce_lazy(self.0 + rhs.0)
    }
}

impl Sub for M31 {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        Self::reduce_lazy(self.0 + Self::MODULUS - rhs.0)
    }
}

impl Mul for M31 {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        Self::from_u64(u64::from(self.0) * u64::from(rhs.0))
    }
}

impl Neg for M31 {
    type Output = Self;
    fn neg(self) -> Self {
        Self::reduce_lazy(Self::MODULUS - self.0)
    }
}

impl Inverse for M31 {
    fn inverse(self) -> Option<Self> {
        if self == Self::ZERO {
            None
        } else {
            Some(self.pow(u64::from(Self::MODULUS - 2)))
        }
    }
}

impl Serialize for M31 {
    type Bytes = [u8; 4];
    fn to_le_bytes(self) -> Self::Bytes {
        self.0.to_le_bytes()
    }
    fn from_le_bytes(bytes: Self::Bytes) -> Option<Self> {
        Self::from_canonical(u32::from_le_bytes(bytes))
    }
}

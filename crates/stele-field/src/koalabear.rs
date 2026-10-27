//! Canonical KoalaBear scalar reference for the DPA interface (RFC-0003 §§5,6).
use crate::{Field, Inverse, Serialize};
use core::ops::{Add, Mul, Neg, Sub};

/// An element of F_q, q = 2^31 - 2^24 + 1, stored canonically in `[0, q)`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct KoalaBear(u32);

impl KoalaBear {
    /// Additive identity.
    pub const ZERO: Self = Self(0);
    /// Multiplicative identity.
    pub const ONE: Self = Self(1);

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

    /// Canonicalise a lazy `[0, 2q)` limb; reject values outside that interval.
    pub const fn from_lazy(value: u32) -> Option<Self> {
        if value < 2 * Self::MODULUS {
            Some(Self::reduce_lazy(value))
        } else {
            None
        }
    }

    // INV: lazy — callers establish value < 2q (RFC-0003 §§5,6).
    const fn reduce_lazy(value: u32) -> Self {
        Self(if value >= Self::MODULUS {
            value - Self::MODULUS
        } else {
            value
        })
    }

    /// Reduce any unsigned 64-bit integer modulo q.
    pub const fn from_u64(value: u64) -> Self {
        Self((value % Self::MODULUS as u64) as u32)
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

impl Field for KoalaBear {
    const MODULUS: u32 = (1 << 31) - (1 << 24) + 1;

    fn from_i64(value: i64) -> Self {
        Self(value.rem_euclid(i64::from(Self::MODULUS)) as u32)
    }

    fn to_i64_signed(self) -> Option<i64> {
        // RFC-0003 §§5,6: centered recovery keeps floor(q/2) positive.
        Some(if self.0 <= Self::MODULUS / 2 {
            i64::from(self.0)
        } else {
            i64::from(self.0) - i64::from(Self::MODULUS)
        })
    }
}

impl Add for KoalaBear {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Self::reduce_lazy(self.0 + rhs.0)
    }
}

impl Sub for KoalaBear {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        Self::reduce_lazy(self.0 + Self::MODULUS - rhs.0)
    }
}

impl Mul for KoalaBear {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        Self::from_u64(u64::from(self.0) * u64::from(rhs.0))
    }
}

impl Neg for KoalaBear {
    type Output = Self;
    fn neg(self) -> Self {
        Self::reduce_lazy(Self::MODULUS - self.0)
    }
}

impl Inverse for KoalaBear {
    fn inverse(self) -> Option<Self> {
        if self == Self::ZERO {
            None
        } else {
            Some(self.pow(u64::from(Self::MODULUS - 2)))
        }
    }
}

impl Serialize for KoalaBear {
    type Bytes = [u8; 4];
    fn to_le_bytes(self) -> Self::Bytes {
        self.0.to_le_bytes()
    }
    fn from_le_bytes(bytes: Self::Bytes) -> Option<Self> {
        Self::from_canonical(u32::from_le_bytes(bytes))
    }
}

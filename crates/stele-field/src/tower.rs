//! Quadratic towers, Karatsuba products and canonical limbs (RFC-0003 §2, A1).
use crate::{Field, Inverse, Serialize, M31};
use core::ops::{Add, Mul, Neg, Sub};

// Each invocation supplies z^2 and z^(p-1). The same quadratic identities apply at
// all three levels (RFC-0003 §2, A1); no configurable modulus is exposed.
macro_rules! tower {
    ($name:ident, $base:ty, $bytes:expr, $nr:expr, $frob:expr, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
        pub struct $name(
            /// Constant coefficient.
            pub $base,
            /// Coefficient of the extension generator.
            pub $base,
        );

        impl $name {
            /// Additive identity.
            pub const ZERO: Self = Self(<$base>::ZERO, <$base>::ZERO);
            /// Multiplicative identity.
            pub const ONE: Self = Self(<$base>::ONE, <$base>::ZERO);

            fn mul_nonresidue(value: $base) -> $base {
                ($nr)(value)
            }

            /// Raise to a nonnegative integer power; `x^0 = 1`.
            pub fn pow(self, mut exponent: u128) -> Self {
                let mut base = self;
                let mut result = Self::ONE;
                while exponent != 0 {
                    if exponent & 1 != 0 {
                        result = result * base;
                    }
                    base = base * base;
                    exponent >>= 1;
                }
                result
            }

            /// Raise to the prime characteristic p (RFC-0003 §6).
            pub fn frobenius(self) -> Self {
                // (a+bz)^p = a^p + b^p*z*(z^2)^((p-1)/2).
                Self(self.0.frobenius(), self.1.frobenius() * ($frob))
            }
        }

        impl Add for $name {
            type Output = Self;
            fn add(self, rhs: Self) -> Self {
                Self(self.0 + rhs.0, self.1 + rhs.1)
            }
        }
        impl Sub for $name {
            type Output = Self;
            fn sub(self, rhs: Self) -> Self {
                Self(self.0 - rhs.0, self.1 - rhs.1)
            }
        }
        impl Neg for $name {
            type Output = Self;
            fn neg(self) -> Self {
                Self(-self.0, -self.1)
            }
        }
        impl Mul for $name {
            type Output = Self;
            fn mul(self, rhs: Self) -> Self {
                // RFC-0003 §2: three lower-field products, with fixed nonresidue maps.
                let ac = self.0 * rhs.0;
                let bd = self.1 * rhs.1;
                Self(
                    ac + Self::mul_nonresidue(bd),
                    (self.0 + self.1) * (rhs.0 + rhs.1) - ac - bd,
                )
            }
        }
        impl Inverse for $name {
            fn inverse(self) -> Option<Self> {
                // Irreducibility makes a^2-n*b^2 nonzero exactly when (a,b) != 0.
                let norm = self.0 * self.0 - Self::mul_nonresidue(self.1 * self.1);
                let inverse = norm.inverse()?;
                Some(Self(self.0 * inverse, -self.1 * inverse))
            }
        }
        impl Field for $name {
            const MODULUS: u32 = M31::MODULUS;
            fn from_i64(value: i64) -> Self {
                Self(<$base>::from_i64(value), <$base>::ZERO)
            }
            fn to_i64_signed(self) -> Option<i64> {
                if self.1 != <$base>::ZERO {
                    None
                } else {
                    self.0.to_i64_signed()
                }
            }
        }
        impl Serialize for $name {
            type Bytes = [u8; $bytes];
            fn to_le_bytes(self) -> Self::Bytes {
                let mut bytes = [0; $bytes];
                bytes[..$bytes / 2].copy_from_slice(&self.0.to_le_bytes());
                bytes[$bytes / 2..].copy_from_slice(&self.1.to_le_bytes());
                bytes
            }
            fn from_le_bytes(bytes: Self::Bytes) -> Option<Self> {
                let mut low = [0; $bytes / 2];
                let mut high = [0; $bytes / 2];
                low.copy_from_slice(&bytes[..$bytes / 2]);
                high.copy_from_slice(&bytes[$bytes / 2..]);
                Some(Self(
                    <$base>::from_le_bytes(low)?,
                    <$base>::from_le_bytes(high)?,
                ))
            }
        }
    };
}

tower!(
    CM31,
    M31,
    8,
    |x: M31| -x,
    -M31::ONE,
    "CM31 = M31[i]/(i²+1), in the ordered basis (1,i) (RFC-0003 §2)."
);

// Fixed (2+i) multiplication uses additions only.
fn times_two_plus_i(x: CM31) -> CM31 {
    CM31(x.0 + x.0 - x.1, x.0 + x.1 + x.1)
}

// These Frobenius constants are checked against p-th powers of every basis vector.
tower!(
    QM31,
    CM31,
    16,
    times_two_plus_i,
    CM31(M31::from_u64(21189756), M31::from_u64(42379512)),
    "QM31 = CM31[u]/(u²-(2+i)), in basis (1,i,u,iu) (RFC-0003 §2)."
);

tower!(
    OM31,
    QM31,
    32,
    |x: QM31| QM31(times_two_plus_i(x.1), x.0),
    QM31(
        CM31::ZERO,
        CM31(M31::from_u64(2086136861), M31::from_u64(184040358))
    ),
    "OM31 = QM31[v]/(v²-u), in basis (1,i,u,iu,v,iv,uv,iuv) (RFC-0003 A1)."
);

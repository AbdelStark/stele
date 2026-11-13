//! Quadratic towers, Karatsuba products and canonical limbs (RFC-0003 §2, A1).
use crate::{Field, Inverse, Serialize, M31};
use core::ops::{Add, Mul, Neg, Sub};

// Each invocation supplies z^2 and z^(p-1). The same quadratic identities apply at
// all three levels (RFC-0003 §2, A1); no configurable modulus is exposed.
macro_rules! tower {
    ($name:ident, $base:ty, $bytes:expr, $nr:expr, $frob:expr, $mul:expr, $doc:literal) => {
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

            /// RFC-0003 §2's product: three lower-field products, with fixed nonresidue
            /// maps (the reference every faster product must equal).
            pub fn karatsuba(self, rhs: Self) -> Self {
                let ac = self.0 * rhs.0;
                let bd = self.1 * rhs.1;
                Self(
                    ac + Self::mul_nonresidue(bd),
                    (self.0 + self.1) * (rhs.0 + rhs.1) - ac - bd,
                )
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
                ($mul)(self, rhs)
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
            fn mul_m31(self, x: M31) -> Self {
                // `from_i64` embeds in the first coefficient: (a + b·w)·c = a·c + b·c·w.
                Self(self.0.mul_m31(x), self.1.mul_m31(x))
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
    CM31::karatsuba,
    "CM31 = M31[i]/(i²+1), in the ordered basis (1,i) (RFC-0003 §2)."
);

// Fixed (2+i) multiplication uses additions only.
fn times_two_plus_i(x: CM31) -> CM31 {
    CM31(x.0 + x.0 - x.1, x.0 + x.1 + x.1)
}

/// The QM31 product with lazy reduction (E16-34): the same element as
/// [`QM31::karatsuba`], about twice as fast. Products of canonical limbs (< p) are
/// summed in u64 and reduced once per output limb. A subtracted product `x·y` is added
/// as `x·(p − y)`, with `p − y ∈ [1, p]`. Every sum has at most four products, each
/// below `p²`, so it stays below `4p² < 2^64`.
fn qm31_lazy(x: QM31, y: QM31) -> QM31 {
    const P: u64 = M31::MODULUS as u64;
    let limb = |v: M31| u64::from(v.as_u32());
    let (a0, a1, b0, b1) = (limb(x.0 .0), limb(x.0 .1), limb(x.1 .0), limb(x.1 .1));
    let (c0, c1, d0, d1) = (limb(y.0 .0), limb(y.0 .1), limb(y.1 .0), limb(y.1 .1));
    let reduce = |v: u64| u64::from(M31::from_u64(v).as_u32());
    // (a + b·u)(c + d·u) = ac + (2 + i)·bd + (ad + bc)·u, with i² = −1.
    let ac = [reduce(a0 * c0 + a1 * (P - c1)), reduce(a0 * c1 + a1 * c0)];
    let bd = [reduce(b0 * d0 + b1 * (P - d1)), reduce(b0 * d1 + b1 * d0)];
    // (2 + i)(e0 + e1·i) = (2e0 − e1) + (e0 + 2e1)·i; each sum is below 4p.
    let r0 = ac[0] + 2 * bd[0] + (P - bd[1]);
    let r1 = ac[1] + bd[0] + 2 * bd[1];
    let s0 = a0 * d0 + a1 * (P - d1) + b0 * c0 + b1 * (P - c1);
    let s1 = a0 * d1 + a1 * d0 + b0 * c1 + b1 * c0;
    QM31(
        CM31(M31::from_u64(r0), M31::from_u64(r1)),
        CM31(M31::from_u64(s0), M31::from_u64(s1)),
    )
}

// These Frobenius constants are checked against p-th powers of every basis vector.
tower!(
    QM31,
    CM31,
    16,
    times_two_plus_i,
    CM31(M31::from_u64(21189756), M31::from_u64(42379512)),
    qm31_lazy,
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
    OM31::karatsuba,
    "OM31 = QM31[v]/(v²-u), in basis (1,i,u,iu,v,iv,uv,iuv) (RFC-0003 A1)."
);

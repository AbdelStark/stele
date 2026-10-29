# use core::ops::{Add, Sub, Mul, Neg};
# use stele_field::{Field, Inverse, Serialize, M31};
# #[derive(Clone, Copy)]
# struct Other(M31);
# macro_rules! binary {
#     ($trait:ident, $method:ident, $op:tt) => {
#         impl $trait for Other {
#             type Output = Self;
#             fn $method(self, rhs: Self) -> Self { Self(self.0 $op rhs.0) }
#         }
#     }
# }
# binary!(Add, add, +);
# binary!(Sub, sub, -);
# binary!(Mul, mul, *);
# impl Neg for Other {
#     type Output = Self;
#     fn neg(self) -> Self { Self(-self.0) }
# }
# impl Inverse for Other {
#     fn inverse(self) -> Option<Self> { self.0.inverse().map(Self) }
# }
# impl Serialize for Other {
#     type Bytes = [u8; 4];
#     fn to_le_bytes(self) -> Self::Bytes { self.0.to_le_bytes() }
#     fn from_le_bytes(bytes: Self::Bytes) -> Option<Self> { M31::from_le_bytes(bytes).map(Self) }
# }
# impl Field for Other {
#     const MODULUS: u32 = M31::MODULUS;
#     fn from_i64(value: i64) -> Self { Self(M31::from_i64(value)) }
#     fn to_i64_signed(self) -> Option<i64> { self.0.to_i64_signed() }
# }

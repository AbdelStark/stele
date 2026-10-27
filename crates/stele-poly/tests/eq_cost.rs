//! RFC-0006 §5: count actual field operations, rather than infer complexity from timing.
use std::sync::atomic::{AtomicUsize, Ordering};
use stele_field::{Field, Inverse, Serialize, M31};
use stele_poly::eq_table;
static ADD: AtomicUsize = AtomicUsize::new(0);
static SUB: AtomicUsize = AtomicUsize::new(0);
static MUL: AtomicUsize = AtomicUsize::new(0);
#[derive(Clone, Copy)]
struct Count(M31);
macro_rules! operation {
    ($trait:ident, $method:ident, $count:ident, $op:tt) => {
        impl std::ops::$trait for Count {
            type Output = Self;
            fn $method(self, rhs: Self) -> Self {
                $count.fetch_add(1, Ordering::Relaxed);
                Self(self.0 $op rhs.0)
            }
        }
    };
}
operation!(Add, add, ADD, +);
operation!(Sub, sub, SUB, -);
operation!(Mul, mul, MUL, *);
impl std::ops::Neg for Count {
    type Output = Self;
    fn neg(self) -> Self {
        Self(-self.0)
    }
}
impl Inverse for Count {
    fn inverse(self) -> Option<Self> {
        self.0.inverse().map(Self)
    }
}
impl Serialize for Count {
    type Bytes = [u8; 4];
    fn to_le_bytes(self) -> Self::Bytes {
        self.0.to_le_bytes()
    }
    fn from_le_bytes(bytes: Self::Bytes) -> Option<Self> {
        M31::from_le_bytes(bytes).map(Self)
    }
}
impl Field for Count {
    const MODULUS: u32 = M31::MODULUS;
    fn from_i64(value: i64) -> Self {
        Self(M31::from_i64(value))
    }
    fn to_i64_signed(self) -> Option<i64> {
        self.0.to_i64_signed()
    }
}
#[test]
fn matches_reference_linear_eq_operation_count() {
    for dimension in 0..=16 {
        for count in [&ADD, &SUB, &MUL] {
            count.store(0, Ordering::Relaxed);
        }
        let point = vec![Count::from_i64(17); dimension];
        let table = eq_table(&point).expect("valid polynomial input");
        let splits = (1 << dimension) - 1;
        assert_eq!(table.len(), splits + 1);
        assert_eq!(ADD.load(Ordering::Relaxed), 0);
        assert_eq!(SUB.load(Ordering::Relaxed), splits);
        assert_eq!(MUL.load(Ordering::Relaxed), splits);
        let sum = table.iter().fold(M31::from_i64(0), |s, v| s + v.0);
        assert_eq!(sum, M31::from_i64(1));
    }
}

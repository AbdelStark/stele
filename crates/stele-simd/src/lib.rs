//! Checked scalar/SIMD M31 and QM31 blocks, governed by RFC-0003 §§1,2,6.
#![allow(unsafe_code)] // AGENTS.md §6 permits documented intrinsic boundaries in stele-simd.
#![deny(unsafe_op_in_unsafe_fn)]
use stele_field::{Field, CM31, M31, QM31};
const P: u32 = M31::MODULUS;

/// Sixteen M31 lanes; internal lazy limbs satisfy `[0,2p)` (RFC-0003 §1).
#[derive(Clone, Copy, Debug)]
pub struct PackedM31([u32; 16]);
impl PackedM31 {
    /// Accept lazy limbs, rejecting values outside `[0,2p)`.
    pub fn from_lazy(limbs: [u32; 16]) -> Option<Self> {
        limbs.iter().all(|x| *x < 2 * P).then_some(Self(limbs))
    }
    /// Export canonical limbs before hashing or serialisation (RFC-0003 §1).
    pub fn to_array(self) -> [u32; 16] {
        self.0.map(|x| M31::from_u64(u64::from(x)).as_u32())
    }
}

/// Sixteen QM31 lanes in four columns ordered `(1,i,u,iu)` (RFC-0003 A1).
#[derive(Clone, Copy, Debug)]
pub struct PackedQM31([[u32; 16]; 4]);
impl PackedQM31 {
    /// Accept four columns of lazy limbs, rejecting any limb outside `[0,2p)`.
    pub fn from_lazy(limbs: [[u32; 16]; 4]) -> Option<Self> {
        limbs
            .iter()
            .flatten()
            .all(|x| *x < 2 * P)
            .then_some(Self(limbs))
    }
    /// Export canonical columns in the ordered tower basis.
    pub fn to_array(self) -> [[u32; 16]; 4] {
        self.0.map(|c| PackedM31(c).to_array())
    }
}

/// Lane-wise arithmetic. Negation is subtraction from a zero block.
#[derive(Clone, Copy, Debug)]
pub enum Op {
    Add,
    Sub,
    Mul,
}

/// Explicit backend selection; unsupported requests never silently fall back.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Backend {
    Scalar,
    Neon,
    Avx2,
    Avx512,
}

/// The requested backend cannot execute on this host.
#[derive(Debug)]
pub struct UnsupportedBackend;
impl core::fmt::Display for UnsupportedBackend {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("requested SIMD backend is unavailable")
    }
}
impl std::error::Error for UnsupportedBackend {}

impl Backend {
    /// Detect architecture and OS-enabled instruction support.
    pub fn available(self) -> bool {
        match self {
            Self::Scalar => true,
            #[cfg(target_arch = "aarch64")]
            Self::Neon => std::arch::is_aarch64_feature_detected!("neon"),
            #[cfg(target_arch = "x86_64")]
            Self::Avx2 => std::arch::is_x86_feature_detected!("avx2"),
            #[cfg(target_arch = "x86_64")]
            Self::Avx512 => std::arch::is_x86_feature_detected!("avx512f"),
            _ => false,
        }
    }
    /// Select the widest available backend, or the scalar reference.
    pub fn detect() -> Self {
        [Self::Avx512, Self::Avx2, Self::Neon]
            .into_iter()
            .find(|b| b.available())
            .unwrap_or(Self::Scalar)
    }
    /// Apply one operation; all output limbs are canonical (RFC-0003 §6).
    pub fn m31(self, op: Op, a: PackedM31, b: PackedM31) -> Result<PackedM31, UnsupportedBackend> {
        if !self.available() {
            return Err(UnsupportedBackend);
        }
        // SAFETY: RFC-0003 §6/INV-8: feature checked, fixed-size arrays, valid lazy limbs.
        let out = unsafe {
            match self {
                Self::Scalar => std::array::from_fn(|i| {
                    let a = M31::from_u64(u64::from(a.0[i]));
                    let b = M31::from_u64(u64::from(b.0[i]));
                    match op {
                        Op::Add => a + b,
                        Op::Sub => a - b,
                        Op::Mul => a * b,
                    }
                    .as_u32()
                }),
                #[cfg(target_arch = "aarch64")]
                Self::Neon => neon::m31(op, &a.0, &b.0),
                #[cfg(target_arch = "x86_64")]
                Self::Avx2 => x86::avx2::m31(op, &a.0, &b.0),
                #[cfg(target_arch = "x86_64")]
                Self::Avx512 => x86::avx512::m31(op, &a.0, &b.0),
                _ => return Err(UnsupportedBackend),
            }
        };
        Ok(PackedM31(out))
    }
    /// Apply a QM31 operation in the ordered basis; outputs are canonical.
    pub fn qm31(
        self,
        op: Op,
        a: PackedQM31,
        b: PackedQM31,
    ) -> Result<PackedQM31, UnsupportedBackend> {
        if !self.available() {
            return Err(UnsupportedBackend);
        }
        // SAFETY: RFC-0003 §6/INV-8: feature checked, fixed-size columns, valid lazy limbs.
        let out = unsafe {
            match self {
                Self::Scalar => {
                    let a = a.to_array();
                    let b = b.to_array();
                    let mut out = [[0; 16]; 4];
                    for i in 0..16 {
                        let unpack = |v: [[u32; 16]; 4]| {
                            let x = v.map(|c| M31::from_u64(u64::from(c[i])));
                            QM31(CM31(x[0], x[1]), CM31(x[2], x[3]))
                        };
                        let x = unpack(a);
                        let y = unpack(b);
                        let z = match op {
                            Op::Add => x + y,
                            Op::Sub => x - y,
                            Op::Mul => x * y,
                        };
                        for (col, v) in [z.0 .0, z.0 .1, z.1 .0, z.1 .1].into_iter().enumerate() {
                            out[col][i] = v.as_u32();
                        }
                    }
                    out
                }
                #[cfg(target_arch = "aarch64")]
                Self::Neon => neon::qm31(op, &a.0, &b.0),
                #[cfg(target_arch = "x86_64")]
                Self::Avx2 => x86::avx2::qm31(op, &a.0, &b.0),
                #[cfg(target_arch = "x86_64")]
                Self::Avx512 => x86::avx512::qm31(op, &a.0, &b.0),
                _ => return Err(UnsupportedBackend),
            }
        };
        Ok(PackedQM31(out))
    }
}

#[macro_use]
mod kernels;
#[cfg(target_arch = "aarch64")]
mod neon;
#[cfg(test)]
mod tests;
#[cfg(target_arch = "x86_64")]
mod x86;

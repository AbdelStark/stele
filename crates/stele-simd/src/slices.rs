//! Kernels over slices of QM31 elements (RFC-0003 §§2,6; RFC-0014 §2 `sumcheck_round`
//! fold). Each has a scalar reference, and every backend writes that reference's limbs.
use crate::{Backend, UnsupportedBackend};
use stele_field::QM31;

// `QM31` is `repr(C)` over `repr(transparent)` limbs: four `u32` in basis order.
const _: () = assert!(core::mem::size_of::<QM31>() == 16 && core::mem::align_of::<QM31>() == 4);

/// The reference fold: `lo[j] += c·(hi[j] − lo[j])`, the first `min(lo.len(), hi.len())`
/// entries.
pub fn fold_reference(lo: &mut [QM31], hi: &[QM31], c: QM31) {
    for (a, b) in lo.iter_mut().zip(hi) {
        *a = *a + c * (*b - *a);
    }
}

impl Backend {
    /// [`fold_reference`] on this backend. NEON has no kernel (one product per 64-bit
    /// lane gives no gain over the scalar multiplier) and runs the reference.
    pub fn fold(self, lo: &mut [QM31], hi: &[QM31], c: QM31) -> Result<(), UnsupportedBackend> {
        if !self.available() {
            return Err(UnsupportedBackend);
        }
        let n = lo.len().min(hi.len());
        let (lo, hi) = (&mut lo[..n], &hi[..n]);
        let done = match self {
            #[cfg(target_arch = "x86_64")]
            Self::Avx2 | Self::Avx512 => {
                let limbs = [
                    c.0 .0.as_u32(),
                    c.0 .1.as_u32(),
                    c.1 .0.as_u32(),
                    c.1 .1.as_u32(),
                ];
                // SAFETY: RFC-0003 §6. The feature was checked above. `lo` and `hi` are
                // `n` elements of four `u32` limbs each (layout asserted above), read and
                // written in whole elements inside their slices. Every stored limb is
                // canonical, which is `M31`'s invariant.
                unsafe {
                    let (lo, hi) = (lo.as_mut_ptr().cast::<u32>(), hi.as_ptr().cast::<u32>());
                    if self == Self::Avx512 {
                        crate::x86::avx512::fold(lo, hi, n, limbs)
                    } else {
                        crate::x86::avx2::fold(lo, hi, n, limbs)
                    }
                }
            }
            _ => 0,
        };
        fold_reference(&mut lo[done..], &hi[done..], c);
        Ok(())
    }
}

/// [`fold_reference`] on the widest backend of this host.
pub fn fold(lo: &mut [QM31], hi: &[QM31], c: QM31) {
    // `detect` returns an available backend, so this cannot fail.
    if Backend::detect().fold(lo, hi, c).is_err() {
        fold_reference(lo, hi, c);
    }
}

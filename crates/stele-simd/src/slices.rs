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

/// `[p0, q0, p1, q1]` of a fraction-tree layer, each `2·half` elements, leading
/// coordinate first.
pub type LayerTables<'a> = [&'a [QM31]; 4];

/// The reference partial sums of a fraction-tree layer round with unit weights
/// (RFC-0008 A3), over the positions `range` of the lower half: `e[x]·t` for
/// `t = q1·(p0 + γ·q0) + p1·q0` at `x`, at `x + half` and of the differences of the two,
/// where `half = e.len()`.
pub fn layer_round_reference(
    tables: LayerTables<'_>,
    e: &[QM31],
    gamma: QM31,
    range: core::ops::Range<usize>,
) -> [QM31; 3] {
    let half = e.len();
    let [p0, q0, p1, q1] = tables;
    let term = |p0: QM31, q0: QM31, p1: QM31, q1: QM31| q1 * (p0 + gamma * q0) + p1 * q0;
    let mut sums = [QM31::ZERO; 3];
    for x in range {
        let y = x + half;
        sums[0] = sums[0] + e[x] * term(p0[x], q0[x], p1[x], q1[x]);
        sums[1] = sums[1] + e[x] * term(p0[y], q0[y], p1[y], q1[y]);
        sums[2] = sums[2] + e[x] * term(p0[y] - p0[x], q0[y] - q0[x], p1[y] - p1[x], q1[y] - q1[x]);
    }
    sums
}

impl Backend {
    /// [`layer_round_reference`] on this backend. Field sums are exact, so the three
    /// elements are the reference's whatever the order of the additions.
    pub fn layer_round(
        self,
        tables: LayerTables<'_>,
        e: &[QM31],
        gamma: QM31,
        range: core::ops::Range<usize>,
    ) -> Result<[QM31; 3], UnsupportedBackend> {
        if !self.available() {
            return Err(UnsupportedBackend);
        }
        let half = e.len();
        let in_bounds = range.start <= range.end
            && range.end <= half
            && tables.iter().all(|t| t.len() >= 2 * half);
        #[allow(unused_mut)]
        let (mut sums, mut done) = ([QM31::ZERO; 3], 0);
        #[cfg(target_arch = "x86_64")]
        if in_bounds && matches!(self, Self::Avx2 | Self::Avx512) {
            let limbs = |c: QM31| {
                [
                    c.0 .0.as_u32(),
                    c.0 .1.as_u32(),
                    c.1 .0.as_u32(),
                    c.1 .1.as_u32(),
                ]
            };
            let pointers = tables.map(|t| t.as_ptr().cast::<u32>());
            // SAFETY: RFC-0003 §6. The feature was checked above. Every table has at
            // least `2·half` elements and `e` has `half`, of four `u32` limbs each
            // (layout asserted above), and `range` lies in `0..half`: all reads are of
            // whole elements inside the slices. The kernel returns canonical limbs.
            let (partial, count) = unsafe {
                let e = e.as_ptr().cast::<u32>();
                let span = (range.start, range.end);
                if self == Self::Avx512 {
                    crate::x86::avx512::layer_round(pointers, e, half, span, limbs(gamma))
                } else {
                    crate::x86::avx2::layer_round(pointers, e, half, span, limbs(gamma))
                }
            };
            let element = |l: [u32; 4]| {
                let m = |v: u32| stele_field::M31::from_canonical(v);
                Some(QM31(
                    stele_field::CM31(m(l[0])?, m(l[1])?),
                    stele_field::CM31(m(l[2])?, m(l[3])?),
                ))
            };
            if let (Some(a), Some(b), Some(c)) = (
                element(partial[0]),
                element(partial[1]),
                element(partial[2]),
            ) {
                (sums, done) = ([a, b, c], count);
            }
        }
        let _ = in_bounds;
        // The tail, and everything on a backend without a kernel. Out-of-bounds input
        // fails here exactly as the reference does.
        let rest = layer_round_reference(tables, e, gamma, range.start + done..range.end);
        Ok([sums[0] + rest[0], sums[1] + rest[1], sums[2] + rest[2]])
    }
}

/// [`layer_round_reference`] on the widest backend of this host.
pub fn layer_round(
    tables: LayerTables<'_>,
    e: &[QM31],
    gamma: QM31,
    range: core::ops::Range<usize>,
) -> [QM31; 3] {
    match Backend::detect().layer_round(tables, e, gamma, range.clone()) {
        Ok(sums) => sums,
        Err(_) => layer_round_reference(tables, e, gamma, range),
    }
}

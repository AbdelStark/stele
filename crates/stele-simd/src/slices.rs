//! Kernels over slices of QM31 elements (RFC-0003 §§2,6; RFC-0014 §2 `sumcheck_round`
//! fold). Each has a scalar reference, and every backend writes that reference's limbs.
use crate::{Backend, UnsupportedBackend};
use stele_field::{CM31, M31, QM31};

// `M31` is `repr(transparent)` over its canonical `u32` limb.
const _: () = assert!(core::mem::size_of::<M31>() == 4 && core::mem::align_of::<M31>() == 4);
// `QM31` is `repr(C)` over `repr(transparent)` limbs: four `u32` in basis order.
const _: () = assert!(core::mem::size_of::<QM31>() == 16 && core::mem::align_of::<QM31>() == 4);
// The order itself: each level's second coefficient follows its first.
const _: () = assert!(core::mem::offset_of!(CM31, 1) == 4 && core::mem::offset_of!(QM31, 1) == 8);

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

/// Whether this host's widest backend has kernels: callers that must copy their operands
/// into tables first do so only when it pays.
pub fn accelerated() -> bool {
    matches!(Backend::detect(), Backend::Avx2 | Backend::Avx512)
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

/// The reference butterflies of one transform level (RFC-0029 §1.2): over the first
/// `min` of the three lengths, `(low[j], high[j]) <- (low[j] + t, low[j] − t)` for
/// `t = high[j]·twiddles[j]`.
pub fn butterflies_reference(low: &mut [M31], high: &mut [M31], twiddles: &[M31]) {
    for ((a, b), twiddle) in low.iter_mut().zip(high.iter_mut()).zip(twiddles) {
        let (x, t) = (*a, *b * *twiddle);
        *a = x + t;
        *b = x - t;
    }
}

impl Backend {
    /// [`butterflies_reference`] on this backend.
    pub fn butterflies(
        self,
        low: &mut [M31],
        high: &mut [M31],
        twiddles: &[M31],
    ) -> Result<(), UnsupportedBackend> {
        if !self.available() {
            return Err(UnsupportedBackend);
        }
        let n = low.len().min(high.len()).min(twiddles.len());
        let (low, high, twiddles) = (&mut low[..n], &mut high[..n], &twiddles[..n]);
        // SAFETY: RFC-0003 §6. The feature was checked above. The three slices have `n`
        // limbs (layout asserted above) and `low`, `high` are distinct `&mut` slices.
        // Every stored limb is canonical, which is `M31`'s invariant.
        let done = unsafe {
            let (l, h, t) = (
                low.as_mut_ptr().cast::<u32>(),
                high.as_mut_ptr().cast::<u32>(),
                twiddles.as_ptr().cast::<u32>(),
            );
            match self {
                Self::Scalar => 0,
                #[cfg(target_arch = "aarch64")]
                Self::Neon => crate::neon::butterflies(l, h, t, n),
                #[cfg(target_arch = "x86_64")]
                Self::Avx2 => crate::x86::avx2::butterflies(l, h, t, n),
                #[cfg(target_arch = "x86_64")]
                Self::Avx512 => crate::x86::avx512::butterflies(l, h, t, n),
                _ => 0,
            }
        };
        butterflies_reference(&mut low[done..], &mut high[done..], &twiddles[done..]);
        Ok(())
    }
}

/// [`butterflies_reference`] on the widest backend of this host.
pub fn butterflies(low: &mut [M31], high: &mut [M31], twiddles: &[M31]) {
    if Backend::detect().butterflies(low, high, twiddles).is_err() {
        butterflies_reference(low, high, twiddles);
    }
}

/// The reference element-wise product: `a[j] *= b[j]` over the first `min` of the lengths.
pub fn mul_assign_reference(a: &mut [QM31], b: &[QM31]) {
    for (x, y) in a.iter_mut().zip(b) {
        *x = *x * *y;
    }
}

impl Backend {
    /// [`mul_assign_reference`] on this backend.
    pub fn mul_assign(self, a: &mut [QM31], b: &[QM31]) -> Result<(), UnsupportedBackend> {
        if !self.available() {
            return Err(UnsupportedBackend);
        }
        let n = a.len().min(b.len());
        let (a, b) = (&mut a[..n], &b[..n]);
        let done = match self {
            #[cfg(target_arch = "x86_64")]
            Self::Avx2 | Self::Avx512 => {
                // SAFETY: RFC-0003 §6. The feature was checked above. `a` and `b` are `n`
                // elements of four `u32` limbs each (layout asserted above), read and
                // written in whole elements. Every stored limb is canonical.
                unsafe {
                    let (a, b) = (a.as_mut_ptr().cast::<u32>(), b.as_ptr().cast::<u32>());
                    if self == Self::Avx512 {
                        crate::x86::avx512::mul_assign(a, b, n)
                    } else {
                        crate::x86::avx2::mul_assign(a, b, n)
                    }
                }
            }
            _ => 0,
        };
        mul_assign_reference(&mut a[done..], &b[done..]);
        Ok(())
    }
}

/// [`mul_assign_reference`] on the widest backend of this host.
pub fn mul_assign(a: &mut [QM31], b: &[QM31]) {
    if Backend::detect().mul_assign(a, b).is_err() {
        mul_assign_reference(a, b);
    }
}

/// The reference int8 dot product: the wrapping `i32` sum of `x[j]·w[j]` over the first
/// `min` of the lengths, with each byte of `w` read as a two's-complement `i8`. Callers
/// bound the length so that the sum is exact (RFC-0004 A15: below `2^28`).
pub fn dot_i8_reference(x: &[i8], w: &[u8]) -> i32 {
    x.iter().zip(w).fold(0i32, |sum, (x, w)| {
        sum.wrapping_add(i32::from(*x) * i32::from(*w as i8))
    })
}

impl Backend {
    /// [`dot_i8_reference`] on this backend. AVX-512 needs the byte and word extension
    /// as well and falls back to the AVX2 kernel without it; NEON runs the reference.
    pub fn dot_i8(self, x: &[i8], w: &[u8]) -> Result<i32, UnsupportedBackend> {
        if !self.available() {
            return Err(UnsupportedBackend);
        }
        let n = x.len().min(w.len());
        let (x, w) = (&x[..n], &w[..n]);
        #[allow(unused_mut)]
        let (mut sum, mut done) = (0i32, 0);
        #[cfg(target_arch = "x86_64")]
        if matches!(self, Self::Avx2 | Self::Avx512) {
            // SAFETY: RFC-0003 §6. AVX2 is implied by either backend's availability check
            // above (an AVX-512 host has AVX2), and the wider kernel runs only when the
            // byte and word extension is detected too. Both slices have `n` bytes.
            (sum, done) = unsafe {
                if self == Self::Avx512 && std::arch::is_x86_feature_detected!("avx512bw") {
                    crate::x86::dot::avx512(x.as_ptr(), w.as_ptr(), n)
                } else if std::arch::is_x86_feature_detected!("avx2") {
                    crate::x86::dot::avx2(x.as_ptr(), w.as_ptr(), n)
                } else {
                    (0, 0)
                }
            };
        }
        Ok(sum.wrapping_add(dot_i8_reference(&x[done..], &w[done..])))
    }
}

/// [`dot_i8_reference`] on the widest backend of this host.
pub fn dot_i8(x: &[i8], w: &[u8]) -> i32 {
    match Backend::detect().dot_i8(x, w) {
        Ok(sum) => sum,
        Err(_) => dot_i8_reference(x, w),
    }
}

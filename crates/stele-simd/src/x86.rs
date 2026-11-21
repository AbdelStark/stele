//! AVX2/AVX-512 widening products in even/odd lanes (RFC-0003 §§1,6).
macro_rules! x86_backend {
    ($name:ident,$feature:literal,$width:expr,$v:ty,
     $load:ident,$store:ident,$dup32:ident,$dup64:ident,$plus32:ident,$minus32:ident,
     $min:ident,$plus64:ident,$and:ident,$or:ident,$shr:ident,$shl:ident,$times:ident,
     $minus64:ident,$swap:ident,$pair:expr,$blend:expr) => {
        pub(crate) mod $name {
            use crate::P;
            use core::arch::x86_64::*;
            #[target_feature(enable=$feature)]
            unsafe fn load(p: *const u32) -> $v {
                // SAFETY: RFC-0003 §6: caller supplies width readable lanes; feature enabled.
                unsafe { $load(p.cast()) }
            }
            #[target_feature(enable=$feature)]
            unsafe fn store(p: *mut u32, v: $v) {
                // SAFETY: RFC-0003 §6: caller supplies width writable lanes; feature enabled.
                unsafe { $store(p.cast(), v) }
            }
            #[target_feature(enable=$feature)]
            unsafe fn canonical(a: $v) -> $v {
                // INV: lazy — wrapping subtraction and unsigned min canonicalise a<2p.
                $min(a, $minus32(a, $dup32(P as i32)))
            }
            #[target_feature(enable=$feature)]
            unsafe fn add(a: $v, b: $v) -> $v {
                // SAFETY: RFC-0003 §1: canonical operands sum to <2p; feature enabled.
                unsafe { canonical($plus32(a, b)) }
            }
            #[target_feature(enable=$feature)]
            unsafe fn sub(a: $v, b: $v) -> $v {
                // SAFETY: RFC-0003 §1: a+p-b lies in [1,2p); feature enabled.
                unsafe { canonical($minus32($plus32(a, $dup32(P as i32)), b)) }
            }
            #[target_feature(enable=$feature)]
            unsafe fn mul(a: $v, b: $v) -> $v {
                let even = $times(a, b);
                let odd = $times($shr::<32>(a), $shr::<32>(b));
                let mask = $dup64(i64::from(P));
                let even = $plus64($and(even, mask), $shr::<31>(even));
                let odd = $plus64($and(odd, mask), $shr::<31>(odd));
                // SAFETY: RFC-0003 §1: folds are <2p, fitting u32; interleave restores order.
                unsafe { canonical($or(even, $shl::<32>(odd))) }
            }
            kernels!($feature, $width, $v);

            /// Two Mersenne folds of 64-bit lanes: at most `p + 4` for any input.
            #[target_feature(enable=$feature)]
            unsafe fn fold2(v: $v) -> $v {
                let mask = $dup64(i64::from(P));
                let f = $plus64($and(v, mask), $shr::<31>(v));
                $plus64($and(f, mask), $shr::<31>(f))
            }
            /// The QM31 product of each element of `x` with the element of `y` in its place
            /// (four `u32` limbs each, basis order, canonical in and out).
            ///
            /// Per element there are two 64-bit lanes: lane 0 holds the a limbs, lane 1 the
            /// b limbs. With x = (a0, a1, b0, b1) and y = (c0, c1, d0, d1), i² = −1 and
            /// u² = 2 + i: ac = (a0c0 − a1c1, a0c1 + a1c0), bd likewise, r = ac + (2 + i)·bd
            /// and s = ad + bc. A subtracted product x·y is added as x·(p − y), so every
            /// lane is a sum of at most four products below p², below 2^64.
            #[target_feature(enable=$feature)]
            unsafe fn mul4(x: $v, y: $v) -> $v {
                let p64 = $dup64(i64::from(P));
                let four_p = $dup64(4 * i64::from(P));
                // SAFETY: RFC-0003 §§1,2: register arithmetic only; the caller enables the
                // feature and passes canonical limbs.
                unsafe {
                    let odd = $shr::<32>(x); // (a1, b1)
                    let yo = $shr::<32>(y); // (c1, d1)
                    let nyo = $minus64(p64, yo); // (p − c1, p − d1)
                    let ys = $swap::<0b01_00_11_10>(y); // (d0, c0)
                    let yos = $swap::<0b01_00_11_10>(yo); // (d1, c1)
                    let nyos = $swap::<0b01_00_11_10>(nyo); // (p − d1, p − c1)
                    let v1 = $plus64($times(x, y), $times(odd, nyo)); // (ac0, bd0)
                    let v2 = $plus64($times(x, yo), $times(odd, y)); // (ac1, bd1)
                    let s0 = $plus64($times(x, ys), $times(odd, nyos)); // halves of s0
                    let s1 = $plus64($times(x, yos), $times(odd, ys)); // halves of s1
                    let (v1, v2) = (fold2(v1), fold2(v2));
                    let (v1s, v2s) = ($swap::<0b01_00_11_10>(v1), $swap::<0b01_00_11_10>(v2));
                    // Lane 0: r0 = ac0 + 2·bd0 − bd1, r1 = ac1 + bd0 + 2·bd1.
                    let r0 = $plus64($plus64(v1, $shl::<1>(v1s)), $minus64(four_p, v2s));
                    let r1 = $plus64($plus64(v2, v1s), $shl::<1>(v2s));
                    let s0 = $plus64(s0, $swap::<0b01_00_11_10>(s0));
                    let s1 = $plus64(s1, $swap::<0b01_00_11_10>(s1));
                    // Folded lanes fit 32 bits with a zero upper half, so the 32-bit
                    // canonical step applies to them.
                    let (r0, r1) = (canonical(fold2(r0)), canonical(fold2(r1)));
                    let (s0, s1) = (canonical(fold2(s0)), canonical(fold2(s1)));
                    // (r0, r1) from lane 0 and (s0, s1) from lane 1 of each element.
                    $blend($or(r0, $shl::<32>(r1)), $or(s0, $shl::<32>(s1)))
                }
            }
            /// One element in every element slot of a vector.
            #[target_feature(enable=$feature)]
            unsafe fn splat(c: [u32; 4]) -> $v {
                let lane = |low: u32, high: u32| i64::from(low) | (i64::from(high) << 32);
                $pair(lane(c[0], c[1]), lane(c[2], c[3]))
            }
            /// `a[j] *= b[j]` on whole vectors of QM31 elements. Returns the number of
            /// elements done.
            #[target_feature(enable=$feature)]
            pub(crate) unsafe fn mul_assign(a: *mut u32, b: *const u32, n: usize) -> usize {
                let per = $width / 4;
                let done = n / per * per;
                // SAFETY: RFC-0003 §6: the caller enables the feature and supplies `n`
                // elements behind each pointer; each load and store covers `per` whole
                // elements below `done <= n`.
                unsafe {
                    let mut i = 0;
                    while i < done {
                        store(a.add(4 * i), mul4(load(a.add(4 * i)), load(b.add(4 * i))));
                        i += per;
                    }
                }
                done
            }
            /// `lo[j] += c·(hi[j] − lo[j])` on whole vectors of QM31 elements. Returns the
            /// number of elements done; the caller finishes the tail with the reference.
            #[target_feature(enable=$feature)]
            pub(crate) unsafe fn fold(
                lo: *mut u32,
                hi: *const u32,
                n: usize,
                c: [u32; 4],
            ) -> usize {
                let per = $width / 4;
                let done = n / per * per;
                // SAFETY: RFC-0003 §6: the caller enables the feature and supplies `n`
                // elements behind each pointer; each load and store covers `per` whole
                // elements below `done <= n`.
                unsafe {
                    let c = splat(c);
                    let mut i = 0;
                    while i < done {
                        let a = load(lo.add(4 * i));
                        let b = load(hi.add(4 * i));
                        store(lo.add(4 * i), add(a, mul4(c, sub(b, a))));
                        i += per;
                    }
                }
                done
            }
            /// Partial sums of a fraction-tree layer round with unit weights, over the
            /// positions `start..start + done` (`done` returned, a multiple of the vector's
            /// elements): `e[x]·t` for `t = q1·(p0 + γ·q0) + p1·q0` at `x`, at `x + half`,
            /// and of the differences of the two. `t` holds `p0, q0, p1, q1`.
            #[target_feature(enable=$feature)]
            pub(crate) unsafe fn layer_round(
                t: [*const u32; 4],
                e: *const u32,
                half: usize,
                (start, end): (usize, usize),
                gamma: [u32; 4],
            ) -> ([[u32; 4]; 3], usize) {
                let per = $width / 4;
                let done = (end - start) / per * per;
                let mut out = [[0u32; 4]; 3];
                // SAFETY: RFC-0003 §6: the caller enables the feature and supplies `2·half`
                // elements behind each table pointer and `half` behind `e`, with
                // `end <= half`; each load covers `per` whole elements below those bounds.
                unsafe {
                    let g = splat(gamma);
                    let zero = $dup32(0);
                    let mut acc = [zero; 3];
                    let mut x = start;
                    while x < start + done {
                        let y = x + half;
                        let at = |table: *const u32, i: usize| load(table.add(4 * i));
                        let (p0x, q0x, p1x, q1x) =
                            (at(t[0], x), at(t[1], x), at(t[2], x), at(t[3], x));
                        let (p0y, q0y, p1y, q1y) =
                            (at(t[0], y), at(t[1], y), at(t[2], y), at(t[3], y));
                        let weight = at(e, x);
                        let (gx, gy) = (mul4(q0x, g), mul4(q0y, g));
                        let tx = add(mul4(q1x, add(p0x, gx)), mul4(p1x, q0x));
                        let ty = add(mul4(q1y, add(p0y, gy)), mul4(p1y, q0y));
                        // γ·(q0y − q0x) is γ·q0y − γ·q0x.
                        let td = add(
                            mul4(sub(q1y, q1x), add(sub(p0y, p0x), sub(gy, gx))),
                            mul4(sub(p1y, p1x), sub(q0y, q0x)),
                        );
                        acc[0] = add(acc[0], mul4(weight, tx));
                        acc[1] = add(acc[1], mul4(weight, ty));
                        acc[2] = add(acc[2], mul4(weight, td));
                        x += per;
                    }
                    for (sum, lanes) in out.iter_mut().zip(acc) {
                        let mut limbs = [0u32; $width];
                        store(limbs.as_mut_ptr(), lanes);
                        for element in limbs.chunks_exact(4) {
                            for (total, limb) in sum.iter_mut().zip(element) {
                                // Canonical limbs: the sum is below 2p.
                                let s = *total + *limb;
                                *total = if s >= P { s - P } else { s };
                            }
                        }
                    }
                }
                (out, done)
            }
        }
    };
}
x86_backend!(
    avx2,
    "avx2",
    8,
    __m256i,
    _mm256_loadu_si256,
    _mm256_storeu_si256,
    _mm256_set1_epi32,
    _mm256_set1_epi64x,
    _mm256_add_epi32,
    _mm256_sub_epi32,
    _mm256_min_epu32,
    _mm256_add_epi64,
    _mm256_and_si256,
    _mm256_or_si256,
    _mm256_srli_epi64,
    _mm256_slli_epi64,
    _mm256_mul_epu32,
    _mm256_sub_epi64,
    _mm256_shuffle_epi32,
    |x: i64, y: i64| _mm256_set_epi64x(y, x, y, x),
    |r: __m256i, s: __m256i| _mm256_blend_epi32::<0b1100_1100>(r, s)
);
x86_backend!(
    avx512,
    "avx512f",
    16,
    __m512i,
    _mm512_loadu_si512,
    _mm512_storeu_si512,
    _mm512_set1_epi32,
    _mm512_set1_epi64,
    _mm512_add_epi32,
    _mm512_sub_epi32,
    _mm512_min_epu32,
    _mm512_add_epi64,
    _mm512_and_si512,
    _mm512_or_si512,
    _mm512_srli_epi64,
    _mm512_slli_epi64,
    _mm512_mul_epu32,
    _mm512_sub_epi64,
    _mm512_shuffle_epi32,
    |x: i64, y: i64| _mm512_set_epi64(y, x, y, x, y, x, y, x),
    |r: __m512i, s: __m512i| _mm512_mask_blend_epi64(0b1010_1010, r, s)
);

/// Exact int8 dot products (RFC-0014 §2 `recompute_layer_int8`): bytes are sign-extended
/// to 16 bits and multiplied in pairs into 32-bit lanes, which add with wrap-around like
/// the reference. A pair of products of sign-extended bytes is at most `2·2^14`, so
/// `madd` never saturates.
pub(crate) mod dot {
    use core::arch::x86_64::*;

    /// The wrapping sum of `x[j]·w[j]` over the first `done` bytes (returned), 16 at a time.
    #[target_feature(enable = "avx2")]
    pub(crate) unsafe fn avx2(x: *const i8, w: *const u8, n: usize) -> (i32, usize) {
        let done = n / 16 * 16;
        let mut lanes = [0i32; 8];
        // SAFETY: RFC-0003 §6: the caller enables the feature and supplies `n` bytes
        // behind each pointer; each load covers 16 bytes below `done <= n`.
        unsafe {
            let mut acc = _mm256_setzero_si256();
            let mut i = 0;
            while i < done {
                let a = _mm256_cvtepi8_epi16(_mm_loadu_si128(x.add(i).cast()));
                let b = _mm256_cvtepi8_epi16(_mm_loadu_si128(w.add(i).cast()));
                acc = _mm256_add_epi32(acc, _mm256_madd_epi16(a, b));
                i += 16;
            }
            _mm256_storeu_si256(lanes.as_mut_ptr().cast(), acc);
        }
        (
            lanes.iter().fold(0i32, |sum, lane| sum.wrapping_add(*lane)),
            done,
        )
    }

    /// As [`avx2`], 32 bytes at a time.
    #[target_feature(enable = "avx512f,avx512bw")]
    pub(crate) unsafe fn avx512(x: *const i8, w: *const u8, n: usize) -> (i32, usize) {
        let done = n / 32 * 32;
        let mut lanes = [0i32; 16];
        // SAFETY: RFC-0003 §6: the caller enables the features and supplies `n` bytes
        // behind each pointer; each load covers 32 bytes below `done <= n`.
        unsafe {
            let mut acc = _mm512_setzero_si512();
            let mut i = 0;
            while i < done {
                let a = _mm512_cvtepi8_epi16(_mm256_loadu_si256(x.add(i).cast()));
                let b = _mm512_cvtepi8_epi16(_mm256_loadu_si256(w.add(i).cast()));
                acc = _mm512_add_epi32(acc, _mm512_madd_epi16(a, b));
                i += 32;
            }
            _mm512_storeu_si512(lanes.as_mut_ptr().cast(), acc);
        }
        (
            lanes.iter().fold(0i32, |sum, lane| sum.wrapping_add(*lane)),
            done,
        )
    }
}

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
            /// `lo[j] += c·(hi[j] − lo[j])` on whole vectors of QM31 elements (four `u32`
            /// limbs each, basis order). Returns the number of elements done; the caller
            /// finishes the tail with the reference.
            #[target_feature(enable=$feature)]
            pub(crate) unsafe fn fold(
                lo: *mut u32,
                hi: *const u32,
                n: usize,
                c: [u32; 4],
            ) -> usize {
                let per = $width / 4;
                let p32 = $dup32(P as i32);
                let four_p = $dup64(4 * i64::from(P));
                let (c0, c1, d0, d1) = (
                    i64::from(c[0]),
                    i64::from(c[1]),
                    i64::from(c[2]),
                    i64::from(c[3]),
                );
                let (nc1, nd1) = (i64::from(P) - c1, i64::from(P) - d1);
                // Per element two 64-bit lanes: lane 0 meets the a limbs, lane 1 the b limbs.
                // With x = (a0, a1, b0, b1) and c = (c0, c1, d0, d1), i² = −1, u² = 2 + i:
                //   ac = (a0c0 − a1c1, a0c1 + a1c0), bd likewise,
                //   r = ac + (2 + i)·bd, s = ad + bc.
                // A subtracted product x·y is added as x·(p − y), so every lane is a sum of
                // at most four products below p², below 2^64.
                let (k1, k2, k3) = ($pair(c0, d0), $pair(nc1, nd1), $pair(c1, d1));
                let (k5, k6, k7) = ($pair(d0, c0), $pair(nd1, nc1), $pair(d1, c1));
                let done = n / per * per;
                let mut i = 0;
                // SAFETY: RFC-0003 §6: the caller enables the feature and supplies `n`
                // elements behind each pointer; each load and store covers `per` whole
                // elements below `done <= n`.
                unsafe {
                    while i < done {
                        let a = $load(lo.add(4 * i).cast());
                        let b = $load(hi.add(4 * i).cast());
                        // d = b − a per limb, canonical.
                        let d = canonical($minus32($plus32(b, p32), a));
                        let odd = $shr::<32>(d);
                        let v1 = $plus64($times(d, k1), $times(odd, k2)); // (ac0, bd0)
                        let v2 = $plus64($times(d, k3), $times(odd, k1)); // (ac1, bd1)
                        let s0 = $plus64($times(d, k5), $times(odd, k6)); // halves of s0
                        let s1 = $plus64($times(d, k7), $times(odd, k5)); // halves of s1
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
                        let r = $or(r0, $shl::<32>(r1));
                        let s = $or(s0, $shl::<32>(s1));
                        // (r0, r1) from lane 0 and (s0, s1) from lane 1 of each element.
                        let product = $blend(r, s);
                        $store(lo.add(4 * i).cast(), canonical($plus32(a, product)));
                        i += per;
                    }
                }
                done
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

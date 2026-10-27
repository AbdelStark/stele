//! AVX2/AVX-512 widening products in even/odd lanes (RFC-0003 §§1,6).
macro_rules! x86_backend {
    ($name:ident,$feature:literal,$width:expr,$v:ty,
     $load:ident,$store:ident,$dup32:ident,$dup64:ident,$plus32:ident,$minus32:ident,
     $min:ident,$plus64:ident,$and:ident,$or:ident,$shr:ident,$shl:ident,$times:ident) => {
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
    _mm256_mul_epu32
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
    _mm512_mul_epu32
);

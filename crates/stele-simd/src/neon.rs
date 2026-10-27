//! NEON M31 limbs, widening products and canonical exits (RFC-0003 §§1,6).
use crate::P;
use core::arch::aarch64::*;

#[target_feature(enable = "neon")]
unsafe fn load(p: *const u32) -> uint32x4_t {
    // SAFETY: RFC-0003 §6: caller supplies four readable lanes; NEON is enabled.
    unsafe { vld1q_u32(p) }
}
#[target_feature(enable = "neon")]
unsafe fn store(p: *mut u32, v: uint32x4_t) {
    // SAFETY: RFC-0003 §6: caller supplies four writable lanes; NEON is enabled.
    unsafe { vst1q_u32(p, v) }
}
#[target_feature(enable = "neon")]
unsafe fn canonical(a: uint32x4_t) -> uint32x4_t {
    // INV: lazy — unsigned min selects a-p only when a>=p, with a<2p.
    vminq_u32(a, vsubq_u32(a, vdupq_n_u32(P)))
}
#[target_feature(enable = "neon")]
unsafe fn add(a: uint32x4_t, b: uint32x4_t) -> uint32x4_t {
    // SAFETY: RFC-0003 §1: canonical operands sum to <2p; feature is enabled.
    unsafe { canonical(vaddq_u32(a, b)) }
}
#[target_feature(enable = "neon")]
unsafe fn sub(a: uint32x4_t, b: uint32x4_t) -> uint32x4_t {
    // SAFETY: RFC-0003 §1: a+p-b lies in [1,2p); feature is enabled.
    unsafe { canonical(vsubq_u32(vaddq_u32(a, vdupq_n_u32(P)), b)) }
}
#[target_feature(enable = "neon")]
unsafe fn mul(a: uint32x4_t, b: uint32x4_t) -> uint32x4_t {
    let low = vmull_u32(vget_low_u32(a), vget_low_u32(b));
    let high = vmull_u32(vget_high_u32(a), vget_high_u32(b));
    let mask = vdupq_n_u64(u64::from(P));
    let low = vaddq_u64(vandq_u64(low, mask), vshrq_n_u64::<31>(low));
    let high = vaddq_u64(vandq_u64(high, mask), vshrq_n_u64::<31>(high));
    // SAFETY: RFC-0003 §1: product <p²; one Mersenne fold is <2p and fits u32.
    unsafe { canonical(vcombine_u32(vmovn_u64(low), vmovn_u64(high))) }
}
kernels!("neon", 4, uint32x4_t);

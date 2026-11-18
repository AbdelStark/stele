// RFC-0013 A5 item 3: each table is interpolated in the current leading variable.
// Flags: bit 0 = base x, bit 1 = mask active now, bit 2 = base mask.
// Higher bits encode 1 + log2(native period) for an unmasked tiled extension.
__device__ __forceinline__ u32 round_base(const u32 *x, u64 j, u64 half, u32 t) {
  return madd(x[j], mmul(msub(x[j + half], x[j]), t));
}
__device__ __forceinline__ Q round_ext(const u32 *x, u64 j, u64 half, u32 t) {
  Q a = qload(x, j);
  return qadd(a, qmulm(qsub(qload(x, j + half), a), t));
}
// Fixed-size code: factors and terms are data, including repeated and empty products.
__device__ __forceinline__ Q round_entry(const u64 *xs, const u64 *rs, const u32 *flags,
    const u32 *offsets, const u32 *indices, const u32 *coef, u32 terms, u64 j, u64 half, u32 t) {
  Q sum = qzero();
  u32 kap = mmul(t, msub(1u, t));
  #pragma unroll 1
  for (u32 term = 0; term < terms; term++) {
    u32 mp = 1u;
    Q qp = qembed(1u);
    #pragma unroll 1
    for (u32 i = offsets[term]; i < offsets[term + 1]; i++) {
      u32 k = indices[i], flag = flags[k];
      const u32 *x = (const u32 *)xs[k];
      bool xb = flag & 1u, masked = flag & 2u, rb = flag & 4u;
      u32 period_code = flag >> 3;
      if (period_code) {
        // Both leading-bit branches equal this cell for the entire current round.
        u64 mask = (1ull << (period_code - 1)) - 1;
        qp = qmul(qp, qload(x, j & mask));
      } else if (xb && (!masked || rb)) {
        u32 v = round_base(x, j, half, t);
        if (masked && t > 1) v = madd(v, mmul(kap, round_base((const u32 *)rs[k], j, half, t)));
        mp = mmul(mp, v);
      } else {
        Q v = xb ? qembed(round_base(x, j, half, t)) : round_ext(x, j, half, t);
        if (masked && t > 1) {
          Q r = rb ? qembed(round_base((const u32 *)rs[k], j, half, t)) : round_ext((const u32 *)rs[k], j, half, t);
          v = qadd(v, qmulm(r, kap));
        }
        qp = qmul(qp, v);
      }
    }
    sum = qadd(sum, qmul(qload(coef, term), qmulm(qp, mp)));
  }
  return sum;
}

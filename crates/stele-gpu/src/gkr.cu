// RFC-0008 A7: evaluate one span of an actual GKR factor on its original inputs.
// Operations are the repr(u32) variants of gkr_build::Op, in order.
__device__ __forceinline__ Q gkr_entry(u32 op, u32 arg, u32 pos, u32 begin,
                                      const u32 *data, const u32 *shifts, u32 shift_count) {
  switch (op) {
  case 0: // Constant.
    return qembed(arg);
  case 1: { // Equality, variable zero is the most significant bit.
    Q value = qload(data, 0);
    for (u32 k = 0; k < arg; ++k) {
      Q point = qload(data, 1 + k);
      bool bit = ((pos - begin) >> (arg - 1 - k)) & 1;
      value = qmul(value, bit ? point : qsub(qembed(1), point));
    }
    return value;
  }
  case 2: { // Interpolated mask block with a tiled low-bit index.
    u64 x = pos % arg;
    u32 a = data[4 + x], b = data[4 + arg + x];
    return qadd(qembed(a), qmulm(qload(data, 0), msub(b, a)));
  }
  case 3: // GatherBase.
  case 4: { // GatherExt.
    u64 x = 0;
    for (u32 k = 0; k < shift_count; ++k)
      x = (x << 1) | ((pos >> shifts[k]) & 1);
    Q value = op == 3 ? qembed(data[x]) : qload(data, x);
    return qadd(value, qembed(arg));
  }
  case 6: { // alpha minus the beta-compressed public row.
    Q value = qzero(), beta = qload(data, 1);
    const u32 *row = data + 8 + (u64)pos * arg;
    for (u32 k = arg; k > 0; --k)
      value = qadd(qmul(value, beta), qembed(row[k - 1]));
    return qsub(qload(data, 0), value);
  }
  default: // Unreachable: the host passes only Op variants.
    return qzero();
  }
}

extern "C" __global__ void gkr_build_span(u32 *out, u32 base, const u32 *data,
    const u32 *shifts, u32 shift_count, u32 op, u32 arg, u32 period,
    u32 begin, u32 width, u64 count) {
  // Visit only the entries this span owns; one thread per destination.
  GRID_STRIDE(i, count) {
    u32 pos = begin + (u32)(i % width);
    u64 destination = (i / width) * period + pos;
    Q value = gkr_entry(op, arg, pos, begin, data, shifts, shift_count);
    if (base) out[destination] = mcanon(value.a0);
    else qstore(out, destination, value);
  }
}

__device__ __forceinline__ Q fold_at(const u32 *t, int base, u64 i, u64 half, Q c) {
  if (base) {
    u32 a = t[i], b = t[i + half];
    return qadd(qembed(a), qmulm(c, msub(b, a)));
  }
  Q a = qload(t, i), b = qload(t, i + half);
  return qadd(a, qmul(c, qsub(b, a)));
}

// The fold that binds a factor's vanishing variable: out = fold(x) + κ(c)·fold(r)
// (Occurrences::fold). `out` may be `x` when x is QM31: thread i reads i and
// i + half before it writes i, and no other thread touches either.
extern "C" __global__ void fold_mask(u32 *out, const u32 *x, int xbase, const u32 *r, int rbase, u64 half,
                                     u32 c0, u32 c1, u32 c2, u32 c3, u32 k0, u32 k1, u32 k2, u32 k3) {
  Q c = {c0, c1, c2, c3}, kc = {k0, k1, k2, k3};
  GRID_STRIDE(i, half) {
    Q fx = fold_at(x, xbase, i, half, c), fr = fold_at(r, rbase, i, half, c);
    qstore(out, i, qadd(fx, qmul(kc, fr)));
  }
}


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

// RFC-0014 §5: the same per-node j order and fixed block tree as generated rounds.
extern "C" __global__ void round_kernel(const u64 *xs, const u64 *rs, const u32 *flags,
    const u32 *offsets, const u32 *indices, const u32 *coef, u32 terms,
    u64 half, int nodes, u32 *partials) {
  __shared__ Q sh[256];
  #pragma unroll 1
  for (int t = 0; t < nodes; t++) {
    Q acc = qzero();
    GRID_STRIDE(j, half) acc = qadd(acc, round_entry(xs, rs, flags, offsets, indices, coef, terms, j, half, (u32)t));
    block_sum(sh, acc, partials, nodes, t);
  }
}

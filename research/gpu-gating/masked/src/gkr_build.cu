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
  case 5: // Child-layer pairs in row-major order.
    return qload(data, 4ull * pos + arg);
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

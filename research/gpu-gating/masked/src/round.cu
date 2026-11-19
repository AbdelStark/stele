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

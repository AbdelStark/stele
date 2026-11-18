// RFC-0014 A6. Construct one actual A7 parent per original Boolean row.
__device__ __forceinline__ u32 lookup_index(const u32 *axes, u32 count, u32 x) {
  u32 index = 0;
  for (u32 i = 0; i < count; ++i) index = 2 * index + ((x >> axes[i]) & 1);
  return index;
}

// Each validated descriptor selects the original owner's upper-left data quadrant.
__device__ __forceinline__ u32 lookup_original(const u64 *owners, const u32 *col, u32 i) {
  const u32 *data = (const u32 *)owners[col[0]];
  u64 x = (u64)col[1] + i;
  u64 width = 1ull << col[2];
  return mcanon(data[(x / width) * (2 * width) + x % width]);
}

extern "C" __global__ void lookup_first(const u64 *owners, const u32 *desc,
    const u32 *axes, const u32 *fields, u32 *tree, u64 n) {
  Q alpha = qload(fields, 0), beta = qload(fields, 1);
  u32 width = desc[4], members = desc[5], valid = desc[6];
  u64 stride = 5ull + 6ull * width;
  GRID_STRIDE(row, n) {
    u32 x = (u32)row;
    u32 lo = 0, hi = members;
    while (lo < hi) {
      u32 mid = lo + (hi - lo) / 2;
      if (x < desc[7ull + mid * stride + 1]) hi = mid;
      else lo = mid + 1;
    }
    u32 selected = 0;
    Q tuple = qzero();
    if (lo < members) {
      const u32 *m = desc + 7ull + lo * stride;
      selected = m[2] == 0xffffffff ? 1 : mcanon(fields[m[2] + lookup_index(axes + m[3], m[4], x)]);
      Q power = qembed(1);
      for (u32 i = 0; i < width; ++i) {
        const u32 *leg = m + 5ull + 6ull * i;
        u32 at = lookup_index(axes + leg[3], leg[4], x);
        tuple = qadd(tuple, qmulm(power, madd(lookup_original(owners, leg, at), leg[5])));
        power = qmul(power, beta);
      }
    }
    Q table = qembed(1);
    if (x < valid) {
      table = alpha;
      Q power = qembed(1);
      for (u32 i = 0; i < width; ++i) {
        table = qsub(table, qmulm(power, fields[8ull + (u64)x * width + i]));
        power = qmul(power, beta);
      }
    }
    u32 count = x < desc[3] ? lookup_original(owners, desc, x) : 0;
    Q denominator = qsub(alpha, qmulm(tuple, selected));
    u64 pair = n - 1 + x;
    qstore(tree, 2 * pair, qsub(qmulm(table, selected), qmulm(denominator, count)));
    qstore(tree, 2 * pair + 1, qmul(denominator, table));
  }
}

extern "C" __global__ void lookup_parents(u32 *tree, u64 width) {
  GRID_STRIDE(i, width) {
    u64 parent = width - 1 + i, child = 2 * parent + 1;
    Q p0 = qload(tree, 2 * child), q0 = qload(tree, 2 * child + 1);
    Q p1 = qload(tree, 2 * child + 2), q1 = qload(tree, 2 * child + 3);
    qstore(tree, 2 * parent, qadd(qmul(p0, q1), qmul(p1, q0)));
    qstore(tree, 2 * parent + 1, qmul(q0, q1));
  }
}

extern "C" __global__ void lookup_child(const u32 *tree, u32 *out, u64 width, u32 arg, u64 len) {
  GRID_STRIDE(i, len) {
    u64 pair = 2 * width - 1 + 2 * (i % width) + arg / 2;
    qstore(out, i, qload(tree, 2 * pair + arg % 2));
  }
}

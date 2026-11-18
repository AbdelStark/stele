// RFC-0003 §2: inverse by the two quadratic norms; zero is reported by the caller.
__device__ __forceinline__ Q qinverse(Q x) {
  u32 a0, a1, b0, b1;
  cmul(x.a0, x.a1, x.a0, x.a1, a0, a1);
  cmul(x.b0, x.b1, x.b0, x.b1, b0, b1);
  u32 n0 = msub(a0, msub(madd(b0, b0), b1));
  u32 n1 = msub(a1, madd(b0, madd(b1, b1)));
  u32 norm = madd(mmul(n0, n0), mmul(n1, n1)), inv = 1;
  // p-2 has 31 bits. Fixed order, including zero -> zero (RFC-0003 §6).
  for (int bit = 30; bit >= 0; --bit) {
    inv = mmul(inv, inv);
    if (((P - 2) >> bit) & 1) inv = mmul(inv, norm);
  }
  n0 = mmul(n0, inv); n1 = mneg(mmul(n1, inv));
  Q out;
  cmul(x.a0, x.a1, n0, n1, out.a0, out.a1);
  cmul(mneg(x.b0), mneg(x.b1), n0, n1, out.b0, out.b1);
  return out;
}

// RFC-0008 A7: tuple coordinates, table, multiplicities, powers, alpha in that order.
extern "C" __global__ void lookup_leaf(const u32 *in, const u32 *selector, u32 *tree, u64 n, u64 width, u64 mults) {
  const u64 table = n * width, mult = table + n, powers = mult + mults;
  const Q alpha = qload(in, powers + width);
  GRID_STRIDE(x, n) {
    Q compressed = qzero();
    for (u64 c = 0; c < width; ++c) compressed = qadd(compressed, qmul(qload(in, powers + c), qload(in, c * n + x)));
    const u64 leaf = 2 * n - 1 + 2 * x;
    qstore(tree, 2 * leaf, qembed(selector[x]));
    qstore(tree, 2 * leaf + 1, qsub(alpha, qmulm(compressed, selector[x])));
    qstore(tree, 2 * leaf + 2, x < mults ? qsub(qzero(), qload(in, mult + x)) : qzero());
    qstore(tree, 2 * leaf + 3, qload(in, table + x));
  }
}

// Root-first storage: a layer of count pairs starts at pair count-1.
extern "C" __global__ void lookup_level(u32 *tree, u64 count) {
  GRID_STRIDE(x, count) {
    const u64 child = 2 * (2 * count - 1 + 2 * x), parent = 2 * (count - 1 + x);
    Q p0 = qload(tree, child), q0 = qload(tree, child + 1);
    Q p1 = qload(tree, child + 2), q1 = qload(tree, child + 3);
    qstore(tree, parent, qadd(qmul(p0, q1), qmul(p1, q0)));
    qstore(tree, parent + 1, qmul(q0, q1));
  }
}

extern "C" __global__ void lookup_top(const u32 *tree, u32 *h, u32 *flags, u64 count) {
  GRID_STRIDE(x, count) {
    const u64 pair = 2 * (count - 1 + x);
    Q q = qload(tree, pair + 1);
    flags[x] = !(mcanon(q.a0) | mcanon(q.a1) | mcanon(q.b0) | mcanon(q.b1));
    qstore(h, x, qmul(qload(tree, pair), qinverse(q)));
  }
}

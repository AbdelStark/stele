// E16-35 (ADR-123): device kernels for the dev-zk masked rounds (RFC-0013 A5 item 2,
// RFC-0008 A7 item 4). Compiled at run time by NVRTC; the round kernel is generated per
// round shape by gpu.rs and appended to this source. Integer arithmetic only; every
// value leaving a kernel is canonical in [0, p). Field code as E16-21's dense_gpu.cu.
typedef unsigned int u32;
typedef unsigned long long u64;
#define P 0x7fffffffu

// QM31 = CM31[u]/(u^2 - (2 + i)), limbs (a0, a1, b0, b1) as stele-field's to_le_bytes.
struct Q { u32 a0, a1, b0, b1; };

__device__ __forceinline__ u32 madd(u32 a, u32 b) { u32 s = a + b; s = (s & P) + (s >> 31); return s == P ? 0 : s; }
__device__ __forceinline__ u32 mneg(u32 a) { return a == 0 ? 0 : P - a; }
__device__ __forceinline__ u32 msub(u32 a, u32 b) { return madd(a, mneg(b)); }
__device__ __forceinline__ u32 mmul(u32 a, u32 b) {
  u64 x = (u64)a * b;
  u32 s = (u32)(x & P) + (u32)(x >> 31);
  s = (s & P) + (s >> 31);
  return s == P ? 0 : s;
}
__device__ __forceinline__ Q qzero() { Q z = {0, 0, 0, 0}; return z; }
__device__ __forceinline__ Q qembed(u32 a) { Q z = {a, 0, 0, 0}; return z; }
__device__ __forceinline__ Q qadd(Q x, Q y) { Q z = {madd(x.a0, y.a0), madd(x.a1, y.a1), madd(x.b0, y.b0), madd(x.b1, y.b1)}; return z; }
__device__ __forceinline__ Q qsub(Q x, Q y) { Q z = {msub(x.a0, y.a0), msub(x.a1, y.a1), msub(x.b0, y.b0), msub(x.b1, y.b1)}; return z; }
// x · m for m in M31: coefficient-wise (stele-field mul_m31).
__device__ __forceinline__ Q qmulm(Q x, u32 m) { Q z = {mmul(x.a0, m), mmul(x.a1, m), mmul(x.b0, m), mmul(x.b1, m)}; return z; }
// CM31 product (a + b i)(c + d i), i^2 = -1.
__device__ __forceinline__ void cmul(u32 a, u32 b, u32 c, u32 d, u32 &r0, u32 &r1) {
  u32 ac = mmul(a, c), bd = mmul(b, d);
  r0 = msub(ac, bd);
  r1 = msub(msub(mmul(madd(a, b), madd(c, d)), ac), bd);
}
__device__ __forceinline__ Q qmul(Q x, Q y) {
  u32 ac0, ac1, bd0, bd1, s0, s1;
  cmul(x.a0, x.a1, y.a0, y.a1, ac0, ac1);
  cmul(x.b0, x.b1, y.b0, y.b1, bd0, bd1);
  cmul(madd(x.a0, x.b0), madd(x.a1, x.b1), madd(y.a0, y.b0), madd(y.a1, y.b1), s0, s1);
  u32 n0 = msub(madd(bd0, bd0), bd1), n1 = madd(bd0, madd(bd1, bd1));  // (2 + i)·bd
  Q z = {madd(ac0, n0), madd(ac1, n1), msub(msub(s0, ac0), bd0), msub(msub(s1, ac1), bd1)};
  return z;
}
__device__ __forceinline__ Q qload(const u32 *t, u64 i) { const Q *q = (const Q *)t; return q[i]; }
__device__ __forceinline__ void qstore(u32 *t, u64 i, Q v) { Q *q = (Q *)t; q[i] = v; }
#define GRID_STRIDE(j, n) for (u64 j = blockIdx.x * (u64)blockDim.x + threadIdx.x; j < (n); j += (u64)gridDim.x * blockDim.x)

// out[i] = scale · eq(point, i), variable 0 the most significant bit of i
// (stele_sumcheck::parallel::eq_table's order). Every entry is the same product of the
// same factors as the CPU's, and the field is exact, so the value is the same element.
extern "C" __global__ void eq_kernel(u32 *out, const u32 *point, int nv, u32 s0, u32 s1, u32 s2, u32 s3, u64 count) {
  Q scale = {s0, s1, s2, s3};
  Q one = qembed(1);
  GRID_STRIDE(i, count) {
    Q acc = scale;
    for (int k = 0; k < nv; k++) {
      Q r = qload(point, k);
      acc = qmul(acc, ((i >> (nv - 1 - k)) & 1) ? r : qsub(one, r));
    }
    qstore(out, i, acc);
  }
}

// out[i] = period[i & (len - 1)] (a tiled block factor, zk_lookup Gin::Block).
extern "C" __global__ void tile_kernel(u32 *out, const u32 *period, u64 mask, u64 count) {
  GRID_STRIDE(i, count) qstore(out, i, qload(period, i & mask));
}

// x[half + i] = x[i] (zk_lookup's `both`).
extern "C" __global__ void dup_kernel(u32 *x, u64 half) {
  GRID_STRIDE(i, half) qstore(x, half + i, qload(x, i));
}

// The mask table r̂(X) = r̃(X_u) (zk_claims block_table): entry bits from u, MSB first.
extern "C" __global__ void mask_kernel(u32 *out, const u32 *block, const u32 *u, int ulen, int n, u64 count) {
  GRID_STRIDE(i, count) {
    u64 e = 0;
    for (int k = 0; k < ulen; k++) e |= ((i >> (n - 1 - (int)u[k])) & 1) << (ulen - 1 - k);
    out[i] = block[e];
  }
}

// x[i] = x[i] + c·(x[i + half] − x[i]) in place (stele_sumcheck::parallel::fold).
extern "C" __global__ void fold_ext(u32 *x, u64 half, u32 c0, u32 c1, u32 c2, u32 c3) {
  Q c = {c0, c1, c2, c3};
  GRID_STRIDE(i, half) {
    Q a = qload(x, i), b = qload(x, i + half);
    qstore(x, i, qadd(a, qmul(c, qsub(b, a))));
  }
}

// The first fold of a base table: out[i] = a + c·(b − a) with a, b in M31.
extern "C" __global__ void fold_base(const u32 *x, u32 *out, u64 half, u32 c0, u32 c1, u32 c2, u32 c3) {
  Q c = {c0, c1, c2, c3};
  GRID_STRIDE(i, half) {
    u32 a = x[i], b = x[i + half];
    qstore(out, i, qadd(qembed(a), qmulm(c, msub(b, a))));
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

// out[t] = Σ_b partials[b][t], blocks in order (no atomics).
extern "C" __global__ void reduce_kernel(const u32 *partials, int blocks, int nodes, u32 *out) {
  int t = threadIdx.x;
  if (t >= nodes) return;
  Q s = qzero();
  for (int b = 0; b < blocks; b++) s = qadd(s, qload(partials, (u64)b * nodes + t));
  qstore(out, t, s);
}

// Fixed-order block tree of one node's per-thread sums; thread 0 writes the block's.
__device__ __forceinline__ void block_sum(Q *sh, Q v, u32 *partials, int nodes, int t) {
  sh[threadIdx.x] = v;
  __syncthreads();
  for (int s = blockDim.x / 2; s > 0; s >>= 1) {
    if (threadIdx.x < s) sh[threadIdx.x] = qadd(sh[threadIdx.x], sh[threadIdx.x + s]);
    __syncthreads();
  }
  if (threadIdx.x == 0) qstore(partials, (u64)blockIdx.x * nodes + t, sh[0]);
  __syncthreads();
}

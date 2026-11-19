// RFC-0014 A2. M31 and QM31 dense batch arithmetic, RFC-0013 A5 item 5.
typedef unsigned int u32;
typedef unsigned long long u64;
#define P 0x7fffffffu

// QM31 = CM31[u]/(u^2 - (2 + i)), limbs (a0, a1, b0, b1) as stele-field's to_le_bytes.
struct Q { u32 a0, a1, b0, b1; };

// INV: lazy — inputs are in [0,2p). Keep the carry and first product fold in
// u64; the last fold is below 2p. Canonicalise stored limbs (RFC-0003 §1).
__device__ __forceinline__ u32 mcanon(u32 a) { return a >= P ? a - P : a; }
__device__ __forceinline__ u32 madd(u32 a, u32 b) { u64 s = (u64)a + b; return mcanon((u32)(s & P) + (u32)(s >> 31)); }
__device__ __forceinline__ u32 mneg(u32 a) { a = mcanon(a); return a == 0 ? 0 : P - a; }
__device__ __forceinline__ u32 msub(u32 a, u32 b) { return madd(a, mneg(b)); }
__device__ __forceinline__ u32 mmul(u32 a, u32 b) {
  u64 x = (u64)a * b;
  u64 s = (x & P) + (x >> 31);
  return mcanon((u32)(s & P) + (u32)(s >> 31));
}
__device__ __forceinline__ Q qzero() { Q z = {0, 0, 0, 0}; return z; }
__device__ __forceinline__ Q qembed(u32 a) { Q z = {mcanon(a), 0, 0, 0}; return z; }
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
__device__ __forceinline__ void qstore(u32 *t, u64 i, Q v) { Q *q = (Q *)t; Q c = {mcanon(v.a0), mcanon(v.a1), mcanon(v.b0), mcanon(v.b1)}; q[i] = c; }
#define GRID_STRIDE(j, n) for (u64 j = blockIdx.x * (u64)blockDim.x + threadIdx.x; j < (n); j += (u64)gridDim.x * blockDim.x)

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
// RFC-0013 A5 item 5: one thread owns one data position. Runs in its tile
// preserve claim and contribution order, even for overlapping or repeated positions.
extern "C" __global__ void batch_weights(const u32 *packed, const u32 *gammas,
    const u64 *runs, const u64 *offsets, u32 *weights, u64 tile, u64 half) {
  GRID_STRIDE(i, half) {
    Q sum = qzero();
    const u64 t = i / tile;
    for (u64 j = offsets[t]; j < offsets[t + 1]; ++j) {
      const u64 *r = runs + 4*j;
      if (r[0] <= i && i < r[1])
        sum = qadd(sum, qmul(qload(packed, r[2] + (i-r[0])), qload(gammas, r[3])));
    }
    qstore(weights, i, sum);
  }
}

// Y=0 of every row, including mask rows. Keep the source at M31 width.
extern "C" __global__ void batch_face(const u32 *message, u32 *face, u64 columns, u64 len) {
  GRID_STRIDE(i, len) face[i] = mcanon(message[(i/columns)*2*columns + i%columns]);
}

// Keep the original face at base-field width until the first transcript fold.
extern "C" __global__ void dense_round(const u32 *weights, const u32 *face,
    u32 base, u64 half, u32 *partials) {
  __shared__ Q sh[256];
  Q sums[3] = {qzero(), qzero(), qzero()};
  GRID_STRIDE(i, half) {
    Q w0 = qload(weights, i), w1 = qload(weights, i + half);
    Q w2 = qadd(w1, qsub(w1, w0));
    if (base) {
      u32 v0 = face[i], v1 = face[i + half];
      sums[0] = qadd(sums[0], qmulm(w0, v0));
      sums[1] = qadd(sums[1], qmulm(w1, v1));
      sums[2] = qadd(sums[2], qmulm(w2, madd(v1, msub(v1, v0))));
    } else {
      Q v0 = qload(face, i), v1 = qload(face, i + half);
      sums[0] = qadd(sums[0], qmul(w0, v0));
      sums[1] = qadd(sums[1], qmul(w1, v1));
      sums[2] = qadd(sums[2], qmul(w2, qadd(v1, qsub(v1, v0))));
    }
  }
  for (int t = 0; t < 3; ++t) block_sum(sh, sums[t], partials, 3, t);
}

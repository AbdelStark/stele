// E16-21 GPU gating micro-benchmark (RFC-0014 §1, §5): device-resident dense
// sumcheck over QM31 for a single product term of K tables (degree K). Tables are
// uploaded once; each round computes the K+1 node sums on the device, copies them to
// the host (Fiat-Shamir round trip), and folds with the host's challenge.
// Output FNV must equal the Rust Dense reference (dense_cpu.rs). Research code.
// Build: nvcc -O3 -arch=sm_89 -o dense_gpu dense_gpu.cu; run: ./dense_gpu <K> <logn>.
// Ledger: bench/ledger/e16-21-gpu-gating.json.
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <vector>
#include <chrono>
#include <cuda_runtime.h>

typedef uint32_t u32;
typedef uint64_t u64;
#define P 0x7fffffffu
#define CK(x) do { cudaError_t e = (x); if (e != cudaSuccess) { fprintf(stderr, "%s:%d %s\n", __FILE__, __LINE__, cudaGetErrorString(e)); exit(1); } } while (0)

struct Q { u32 a0, a1, b0, b1; };

__host__ __device__ inline u32 madd(u32 a, u32 b) { u32 s = a + b; s = (s & P) + (s >> 31); return s == P ? 0 : s; }
__host__ __device__ inline u32 msub(u32 a, u32 b) { return madd(a, P - b == P ? 0 : P - b); }
__host__ __device__ inline u32 mmul(u32 a, u32 b) { u64 x = (u64)a * b; u32 s = (u32)(x & P) + (u32)(x >> 31); s = (s & P) + (s >> 31); return s == P ? 0 : s; }
__host__ __device__ inline Q qadd(Q x, Q y) { return {madd(x.a0, y.a0), madd(x.a1, y.a1), madd(x.b0, y.b0), madd(x.b1, y.b1)}; }
__host__ __device__ inline Q qsub(Q x, Q y) { return {msub(x.a0, y.a0), msub(x.a1, y.a1), msub(x.b0, y.b0), msub(x.b1, y.b1)}; }
// CM31 product (a + b i)(c + d i), i^2 = -1.
__host__ __device__ inline void cmul(u32 a, u32 b, u32 c, u32 d, u32 &r0, u32 &r1) {
  u32 ac = mmul(a, c), bd = mmul(b, d);
  r0 = msub(ac, bd);
  r1 = msub(msub(mmul(madd(a, b), madd(c, d)), ac), bd);
}
// QM31 = CM31[u]/(u^2 - (2 + i)).
__host__ __device__ inline Q qmul(Q x, Q y) {
  u32 ac0, ac1, bd0, bd1, s0, s1;
  cmul(x.a0, x.a1, y.a0, y.a1, ac0, ac1);
  cmul(x.b0, x.b1, y.b0, y.b1, bd0, bd1);
  cmul(madd(x.a0, x.b0), madd(x.a1, x.b1), madd(y.a0, y.b0), madd(y.a1, y.b1), s0, s1);
  u32 n0 = msub(madd(bd0, bd0), bd1), n1 = madd(bd0, madd(bd1, bd1));  // (2+i)·bd
  return {madd(ac0, n0), madd(ac1, n1), msub(msub(s0, ac0), bd0), msub(msub(s1, ac1), bd1)};
}

template <int K>
__global__ void round_kernel(Q *const *tables, u64 half, Q *partials) {
  __shared__ Q sh[256][K + 1];
  Q acc[K + 1];
  for (int x = 0; x <= K; x++) acc[x] = {0, 0, 0, 0};
  for (u64 j = blockIdx.x * (u64)blockDim.x + threadIdx.x; j < half; j += (u64)gridDim.x * blockDim.x) {
    Q v[K], d[K];
#pragma unroll
    for (int t = 0; t < K; t++) { v[t] = tables[t][j]; d[t] = qsub(tables[t][j + half], v[t]); }
#pragma unroll
    for (int x = 0; x <= K; x++) {
      Q p = v[0];
#pragma unroll
      for (int t = 1; t < K; t++) p = qmul(p, v[t]);
      acc[x] = qadd(acc[x], p);
#pragma unroll
      for (int t = 0; t < K; t++) v[t] = qadd(v[t], d[t]);
    }
  }
  for (int x = 0; x <= K; x++) sh[threadIdx.x][x] = acc[x];
  __syncthreads();
  for (int s = blockDim.x / 2; s > 0; s >>= 1) {  // fixed tree order
    if (threadIdx.x < s)
      for (int x = 0; x <= K; x++) sh[threadIdx.x][x] = qadd(sh[threadIdx.x][x], sh[threadIdx.x + s][x]);
    __syncthreads();
  }
  if (threadIdx.x == 0)
    for (int x = 0; x <= K; x++) partials[blockIdx.x * (K + 1) + x] = sh[0][x];
}

template <int K>
__global__ void reduce_kernel(const Q *partials, int blocks, Q *out) {
  // One thread per node, block-id order.
  int x = threadIdx.x;
  if (x > K) return;
  Q s = {0, 0, 0, 0};
  for (int b = 0; b < blocks; b++) s = qadd(s, partials[b * (K + 1) + x]);
  out[x] = s;
}

template <int K>
__global__ void fold_kernel(Q *const *tables, u64 half, Q r) {
  for (u64 j = blockIdx.x * (u64)blockDim.x + threadIdx.x; j < half; j += (u64)gridDim.x * blockDim.x) {
#pragma unroll
    for (int t = 0; t < K; t++) {
      Q a = tables[t][j], b = tables[t][j + half];
      tables[t][j] = qadd(a, qmul(r, qsub(b, a)));
    }
  }
}

static u32 from_i64(int64_t v) { int64_t m = v % (int64_t)P; if (m < 0) m += P; return (u32)m; }
static u64 fnv = 0xcbf29ce484222325ull;
static void fnv_q(Q q) {
  u32 w[4] = {q.a0, q.a1, q.b0, q.b1};
  for (int i = 0; i < 4; i++) for (int b = 0; b < 4; b++) { fnv ^= (w[i] >> (8 * b)) & 0xff; fnv *= 0x100000001b3ull; }
}
static Q challenge(int i) {
  return {from_i64(1000003LL * i + 17), from_i64(7919LL * i + 5), from_i64(104729LL * i + 3), from_i64(31337LL * i + 11)};
}

template <int K>
int run(int logn) {
  u64 n = 1ull << logn;
  std::vector<std::vector<Q>> host(K, std::vector<Q>(n));
  const int64_t a[4] = {73, 29, 41, 13}, b[4] = {19, 7, 3, 23}, q[4] = {1048573, 1048571, 999983, 1000003};
  for (int t = 0; t < K; t++)
    for (u64 j = 0; j < n; j++) host[t][j] = {from_i64((int64_t)((j * a[t] + b[t]) % q[t]) - q[t] / 2), 0, 0, 0};
  int blocks = 0, dev = 0;
  CK(cudaGetDevice(&dev));
  CK(cudaDeviceGetAttribute(&blocks, cudaDevAttrMultiProcessorCount, dev));
  blocks *= 8;
  Q *tabs[K];
  Q **dtabs, *partials, *dout;
  CK(cudaMalloc(&dtabs, K * sizeof(Q *)));
  CK(cudaMalloc(&partials, blocks * (K + 1) * sizeof(Q)));
  CK(cudaMalloc(&dout, (K + 1) * sizeof(Q)));
  for (int t = 0; t < K; t++) CK(cudaMalloc(&tabs[t], n * sizeof(Q)));
  CK(cudaDeviceSynchronize());
  auto t0 = std::chrono::steady_clock::now();
  for (int t = 0; t < K; t++) CK(cudaMemcpy(tabs[t], host[t].data(), n * sizeof(Q), cudaMemcpyHostToDevice));
  CK(cudaMemcpy(dtabs, tabs, K * sizeof(Q *), cudaMemcpyHostToDevice));
  auto t1 = std::chrono::steady_clock::now();
  Q row[K + 1];
  for (int i = 0; i < logn; i++) {
    u64 half = n >> (i + 1);
    int g = (int)std::min<u64>((u64)blocks, (half + 255) / 256);
    round_kernel<K><<<g, 256>>>(dtabs, half, partials);
    reduce_kernel<K><<<1, 32>>>(partials, g, dout);
    CK(cudaMemcpy(row, dout, sizeof(row), cudaMemcpyDeviceToHost));
    for (int x = 0; x <= K; x++) fnv_q(row[x]);
    fold_kernel<K><<<g, 256>>>(dtabs, half, challenge(i));
  }
  for (int t = 0; t < K; t++) { Q f; CK(cudaMemcpy(&f, tabs[t], sizeof(Q), cudaMemcpyDeviceToHost)); fnv_q(f); }
  CK(cudaDeviceSynchronize());
  auto t2 = std::chrono::steady_clock::now();
  double up = std::chrono::duration<double>(t1 - t0).count(), rounds = std::chrono::duration<double>(t2 - t1).count();
  printf("gpu K=%d logn=%d upload_s=%.4f rounds_s=%.4f total_s=%.4f bytes=%llu fnv=%016llx\n", K, logn, up, rounds, up + rounds,
         (unsigned long long)(K * n * sizeof(Q)), (unsigned long long)fnv);
  for (int t = 0; t < K; t++) cudaFree(tabs[t]);
  cudaFree(dtabs); cudaFree(partials); cudaFree(dout);
  return 0;
}

int main(int argc, char **argv) {
  if (argc != 3) { fprintf(stderr, "usage: dense_gpu K logn\n"); return 2; }
  int k = atoi(argv[1]), logn = atoi(argv[2]);
  cudaFree(0);  // context creation outside the timed region
  switch (k) { case 2: return run<2>(logn); case 3: return run<3>(logn); case 4: return run<4>(logn); }
  return 2;
}

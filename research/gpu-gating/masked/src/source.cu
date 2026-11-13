// E16-36: hiding-source preparation on the device (RFC-0010 A2 Circle encoding,
// RFC-0012 A3 Merkle tree, RFC-0013 A8 salts). Mirrors src/source.rs step for step.
// Appended to kernels.cu (u32, u64, P, madd, msub, mmul, GRID_STRIDE).

// Row-major `msg` (rows × n) into the symbol-major head of `x` (x[c·rows + r]).
extern "C" __global__ void transpose_kernel(const u32 *msg, u32 *x, u64 rows, u64 n) {
  __shared__ u32 tile[32][33];
  u64 c0 = (u64)blockIdx.x * 32, r0 = (u64)blockIdx.y * 32;
  for (int k = threadIdx.y; k < 32; k += blockDim.y) {
    u64 r = r0 + k, c = c0 + threadIdx.x;
    if (r < rows && c < n) tile[k][threadIdx.x] = msg[r * n + c];
  }
  __syncthreads();
  for (int k = threadIdx.y; k < 32; k += blockDim.y) {
    u64 c = c0 + k, r = r0 + threadIdx.x;
    if (r < rows && c < n) x[c * rows + r] = tile[threadIdx.x][k];
  }
}

// Swap symbols i and rev(i) of every row.
extern "C" __global__ void bitrev_kernel(u32 *x, u64 rows, int log) {
  GRID_STRIDE(t, ((u64)1 << log) * rows) {
    u64 i = t / rows, r = t % rows;
    u64 j = __brevll(i) >> (64 - log);
    if (i < j) {
      u32 a = x[i * rows + r];
      x[i * rows + r] = x[j * rows + r];
      x[j * rows + r] = a;
    }
  }
}

// One butterfly level (src/source.rs `level`): blocks of width 2h, the quad
// {j, h-1-j, h+j, 2h-1-j} per thread, closed under the level's reads and writes.
extern "C" __global__ void level_kernel(u32 *x, const u32 *tw, u64 h, u64 rows, u64 n, int inverse) {
  u64 per = (h + 1) / 2, w = 2 * h;
  GRID_STRIDE(t, (n / w) * per * rows) {
    u64 r = t % rows, q = t / rows;
    u64 base = (q / per) * w, j = q % per;
    u64 p0 = base + j, p1 = base + h - 1 - j, p2 = base + h + j, p3 = base + w - 1 - j;
    u32 v0 = x[p0 * rows + r], v1 = x[p1 * rows + r], v2 = x[p2 * rows + r], v3 = x[p3 * rows + r];
    u32 t0 = tw[j], t1 = tw[h - 1 - j];
    if (inverse) {
      x[p0 * rows + r] = madd(v0, v3);
      x[p2 * rows + r] = mmul(msub(v0, v3), t0);
      if (p1 != p0) {
        x[p1 * rows + r] = madd(v1, v2);
        x[p3 * rows + r] = mmul(msub(v1, v2), t1);
      }
    } else {
      u32 c0 = mmul(v2, t0), c1 = mmul(v3, t1);
      x[p0 * rows + r] = madd(v0, c0);
      x[p3 * rows + r] = msub(v0, c0);
      if (p1 != p0) {
        x[p1 * rows + r] = madd(v1, c1);
        x[p2 * rows + r] = msub(v1, c1);
      }
    }
  }
}

extern "C" __global__ void scale_kernel(u32 *x, u32 s, u64 count) {
  GRID_STRIDE(i, count) x[i] = mmul(x[i], s);
}

// BLAKE3 (src/source.rs): compression, chunks of 16 blocks, the CV stack.
__constant__ u32 B3_IV[8] = {0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
                             0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19};
#define CHUNK_START 1u
#define CHUNK_END 2u
#define PARENT 4u
#define ROOT 8u
#define KEYED_HASH 16u
__device__ __forceinline__ u32 rotr(u32 x, int n) { return (x >> n) | (x << (32 - n)); }
#define G(a, b, c, d, x, y)                     \
  s[a] = s[a] + s[b] + (x); s[d] = rotr(s[d] ^ s[a], 16); \
  s[c] = s[c] + s[d]; s[b] = rotr(s[b] ^ s[c], 12);       \
  s[a] = s[a] + s[b] + (y); s[d] = rotr(s[d] ^ s[a], 8);  \
  s[c] = s[c] + s[d]; s[b] = rotr(s[b] ^ s[c], 7);

__device__ void compress(const u32 cv[8], const u32 block[16], u64 counter, u32 len, u32 flags, u32 out[16]) {
  u32 s[16] = {cv[0], cv[1], cv[2], cv[3], cv[4], cv[5], cv[6], cv[7],
               B3_IV[0], B3_IV[1], B3_IV[2], B3_IV[3], (u32)counter, (u32)(counter >> 32), len, flags};
  u32 m[16], t[16];
  for (int i = 0; i < 16; i++) m[i] = block[i];
  const int perm[16] = {2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8};
#pragma unroll
  for (int round = 0; round < 7; round++) {
    G(0, 4, 8, 12, m[0], m[1]); G(1, 5, 9, 13, m[2], m[3]);
    G(2, 6, 10, 14, m[4], m[5]); G(3, 7, 11, 15, m[6], m[7]);
    G(0, 5, 10, 15, m[8], m[9]); G(1, 6, 11, 12, m[10], m[11]);
    G(2, 7, 8, 13, m[12], m[13]); G(3, 4, 9, 14, m[14], m[15]);
#pragma unroll
    for (int i = 0; i < 16; i++) t[i] = m[perm[i]];
#pragma unroll
    for (int i = 0; i < 16; i++) m[i] = t[i];
  }
  for (int i = 0; i < 8; i++) { out[i] = s[i] ^ s[i + 8]; out[i + 8] = s[i + 8] ^ cv[i]; }
}

// Little-endian word i of `bytes` (zero beyond `len`).
__device__ __forceinline__ u32 byte_word(const unsigned char *bytes, int len, int i) {
  u32 w = 0;
  for (int k = 0; k < 4; k++) if (4 * i + k < len) w |= (u32)bytes[4 * i + k] << (8 * k);
  return w;
}

// Leaf i: BLAKE3 of prefix(43) || index || present || salt(32) || column (rows words).
// `prefix` holds the 43 descriptor bytes; `key`, `sblock`, `slen` the salt stream.
extern "C" __global__ void leaf_kernel(const u32 *enc, u64 rows, u64 leaves, const unsigned char *prefix,
                                       const u32 *key, const u32 *sblock, u32 slen, u32 *digests) {
  GRID_STRIDE(i, leaves) {
    unsigned char head[52];
    for (int k = 0; k < 43; k++) head[k] = prefix[k];
    for (int k = 0; k < 8; k++) head[43 + k] = (unsigned char)(i >> (8 * k));
    head[51] = 1;
    u32 hw[13];
    for (int k = 0; k < 13; k++) hw[k] = byte_word(head, 52, k);
    u32 kv[8], sb[16], so[16];
    for (int k = 0; k < 8; k++) kv[k] = key[k];
    for (int k = 0; k < 16; k++) sb[k] = sblock[k];
    compress(kv, sb, i / 2, slen, CHUNK_START | CHUNK_END | ROOT | KEYED_HASH, so);
    const u32 *salt = so + 8 * (i % 2);
    const u32 *col = enc + i * rows;
    u64 len = 84 + 4 * rows;
    u64 chunks = (len + 1023) / 1024;
    u32 stack[24][8];
    int depth = 0;
    u32 cv[8], block[16], out[16];
    for (u64 c = 0; c < chunks; c++) {
      u64 start = c * 1024, bytes = len - start < 1024 ? len - start : 1024;
      u64 blocks = (bytes + 63) / 64;
      for (int k = 0; k < 8; k++) cv[k] = B3_IV[k];
      for (u64 b = 0; b < blocks; b++) {
        u64 off = start + b * 64;
        u32 blen = (u32)(len - off < 64 ? len - off : 64);
        for (int k = 0; k < 16; k++) {
          u64 w = off / 4 + k;
          u32 v = 0;
          if (4 * (u64)k < blen) v = w < 13 ? hw[w] : (w < 21 ? salt[w - 13] : col[w - 21]);
          block[k] = v;
        }
        u32 flags = b == 0 ? CHUNK_START : 0;
        if (b + 1 == blocks) {
          flags |= CHUNK_END;
          if (c + 1 == chunks) {
            // Pending output: merge with the stack, root on the last compression.
            u32 ocv[8], ob[16]; u64 octr = c; u32 olen = blen, oflags = flags;
            for (int k = 0; k < 8; k++) ocv[k] = cv[k];
            for (int k = 0; k < 16; k++) ob[k] = block[k];
            while (depth > 0) {
              compress(ocv, ob, octr, olen, oflags, out);
              depth--;
              for (int k = 0; k < 8; k++) { ob[k] = stack[depth][k]; ob[8 + k] = out[k]; ocv[k] = B3_IV[k]; }
              octr = 0; olen = 64; oflags = PARENT;
            }
            compress(ocv, ob, octr, olen, oflags | ROOT, out);
            for (int k = 0; k < 8; k++) digests[i * 8 + k] = out[k];
            break;
          }
        }
        compress(cv, block, c, blen, flags, out);
        for (int k = 0; k < 8; k++) cv[k] = out[k];
      }
      if (c + 1 == chunks) break;
      u64 total = c + 1;
      while ((total & 1) == 0) {
        depth--;
        for (int k = 0; k < 8; k++) { block[k] = stack[depth][k]; block[8 + k] = cv[k]; }
        compress(B3_IV, block, 0, 64, PARENT, out);
        for (int k = 0; k < 8; k++) cv[k] = out[k];
        total >>= 1;
      }
      for (int k = 0; k < 8; k++) stack[depth][k] = cv[k];
      depth++;
    }
  }
}

// Node `index` of tree level `level`: BLAKE3 of prefix(43, tag 1) || level || index ||
// left || right (119 bytes, one chunk, two blocks).
extern "C" __global__ void node_kernel(const u32 *children, u32 *parents, u64 count, u32 level,
                                       const unsigned char *prefix) {
  GRID_STRIDE(i, count) {
    unsigned char b[128];
    for (int k = 0; k < 43; k++) b[k] = prefix[k];
    for (int k = 0; k < 4; k++) b[43 + k] = (unsigned char)(level >> (8 * k));
    for (int k = 0; k < 8; k++) b[47 + k] = (unsigned char)(i >> (8 * k));
    for (int k = 0; k < 16; k++) {
      u32 w = children[(2 * i) * 8 + k];  // left then right: 16 consecutive words
      for (int q = 0; q < 4; q++) b[55 + 4 * k + q] = (unsigned char)(w >> (8 * q));
    }
    for (int k = 119; k < 128; k++) b[k] = 0;
    u32 cv[8], block[16], out[16];
    for (int k = 0; k < 8; k++) cv[k] = B3_IV[k];
    for (int k = 0; k < 16; k++) block[k] = byte_word(b, 119, k);
    compress(cv, block, 0, 64, CHUNK_START, out);
    for (int k = 0; k < 8; k++) cv[k] = out[k];
    for (int k = 0; k < 16; k++) block[k] = byte_word(b, 119, 16 + k);
    compress(cv, block, 0, 55, CHUNK_END | ROOT, out);
    for (int k = 0; k < 8; k++) parents[i * 8 + k] = out[k];
  }
}

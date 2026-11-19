// RFC-0014 §5: host execution of actual expressions, not a CUDA scheduling proof.
#include <cstdio>
#include <vector>
#include <algorithm>
#define __device__
#define __global__
#define __forceinline__ inline
#define __constant__
#define __shared__ static
struct Dim { unsigned x=0,y=0; } threadIdx,blockIdx,blockDim,gridDim;
static int host_phase=1;
// First pass fills the shared tile. Repeated reads in the second pass are identical.
#define __syncthreads() do { if (!host_phase) return; } while (0)
static unsigned long long __brevll(unsigned long long x) {
  unsigned long long out=0;
  for(int i=0;i<64;i++){out=(out<<1)|(x&1);x>>=1;}
  return out;
}

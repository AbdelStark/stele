// RFC-0008 A7. Compute the original-member and multiplicity/table leaves at x.
// A projection maps MSB-first source coordinates to a small source-column index.
__device__ __forceinline__ u32 lookup_project(const u32 *shifts, u32 start, u32 count, u64 x) {
  u32 index = 0;
  for (u32 j = 0; j < count; ++j)
    index = (index << 1) | ((x >> shifts[start+j]) & 1);
  return index;
}

// Each view is (validated owner device address, first logical position, log2 data width).
template<bool ORIGINAL>
__device__ __forceinline__ u32 lookup_base(const u32 *fields, const u64 *views, u64 slot, u64 j) {
  if (!ORIGINAL) return fields[slot+j];
  const u64 *v = views+3*slot;
  const u64 x = v[1]+j;
  const u64 mask = (1ULL << v[2])-1;
  return ((const u32 *)v[0])[(x & ~mask)*2 + (x & mask)];
}

template<bool ORIGINAL>
__device__ __forceinline__ void compact_leaf(const u32 *fields, const u32 *members,
    const u32 *shifts, u32 *tree, u64 n, u32 width, u32 count, u32 valid, u32 mults, const u64 *views) {
  const u64 row_start = 4 * (1 + u64(width));
  const u64 mult_start = row_start + u64(valid) * width;
  const u64 stride = 5 + 4 * u64(width);
  const Q alpha = qload(fields, 0);
  GRID_STRIDE(x, n) {
    // The validated plan's member ranges are ordered and disjoint. Padding
    // outside them has selector zero, tuple zero and denominator alpha.
    u32 lo = 0, hi = count;
    while (lo < hi) {
      u32 mid = lo + (hi-lo)/2;
      if (members[mid*stride+1] <= x) lo = mid+1;
      else hi = mid;
    }
    u32 selected = 0;
    Q tuple = qzero();
    if (lo < count && members[lo*stride] <= x) {
      const u32 *m = members + lo*stride;
      selected = m[2] == 0xffffffffU ? 1 : fields[m[2] + lookup_project(shifts,m[3],m[4],x)];
      for (u32 c=0; c<width; ++c) {
        const u32 *r = m + 5 + 4*u64(c);
        u32 value = madd(lookup_base<ORIGINAL>(fields,views,r[0],lookup_project(shifts,r[1],r[2],x)), r[3]);
        tuple = qadd(tuple,qmulm(qload(fields,1+c),value));
      }
    }
    Q table = qembed(1);
    if (x < valid) {
      Q compressed = qzero();
      for (u32 c=0; c<width; ++c)
        compressed = qadd(compressed,qmulm(qload(fields,1+c),fields[row_start + x*width + c]));
      table = qsub(alpha,compressed);
    }
    const u64 leaf = 2*n-1+2*x;
    qstore(tree,2*leaf,qembed(selected));
    qstore(tree,2*leaf+1,qsub(alpha,qmulm(tuple,selected)));
    qstore(tree,2*leaf+2,qembed(x < mults ? mneg(lookup_base<ORIGINAL>(fields,views,ORIGINAL ? 0 : mult_start,x)) : 0));
    qstore(tree,2*leaf+3,table);
  }
}


extern "C" __global__ void lookup_compact_leaf(const u32 *fields, const u32 *members,
    const u32 *shifts, u32 *tree, u64 n, u32 width, u32 count, u32 valid, u32 mults) {
  compact_leaf<false>(fields,members,shifts,tree,n,width,count,valid,mults,0);
}
extern "C" __global__ void lookup_original_leaf(const u32 *fields, const u32 *members,
    const u32 *shifts, u32 *tree, u64 n, u32 width, u32 count, u32 valid, u32 mults,
    const u64 *views) {
  compact_leaf<true>(fields,members,shifts,tree,n,width,count,valid,mults,views);
}

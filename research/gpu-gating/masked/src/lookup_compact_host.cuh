// RFC-0014 §5. Run the identical leaf expression as serial C++, comparing every pair.
int main() {
  u32 h[8];
  while (std::fread(h,sizeof(u32),8,stdin)==8) {
    const u64 n=h[0];
    std::vector<u32> fields(h[5]), members(h[6]), shifts(h[7]), tree((4*n-1)*8);
    auto read=[](auto &v){return std::fread(v.data(),sizeof(u32),v.size(),stdin)==v.size();};
    if (!read(fields) || !read(members) || !read(shifts)) return 1;
    lookup_compact_leaf(fields.data(),members.data(),shifts.data(),tree.data(),n,h[1],h[2],h[3],h[4]);
    if (std::fwrite(tree.data()+(2*n-1)*8,sizeof(u32),16*n,stdout)!=16*n) return 1;
  }
  return std::feof(stdin) ? 0 : 1;
}

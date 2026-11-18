// CPU-only execution of the actual kernels, including lazy inputs between levels.
bool read_words(std::vector<u32> &v) { return std::fread(v.data(), 4, v.size(), stdin) == v.size(); }
bool write_words(const std::vector<u32> &v) { return std::fwrite(v.data(), 4, v.size(), stdout) == v.size(); }
int main() {
  u32 header[5];
  while (true) {
    auto read = std::fread(header, 4, 5, stdin);
    if (!read) return std::ferror(stdin) ? 1 : 0;
    if (read != 5) return 2;
    const u64 n = header[0], width = header[1], mults = header[2], top = header[3];
    const bool lazy = header[4];
    std::vector<u32> in(4*(n*width+n+mults+width+1)), selector(n), tree(8*(4*n-1)), out(tree.size()), h(4*top), flags(top);
    if (!read_words(in) || !read_words(selector)) return 3;
    if (lazy) { for (auto &v : in) v += P; for (auto &v : selector) v += P; }
    lookup_leaf(in.data(), selector.data(), tree.data(), n, width, mults);
    std::copy(tree.begin()+8*(2*n-1), tree.end(), out.begin()+8*(2*n-1));
    for (u64 count = n; count; count /= 2) {
      if (lazy) for (u64 w = 8*(2*count-1); w < 8*(4*count-1); ++w) tree[w] += P;
      lookup_level(tree.data(), count);
      std::copy(tree.begin()+8*(count-1), tree.begin()+8*(2*count-1), out.begin()+8*(count-1));
    }
    tree = out;
    if (lazy) for (u64 w = 8*(top-1); w < 8*(2*top-1); ++w) tree[w] += P;
    lookup_top(tree.data(), h.data(), flags.data(), top);
    if (!write_words(out) || !write_words(h) || !write_words(flags)) return 4;
  }
}

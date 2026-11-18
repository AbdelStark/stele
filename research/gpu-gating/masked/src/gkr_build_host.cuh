// RFC-0014 §5: run the actual span writer over the borrowed construction inputs.
int main() {
  u32 table[3], span[7];
  while (true) {
    auto n = std::fread(table, sizeof(u32), 3, stdin);
    if (n == 0) return std::ferror(stdin) ? 1 : 0;
    if (n != 3) return 2;
    std::vector<u32> out(table[0] * (table[1] ? 1 : 4));
    for (u32 i = 0; i < table[2]; ++i) {
      if (std::fread(span, sizeof(u32), 7, stdin) != 7) return 3;
      std::vector<u32> shifts(span[5]), data(span[6]);
      if (std::fread(shifts.data(), sizeof(u32), shifts.size(), stdin) != shifts.size() ||
          std::fread(data.data(), sizeof(u32), data.size(), stdin) != data.size()) return 4;
      const u32 width = span[2] - span[1];
      gkr_build_span(out.data(), table[1], data.data(), shifts.data(), span[5],
                     span[3], span[4], span[0], span[1], width,
                     (u64)(table[0] / span[0]) * width, 0, 0);
    }
    if (std::fwrite(out.data(), sizeof(u32), out.size(), stdout) != out.size()) return 5;
  }
}

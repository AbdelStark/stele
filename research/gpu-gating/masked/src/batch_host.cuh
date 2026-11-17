// RFC-0014 §5: CPU execution of the actual construction kernels, canonical/lazy.
int main() {
  u32 header[4];
  while (true) {
    auto count = std::fread(header, 4, 4, stdin);
    if (!count) return std::ferror(stdin) ? 1 : 0;
    if (count != 4) return 2;
    u64 len = header[0], columns = header[1], pair_words = header[2];
    std::vector<u32> message(2*len), pairs(pair_words), weights(4*len), face(len);
    std::vector<u64> offsets(len/2+1);
    for (auto &v : offsets) {
      u32 words[2];
      if (std::fread(words, 4, 2, stdin) != 2) return 3;
      v = words[0] | ((u64)words[1] << 32);
    }
    if (std::fread(message.data(), 4, message.size(), stdin) != message.size() || std::fread(pairs.data(), 4, pairs.size(), stdin) != pairs.size()) return 4;
    if (header[3]) { for (auto &v : message) v += P; for (auto &v : pairs) v += P; }
    batch_weights(pairs.data(), offsets.data(), weights.data(), len);
    batch_face(message.data(), face.data(), columns, len);
    if (std::fwrite(weights.data(), 4, weights.size(), stdout) != weights.size() || std::fwrite(face.data(), 4, face.size(), stdout) != face.size()) return 5;
  }
}

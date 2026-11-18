// RFC-0014 §5: run the same construction kernels, in both field representations.
int main() {
  u32 h[8];
  while (true) {
    size_t n = std::fread(h, 4, 8, stdin);
    if (!n) return std::ferror(stdin) ? 1 : 0;
    if (n != 8) return 2;
    const u64 len = h[0];
    std::vector<u64> offsets(h[2]), runs(4ull*h[3]);
    std::vector<u32> message(2*len), packed(4ull*h[4]), gammas(4ull*h[5]);
    std::vector<u32> weights(4*len), face(len);
    for (auto *v : {&offsets, &runs}) for (auto &entry : *v) {
      u32 words[2];
      if (std::fread(words, 4, 2, stdin) != 2) return 3;
      entry = words[0] | ((u64)words[1] << 32);
    }
    for (auto *v : {&message, &packed, &gammas}) {
      if (std::fread(v->data(), 4, v->size(), stdin) != v->size()) return 4;
      if (h[7]) for (auto &x : *v) x += P;
    }
    batch_weights(packed.data(), gammas.data(), runs.data(), offsets.data(), weights.data(), h[6], len/2);
    batch_face(message.data(), face.data(), h[1], len);
    if (std::fwrite(weights.data(), 4, weights.size(), stdout) != weights.size() ||
        std::fwrite(face.data(), 4, face.size(), stdout) != face.size()) return 5;
  }
}

# E16-40ac independent source review

Codex-source-visits (lane Z) reviewed candidate `3e8ad0f9`. The only compact factor is a complete, unmasked, power-of-two QM31 block on the low axes. While the logical extent exceeds one period, both halves agree at each position, so their interpolant is the same value. At the period boundary, ordinary interpolation starts. The round kernel, canonical table readback and live-buffer model use the same physical extent.

The pinned chunk is initialized before DMA. Acquiring the next mutable chunk waits for its preceding transfer event. The review checked full initialization for the final power-of-two chunk and the canonical and lazy differential. The device allocation remains immutable across its certification, ordinary batch and selected opening. The source registry binds the certified root and identifier. The underlying words accessor checks the device and physical extents.

The source and ordinary-batch memory preflights include existing live owners, newly constructed tables, dense-round scratch and simultaneous old and promoted values. The reviewer accepted this source for hardware qualification. The real T32 verifier, device reference comparisons and driver high-water checks determine qualification.

Lucid job 6800 at combined source `323f6218` passed all four hardware suites and the complete CPU-authored T32 proof with both verifier outcomes. A total of five pinned sources supplied both PCS visits and all three ordinary source batches. Four originals remained live across all 385 checked GKR steps. The actual lookup projection, comparison, allocator and time receipts are in the [H100 qualification ledger](../../bench/ledger/e16-40ac-t32-original-residency-h100.json).

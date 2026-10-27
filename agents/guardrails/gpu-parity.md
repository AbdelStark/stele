# Guardrail — GPU parity
1. Every CUDA kernel has a CPU reference with the same function signature in `stele-kernels`.
2. `scripts/gates/parity.sh` runs each kernel on 10³ seeded random inputs (including edge values `0, 1, p−1, p`, lazy-range inputs) and compares bytes.
3. The prover-level gate proves 50 random W8-class instances on both backends and compares proof digests.
4. Lazy reduction: outputs leaving a kernel are canonical; a test feeds `[p, 2p)` inputs and checks canonical outputs.
5. Reduction order of parallel sums is fixed (tree by block id); atomics are forbidden for anything that reaches the transcript.
6. No `fast-math`, no tensor-core float paths for field arithmetic; int8 GEMM (CUTLASS) is allowed only for CQIS recompute with exact int32 accumulation, and its outputs are digest-checked against the CPU reference.

---
name: cuda-kernel-author
description: Write CUDA kernels behind the stele-kernels backend trait — sumcheck rounds and folds, lookup tree levels and layer sumchecks, small-value partial evaluations, circle-FFT row encoding, BLAKE3 Merkle, CQIS forward pass — with byte-identical parity to the scalar reference.
---
# CUDA kernel author
Read first: RFC-0014, `agents/guardrails/gpu-parity.md`, RFC-0003 §1 (lazy reduction), Workflow 09,
`docs/plan.md` §3.8.

Rules
- Integer only; fixed reduction order; no atomics on transcript-bound values; canonical outputs at kernel exit.
- One kernel is one operation of the backend trait, with a scalar reference of the same signature. The scalar
  path defines the bytes; the kernel matches them on 10³ seeded inputs including 0, 1, p−1 and lazy-range values.
- Order of work follows the profile, not the list: lookup tree levels and layer sumchecks, dense rounds and
  sumcheck folds, small-value partial evaluations (bucketed for int4 and int8 weights), row encoding and Merkle
  hashing, witness generation.
- Sumcheck is memory-bound. Prefer formulations that touch each byte once: bucketing, fused level build and round
  data, small values kept small until the first challenge.
- Weights larger than device memory stream from pinned host memory; count every read (INV-7).
- int8 GEMM on tensor cores is allowed only for the CQIS forward pass with exact int32 accumulation, and its
  outputs are digest-checked against the CPU executor.
- Measure elements/s and bytes/s per kernel and write them to the ledger. Parity runs before any benchmark.
- `unsafe` only in `stele-gpu`, each block with a `// SAFETY:` comment and a test.

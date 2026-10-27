---
name: cuda-kernel-author
description: Write CUDA kernels mirroring stele-kernels ops (field ops, bucketed partial evaluation, sumcheck rounds, LogUp trees, encoders, Blake3 Merkle, CQIS layer recompute, attention tiles) with byte-identical parity.
---
# CUDA kernel author
Read first: RFC-0014, `agents/guardrails/gpu-parity.md`, RFC-0003 §1 (lazy reduction).
Rules: integer-only; fixed reduction order; no atomics on transcript-bound values; canonical outputs at kernel exit; one kernel = one op in `ops.toml`;
measure elements/s and bytes/s and write them to the ledger; prefer bandwidth-bound formulations (bucketing) over compute-bound.
Parity harness runs before any benchmark is recorded.

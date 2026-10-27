# RFC-0014 — GPU prover architecture

Status: Accepted · Version: 0.1.0 · Depends: RFC-0006–0010

## 1. Principles
- The CPU/SIMD prover is the reference; CUDA produces byte-identical proofs (INV-3). Same algorithms, same variable
  orders, same reduction strategy ids; only the execution differs.
- No floating point. All kernels are integer (`u32`/`u64`) with M31 lazy reduction inside warps.
- The prover is a **streaming** pipeline over stages (RFC-0007 §4); device memory holds one layer's recompute window
  plus the stacked sumcheck state; weights stream from HBM/NVMe once.

## 2. Kernel inventory (generated from one op table shared with the CPU backend: `crates/stele-kernels/ops.toml`)
| Kernel | Work | Notes |
|---|---|---|
| `m31_ops`, `qm31_ops` | field arithmetic | lazy `[0,2p)`; QM31 Karatsuba; 64-bit delayed reduction |
| `partial_eval_bucketed_{w4,w8,i16}` | `f̃(r, ·)` for small-value tensors | one pass, bucket accumulate in shared memory, `eq` table in L2 |
| `sumcheck_round_deg{2,3,4}` | round polynomial + fold | warp-level reduction, base-field first rounds (BDT), eq-trick variant |
| `logup_leaf`, `logup_level` | fraction trees | fused: compute level `t+1` while emitting round data for level `t` |
| `zerocheck_eq` | `Σ eq(ρ,x)·C(x)` | Gruen split |
| `rs_encode_circle` | one-time weight encoding | circle FFT (registration only) |
| `raa_encode` | linear-time code for cuts | permutation + accumulate ×3, L2-resident |
| `blake3_merkle` | leaves + tree | 1 block per leaf, short columns |
| `recompute_layer_int8` | CQIS forward for one layer | reuses the serving int8 GEMM (CUTLASS) with exact int32 accumulation; `exp_q` etc. as table gathers |
| `attention_tile` | `S`, `P̂`, `Z`, partial evals per tile | flash-style tiling; tile consumed by `logup_leaf` and `partial_eval` in the same launch |
| `transcript_absorb` | host side | not a kernel |

## 3. Weight pass kernel
Input: packed int4/int8 `W_τ` fibre-major by `(ℓ,k)` (contiguous `j`), `eq_j ∈ K^{d_out}` (≤ 1 MB, L2). For each `(ℓ,k)`:
accumulate `eq_j` into `2^b` buckets (`b = 4` or `8`) in registers/shared memory, then `B[ℓ,k] = Σ_v v·bucket_v`.
Arithmetic ≈ 4 K-adds per weight; bytes ≈ 1 (int8) ⇒ bound by HBM (3.3 TB/s → 405 GB in ≈ 0.12 s) or NVMe (≈ 2–4 s at
100–200 GB/s per node; prefetch during earlier stages). Multi-GPU: `(ℓ,k)` ranges sharded (RFC-0015).

## 4. Memory plan and recompute
- Residual cuts: int16 `n·d·(L+1)`; 405B/4608 ⇒ 19 GB (host or HBM).
- Stage `s` needs, per layer, the virtual tensors of its reduction: recompute layer `ℓ` from `R_ℓ` (one int8 layer forward)
  immediately before the layer's contribution to the stacked sumcheck; discard after. Attention tiles are recomputed per
  reduction that needs them (3 sweeps: exp lookups, `P̂·V` partial eval, `Z`), or cached if memory allows (`plan.json` knob).
- Stacked sumcheck state: after the first `k` base-field rounds (small-value), the folded state is `K`-valued and `2^{−k}`
  of the original; the plan chooses `k` so that state ≤ 40% of device memory; otherwise two-pass streaming (RFC-0006 §5).
- The `n²·h` exp phase is tiled so that no `n²` object is ever resident.

## 5. Parity protocol (`scripts/gates/parity.sh`)
For each kernel: randomised inputs (seeded), CPU vs GPU outputs compared bit-exactly, 10³ cases. For the prover: 50 random
small-model proofs per PR, byte-identical digests. Any divergence blocks merge; no "approximately equal".

## 6. Instrumentation
Every kernel reports elements processed and elapsed cycles into the bench ledger; `c_w, c_a, c_x, c_c, R` are fitted from
these (RFC-0018). Roofline plots are produced by `stele-bench roofline`.

## 7. Negative controls
GPU-specific: NC-1000 lazy reduction leaking `p` as a value; NC-1001 bucket overflow for `b = 8` with `d_out > 2^23`
(must be rejected statically); NC-1002 tile boundary off-by-one in masks.

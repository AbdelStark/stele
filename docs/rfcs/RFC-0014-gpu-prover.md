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

## 8. Amendment log

### A1 — Account for the streaming fallback's source and transition

Status: Accepted. Question Q22; paired with RFC-0006 A6. Review:
[A6/A1 skill passes](../../agents/reviews/streaming-a6.md).
Motivation: the original 40% rule counts only a folded-tail estimate and promises
an unspecified two-pass fallback. The complete CPU contract separates source
visits, preallocated work/proof buffers and actual process/device resources.

Exact replacement for §4's stacked-sumcheck-state bullet:

> Select a strategy whose complete planned device allocation peak fits the
> plan's budget. The 40% limit includes every device-resident source buffer,
> grid, tail, proof/descriptor buffer, scratch allocation and retained capacity;
> host/external source storage and total pipeline memory are reported separately.
> If a validated small-value configuration does not fit, use an explicit
> schedule under RFC-0006 A6 and its detailed buffer contract, or reject the
> unsupported plan. Two source visits are a feasible one-window specialization,
> not a universal fallback. Charge layout preparation, source replay, transfer
> bytes and any virtual-tensor recomputation to the plan. A replay cannot add
> a weight pass under RFC-0007.

The CPU source and arena contract does not approve a GPU implementation or
establish a device budget from host measurements. GPU delivery must measure
actual device allocation and transfer lifetimes, including host/device overlap,
then pass the unchanged CPU/CUDA byte-parity gate. A caller's workspace budget
alone cannot establish the 40% condition. No new GPU code is introduced here.
Soundness: no implemented challenge or ledger change; original consumers and
CQIS certificates remain. Cost: c_sc/T_misc, source/working memory and T_witness
when recomputation is actually integrated. No measured constant or pass count
changes. Affected tasks: E3-05 and downstream GPU planning/streaming work.

### A2 — Development-profile resident field backend

Status: Accepted (development-tier amendment under RFC-0027 §2). Task E20-10.
[Independent lane Z review](../../agents/reviews/e20-10-dev-zk-backend-contract.md)

**Motivation.** ADR-138 qualifies implementation on the measured E45 CPU
path. Any claim about its speed on different CPU code requires an equally
qualified reference. A complete device-produced proof requires independent
byte parity. [Calibrated projection](https://github.com/AbdelStark/stele/blob/b711bd764c294cea3ea3c98d1ef63f106fad3ca3/bench/ledger/e16-40ag-t32-resident-projection.json)

**Addition to §§1–2.** A caller may select an explicitly required CUDA
backend when proving a balanced development-ZK window (profile byte 4).
The default is the existing CPU path. Backend selection is local execution
configuration. A selected device operation must finish on that device or
return an error. The implementation declares which operations are selected.
The caller uses the ordinary lifetime-index reservation, persistence, proof
encoding and self-verification path. Masks, ordered Fiat–Shamir draws, aborts,
claimed-sum checks, routed claims, certificate verification and authenticated
openings keep their original authority and order.

The first interface in `stele-kernels` is the field-only backend for the
ordinary RFC-0013 A5 item-5 batches. Its CPU implementation defines the
reference for every operation. Its CUDA mirror implements the same operations.
The op table names source import, dense batch construction, round, fold and
final evaluation. For each proof attempt the caller starts a fresh backend session, which
may share its device context. Source import accepts the exact immutable
message associated by the caller with its authenticated source and binds
the owner to that session, identifier and physical dimensions. An identifier
can be imported only once per session. Every consumer checks the session,
identifier and dimensions. An owner from a different proof, retry or concurrent
session is rejected even if the identifier, dimensions and device are equal.
Certificate and root verification belong to the caller. For physical dimensions `2R × 2C`
the source contains exactly `4RC` base limbs. The data face uses the left
`C` columns of every physical row. The batch borrows the caller's ordered
claims and transcript-derived coefficients. A claim carries its ordered
`(position, weight)` pairs and claimed value. Multiple contributions to
one position are added in order, including repeated positions inside a claim.
Each data position must be below `RC`. The lower `RC` positions of the
weight table contain those sums and its upper `RC` positions are zero.
The caller checks the returned sum against the instance's claimed sum.
Construction yields an opaque two-factor state. Each round returns the
degree-two product's three evaluations in existing node order. Fold binds
one MSB-first coordinate at the supplied field point. Finals return the
weight and face evaluations in that order after the final fold. Every
operation checks its input extent and state transition. The reductions
adapter owns the instance check and calls the existing checked masked prover.
The backend has no transcript, proof, authentication or verifier interface.

**Addition to §§4–6.** Account for all allocations under A1, including live
owners, promotion, staging and retained device capacity. Charge host work,
copies, cold startup and externally retained storage separately. The hardware
gate runs 1,000 seeded byte comparisons per implemented operation, including
zero, one, `p−1`, `p` and lazy representatives. It fails if CUDA is unavailable
or a requested operation does no device work. For byte 4 it additionally
requires 50 complete random small-model inference proofs with distinct
weight artifacts and independently pinned CPU results. Use the identical
source, public inputs, seeds, index and lifetime geometry within each pair.
Compare canonical public and proof bytes, verify both normally and exercise
a changed expected model. Require positive device-call counts consistent
with every selected invocation in every candidate. Report the actual corpus
geometry. The separate stories42M T32 rung checks the full original workload
and memory budget. Other profiles, architecture coverage, kernel families and
complete-prover milestones retain their existing gates.

**Soundness, cost and controls.** No bound, parameter, round, error term,
ledger line, committed cell, lookup, public byte or honest proof byte changes.
The target cost terms are `c_sc` and `T_misc`. Preserve the ordinary NC-0915
weight-final rejection. Exercise a corrupted round, a wrong source owner,
a same-id/same-extent owner from another session, wrong source extent,
unavailable CUDA and malformed transition in the device
differential. NC-1000 covers canonical field output. This interface specifies
no new binding and confers no profile promotion. Affected tasks include
E20-03, E20-04, E20-10, E20-11 and E20-12.

# Cost model — closed form, constants, projections

Every optimisation in this repository must name the term it moves. Every benchmark must report the measured
constants so the model can be re‑fitted (RFC‑0018). Units: **Mops** = M31 multiply‑equivalents (an M31 add ≈ ¼,
a QM31 mult ≈ 10–12, a base×QM31 MAC ≈ 4).

## 1. Symbols

| Symbol | Meaning |
|---|---|
| `n` | positions in the proof (prompt + generated, all sequences in the batch) |
| `L, d, d_ff, h, h_kv, d_h, V` | layers, model dim, FFN dim, heads, KV heads, head dim, vocabulary |
| `P` | parameters touched (dense: all; MoE: experts touched by any position) |
| `N_act` | nonlinear‑path activation elements per layer per position ≈ `7d + 4·h_kv·d_h + 4·d_ff` (requant outputs, SiLU, gate product, two norms, RoPE) |
| `N_attn` | exp lookups ≈ `n²/2 · h · L` (causal, dense), windowed: `n·w·h·L` |
| `C_cut` | committed residual‑cut elements = `n·d·L` (int16) |
| `c_w` | Mops per weight in the weight pass (4; ≈1 with bucketing, then bandwidth‑bound) |
| `c_a` | Mops per nonlinear activation element (≈ 1.5–3 lookups × 60–150 + partial evaluations) — default **200** |
| `c_x` | Mops per attention score (1 exp lookup + partial evals) — default **110** |
| `c_c` | Mops per committed element (linear‑time encode + Blake3) — default **30** |
| `R` | effective Mops/s of the device (H100: peak ≈ 10¹³; **planning value 3·10¹²** = 30% utilisation) |
| `BW` | HBM bandwidth (H100 ≈ 3.3 TB/s) |

## 2. Per‑proof cost

```
T_weights   = max( P·c_w / R ,  P·bytes_per_weight / BW )      # one pass (RFC-0007), fused opening (RFC-0010)
T_act       = n·L·N_act·c_a / R
T_attn      = N_attn·c_x / R
T_cuts      = C_cut·c_c / R  + 2·C_cut·4 / R                      # commit + batched opening passes
T_misc      = (n·V·c_lu [argmax/sampling] + multiplicities + transcript) / R     # small
T_witness   ≈ one int8 forward pass (recomputed from cuts, RFC-0014 §4)
T_proof     = T_weights + T_act + T_attn + T_cuts + T_misc        (+ T_witness on the same device)
```
Everything except `T_weights` is linear in `n` (and `T_attn` quadratic). `T_weights` is paid **once per proof**
whatever `n`, `L` or the batch; with epoch batching (RFC‑0019 R‑EPOCH) once per epoch.

## 3. Projections (planning value R = 3·10¹² Mops/s, one H100; 4096‑token prompt + 512 generated, batch 1)

| Model | P | n·L·N_act | N_attn | T_weights | T_act | T_attn | T_cuts | **T_proof (1×H100)** | Open SOTA (SASH) | Serving (vLLM, same request) |
|---|---|---|---|---|---|---|---|---|---|---|
| Llama‑3.1‑8B | 8·10⁹ | 1.3·10¹⁰ | 1.1·10¹⁰ | 0.01 s | 0.9 s | 0.4 s | 0.01 s | **≈ 1.3 s** | 3,600–5,400 s measured | 3.4 s |
| Llama‑3.1‑70B | 70·10⁹ | 6.2·10¹⁰ | 3.4·10¹⁰ | 0.1 s | 4.1 s | 1.2 s | 0.04 s | **≈ 5.5 s** | 5–8 h projected | ≈ 20 GPU‑s ∂ |
| Llama‑3.1‑405B | 405·10⁹ | 1.9·10¹¹ | 1.7·10¹¹ | 0.5 s | 13 s | 6.3 s | 0.2 s | **≈ 20 s** | 16–24 h projected | ≈ 67 GPU‑s ∂ (8×H100, batch 1) |
| DeepSeek‑V3 (671B MoE, all experts touched) | 671·10⁹ | 3.5·10¹⁰ | 8.3·10¹⁰ | 0.9 s | 2.3 s | 3.0 s | 0.1 s | **≈ 6.5 s** | 8–12 h projected | ≈ 25 GPU‑s ∂ |

Reading: at the planning utilisation the proof costs **less than serving** for decode‑heavy requests at 405B
(the serving decode is memory‑bound on 8 GPUs; the proof reads the weights once). The 8B request is ~2,000–4,000×
cheaper than the measured open SOTA and ~15–20× cheaper than the best closed number (Attestable, 195 tok/s).
Engineering acceptance for the first GPU milestone is **10× off these numbers** (PRD G1); the gap closes with
the kernel work in RFC‑0014.

## 4. Memory (405B, n = 4608)

| Object | Size | Where |
|---|---|---|
| int8 weights (one pass, streamed) | 405 GB | sharded across GPUs or NVMe→HBM streaming at BW |
| residual cuts (int16) | 19 GB | HBM/host, committed once |
| one layer's activations (recompute window) | ≈ 15 GB (incl. n²·h scores for the exp phase, tiled) | HBM, per layer in flight |
| stacked sumcheck state after round 1 (QM31) | ≤ 2× the stacked tensor bytes; first rounds in base field (ST‑9) | sharded by layer |
| proof (native) | ≈ 50–150 MB | dominated by weight column openings; Ligerito mode → ≈ 1 MB |

## 5. Constants to measure first (bench targets, RFC‑0018)
`c_a`, `c_x`, `c_c`, `c_w`, `R` on H100/B200, and the QM31‑mult : M31‑mult ratio under the chosen representation.
Until measured, every number above is a projection and must be labelled so.

## 6. Native small-value observations

The [E3-04 CPU ledgers and tables](../bench/README.md#small-value-pipeline-e3-04)
measure c_sc/T_misc preparation, proving and public consumption for the Accepted
RFC-0006 A5 strategy. They include separate prover/consumer process peaks,
transition overlap, retained capacity and losing cases. Observed ns/point values
are microbenchmark evidence; they do not refit the planning constants above or
change the weight-pass count. The measured prover-memory saving does not lower
the complete public-consumer pipeline peak in this experiment.

## 7. One-time circle registration baseline

The [E4-02 CPU ledger and report](../bench/README.md#circle-encoding-e4-02)
measure actual full-size circle encoding at both required rates, including
preparation, exhaustive output validation and native process memory peaks.
This is one-time weight-registration work. It does not fit c_c for linear-time
cut encoding, add a per-proof weight pass or change the planning constants above.

## 8. Native streaming observations

The [E3-05 CPU ledgers and tables](../bench/README.md#streaming-pipeline-e3-05)
measure the Accepted RFC-0006 A6 strategy's c_sc/T_misc tradeoff, including fixture
creation, layout conversion, source I/O, proving and original claim consumption.
Explicit windows reduce prover buffer capacity and process peaks in the measured
large case, while every tested streaming schedule increases complete runtime.
The original public consumer still determines the complete pipeline memory peak.
These observations do not refit the planning constants or establish an inference
planner, virtual-tensor recomputation cost, GPU bound or additional weight pass.

## 9. Bounded native encoder evidence

The [E4-08 native ledger and report](../bench/README.md#bounded-native-encoder-e4-08)
record the full c_c/T_misc operation for RFC-0010 A4/A5 in all supported fields
through the required measured size. Per-call generation, observation overhead,
base/sparse work, initialization, copies and full query re-encoding are charged.
Actual owned/caller capacities, compiled native/hash frames and process RSS retain
separate scopes. These CPU observations do not refit planning constants, add a
weight pass, authenticate a commitment or establish a PCS/profile error bound.

## 10. Conditional fraction primitive observations

The [E3-07a CPU ledgers and tables](../bench/README.md#conditional-fraction-primitives-e3-07a)
measure RFC-0008 A3 tree and selected-product c_sc/T_misc work, including
preparation, all internal levels/copies, encoding, decoding, original public
consumption and cleanup. Native whole-operation RSS includes allocator retention;
named source/encoding capacities have a narrower scope. These observations do
not fit c_lu, change planning constants or add a weight pass. Full lookup, private
source authentication, PCS, ZK, FS and inference remain separate obligations.

## 11. Conditional field PCS observations

The [E4-03a ledger and table](../bench/README.md#conditional-field-pcs-resources-e4-03a)
measure complete native registration, repeated functional openings and actual
three-original A1 closure under RFC-0010 A9. The c_c/c_sc/T_misc observations
include full encoding, every consumer, producer point replay, validation and
cleanup. Process RSS covers the complete pipeline; preparation and caller
capacities retain their partial scopes. No fitted constant, additional weight
pass, private-source composition, Q12 or inference/profile admission follows.

## 12. Conditional stacked runtime scope

The E3-06 runtime implements RFC-0006 A4's dense preparation, block partials,
A1 reduction and complete public or certified consumption. This work belongs to
c_sc/T_misc. Certified preparation embeds immutable M31 messages directly into
Dense and retains the actual m fold challenges; consuming that point releases
Dense before A9 opening preparation. Each source still incurs its actual A9
preparation, registration and opening work, including certificate lifetime losses.

`Dense::capacity_entries` measures retained dense tables and captured-point
capacity. The measured producers return `Work` from that same Dense instance:
retained field capacity, actual partial/result capacities and their simultaneous
round scratch maximum. Ordinary producers execute the same path and discard this
description. Diagnostic `partials()` calls do not increment production work.
These observations exclude other retained proof/descriptor storage and are not a
complete owned-memory peak. The caller's prepared-entry policy covers GKR state; it is not a complete
adapter memory ceiling. Caller tables, source/descriptor frames, partials, PCS point
weights, row/encoder storage, retained proofs and process memory have separate costs.
The [complete stacked ledger](../bench/ledger/e3-06-stacked.json) records actual
public/certified production, consumption, source registration, observations and
cleanup, with separate scoped capacities and fresh-worker RSS. Its fixed relation
and shared-host measurements are described in [the benchmark report](../bench/README.md#complete-conditional-stacked-resources).
No fitted constant, weight-pass count or inference projection changes from these observations.

## 13. Conditional grouped lookup contract

RFC-0008 A5 fixes [complete lookup costs](../formal/native-lookup.md#6-complete-costs-and-resource-admission):
source/table validation, grouped histograms, K-limb conversion and actual mu
preparation/registration, two A3 trees and selected-product work per repetition,
every original opening, and one or two mu functional openings for the real
table prefix. Each piece pays its own A9 row preparation/encoding/query work;
there is no uncharged batched opening. Actual Table serialization hashes and
certificate-ID comparison belong to disjoint local H/T_misc.

Retained source, tree/A1, preparation, coefficient and proof buffers have distinct
lifetimes. The [complete lookup ledger](../bench/ledger/e3-07b-lookup.json)
and [benchmark report](../bench/README.md#complete-conditional-lookup-resources)
record actual registration, production, import, closed verification and cleanup.
These bounded conditional observations do not fit c_lu, change an inference
projection or establish a weight-pass result.

The native A3 and lookup `prove_measured` methods execute the same producer as
ordinary `prove`. Their descriptive Work values record actual capacities from
that invocation. A3 observes level, Dense, completed-proof and point payloads;
lookup observes its index, units, multiplicities, limbs, original lifts, selector,
returned coefficients and wire buffers, plus actual mu preparation. A child
observation is combined only with buffers retained throughout that child call.
Completed proofs are counted after A1 returns, when its Dense has dropped.

`peak_observed_bytes` is the largest included boundary observation, not an exact
allocation peak, a sum of independent category maxima, or process RSS. Vector
headers, descriptor/record metadata and unobserved internal scratch remain
outside its scope. The complete benchmark retains these costs in its inclusive
timing and fresh-worker RSS. Conservative producer admission limits remain
separate from observed capacity. The producer interval includes internal mu
preparation and registration; standalone import and closed verification have
their own intervals. Diagnostic framing and hashes remain separate executed
scopes. E3-07's full private/source/plan, c_lu and profile obligations remain.

## 14. Conditional matmul verifier scope

E7-01b2 implements the [original-source matmul verifier](../formal/native-matmul.md).
Its A4/A1/A7 work contributes to c_sc/T_misc; both A9 consumers retain their full
row decoding, encoding, scalar checks, path authentication and column equations
under c_c/T_misc. The verifier reads no original matrix. The outer descriptor,
restored points, decoded A1 proof and both opening buffers retain their separate
storage costs. Existing A4 admission scopes conservatively include its unused
closed-roster bytes and message prefixes, as specified by the contract.

This delivery changes no measured constant or weight-pass count. Complete native
production, registration/prove/verify timing, observed capacities and process RSS
remain E7-01b requirements; verifier/control tests supply no resource-ledger credit.

## 15. Native validation cost

The [E0-07 paired ledger](../bench/README.md#native-test-profile-e0-07) measures
compilation and test execution under Cargo test optimization levels 0 and 2,
with debug assertions and overflow checks enabled. This changes validation cost
only. No per-proof term, fitted constant, weight-pass count or inference
projection above changes; the isolated pair does not measure full-CI wall time.

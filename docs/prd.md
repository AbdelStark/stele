# Stele — Product Requirements Document (PRD)

Status: Accepted (v0.1.0) · Owner: project lead · Governs: all RFCs

## 1. Problem

International agreements that pace frontier AI (compute caps, model registries, evaluation mandates, usage
restrictions) need a way for one party to verify what another party's AI systems actually computed, without
access to the weights and without trusting the other party's hardware. Today's options trade trust for cost:

| Mechanism | Trusts | Overhead | Blocker for treaties |
|---|---|---|---|
| TEE / confidential computing | the hardware vendor, firmware, absence of physical attacks (TEE.fail) | <1.3× | one vendor's silicon is a single point of failure between rivals |
| Recomputation by a third party | a party holding the weights | 1 full run per challenge | no mutually trusted party exists between rival states |
| Activation spot checks (TOPLOC, DiFR) | a checker with the weights + a tolerance | ≈0 | tolerance is an attack surface; checker needs weights |
| ZK proofs of inference (open SOTA, 2026) | hash function + Fiat–Shamir + the *code* | 400–1,100× (SASH), ~100× (Attestable, closed) | cost, auditability, zero‑knowledge, floating point |

The proof route is the only one that moves trust entirely into mathematics and auditable code. Its blocker is
cost and legibility. Stele exists to remove that blocker.

## 2. Users and jobs‑to‑be‑done

1. **Provider (lab / inference operator)** — "Produce, on the GPUs I already run, a proof for a sampled request
   that the declared model produced it, without revealing my weights, at a marginal cost that does not change my
   economics."
2. **Verifier (treaty auditor, regulator, counterparty state)** — "Check a proof on commodity hardware, with a
   verifier small enough that my own cryptographers can audit it, under assumptions I can state in a treaty annex."
3. **Model registrant** — "Register a model once (a *passport*) so that every future proof binds to the same
   public commitment and to the SHA‑256 of the published checkpoint."
4. **Evaluator** — "Prove that an evaluation run (thousands of prompts) was executed on the registered model."
5. **Agent developers (this repo)** — "Build, extend and audit the system from specs without tribal knowledge."

## 3. Goals (measurable)

| ID | Goal | Metric | Target (treaty profile) |
|---|---|---|---|
| G1 | Proving cost | GPU‑seconds per 1k positions, Llama‑3.1‑405B class, 4k context | roofline ≈ 4 GPU‑s/1k pos; **M‑GPU milestone acceptance: ≤ 40 GPU‑s/1k pos** (≤10× off roofline), stretch ≤ 10 |
| G2 | Overhead vs serving | prover GPU‑s ÷ vLLM GPU‑s for the same request (prompt‑heavy and decode‑heavy) | ≤ 10× at first GPU milestone; ≤ 2× steady state; < 1× for decode‑heavy requests |
| G3 | Soundness | documented total error, treaty profile | ≤ 2⁻¹²⁸ using only proven bounds + ROM Fiat–Shamir |
| G4 | Verification | wall clock on 8 CPU cores, no GPU | ≤ 10 s native; ≤ 200 ms after recursion wrapper |
| G5 | Proof size | bytes per request | ≤ 200 MB native (405B); ≤ 500 KB with wrapper |
| G6 | Zero‑knowledge | leakage about weights/activations beyond public I/O | none (masked sumchecks + blinded commitments), overhead ≤ 5% |
| G7 | Fidelity | CQIS model vs fp32 original on an agreed benchmark suite | within standard error on ≥ 3 reasoning/instruction benchmarks; perplexity Δ ≤ 8% (8B class) |
| G8 | Coverage | architectures | dense Llama/Qwen/Gemma‑style, GQA, RoPE variants, QK‑norm, softcap, sliding window, MoE (top‑k routers), MLA |
| G9 | Scale | largest proven model | ≥ 400B dense and ≥ 600B MoE, 16k context, multi‑GPU |
| G10 | Auditability | verifier crate | `no_std`, < 15k LoC, every check cites an RFC section, Lean statements for every IOP |
| G11 | Reproducibility | determinism | byte‑identical proofs across CPU/SIMD/CUDA for randomised inputs |

## 4. Non‑goals (v1)

- A general‑purpose zkVM or circuit DSL. Stele proves tensor programs under CQIS; arbitrary code is out of scope.
- Bit‑exact reproduction of bf16/fp8 floating‑point serving arithmetic (RFC‑0019 tracks a feasibility study).
- Proving training. (Kaizen‑style training proofs reuse most reductions; deferred.)
- Binding proofs to live network traffic (certifier integration). Stele exposes the hooks (public input digests, RFC‑0011) and stops there.
- On‑chain verification as a first‑class target. The recursion wrapper (RFC‑0016) makes it possible; it is not a release gate.

## 5. Functional requirements

- FR1 Prove the statement of RFC‑0001 §3 for a model registered under RFC‑0011, for prompt+continuation with greedy or committed‑seed sampling (RFC‑0004 §9).
- FR2 Accept HF‑format checkpoints (safetensors) + config; emit a CQIS artefact (quantised weights + scale tables + bound certificates) and its passport.
- FR3 Prover runs on 1…N GPUs with layer‑parallel phases and a sharded weight pass (RFC‑0014/0015); CPU/SIMD reference for every kernel.
- FR4 Verifier is a separate `no_std` crate consuming a self‑describing proof (RFC‑0016); a Python reference verifier exists for differential testing.
- FR5 Profiles: `standard` (≈100‑bit, conjectural PCS bounds allowed), `treaty` (≥128‑bit, proven bounds only, ZK on, double‑challenge LogUp).
- FR6 Negative‑control corpus runnable in CI against any prover claiming compatibility (public good, RFC‑0002 §7).
- FR7 Cost model CLI: predict GPU‑seconds and proof bytes from a model config before proving (RFC‑0018).

## 6. Non‑functional requirements

- Rust, `forbid(unsafe)` outside kernel crates; CUDA kernels generated from the same op definitions as the CPU reference; no floating point in prover/verifier.
- Streaming prover memory ≤ activations of one layer + sumcheck state (RFC‑0014 §4); witness recomputed from residual cuts.
- Every RFC has: statement, protocol, prover algorithm with cost, verifier algorithm with cost, soundness proof sketch with error terms, negative controls, open questions.

## 7. Success criteria for v1.0

1. Llama‑3.1‑8B, 4096+512 request, one H100: ≤ 10 s proving, ≤ 10 s native verification, passes the full negative‑control corpus, treaty profile.
2. Llama‑3.1‑405B, same request, 8×H100: ≤ 3 min proving.
3. External audit of `stele-verifier` + RFC‑0002/0012 soundness accounting with no critical findings.
4. A second, independent implementation of the verifier (Python) agrees on 10⁴ randomised proofs and rejects every control.

## 8. Risks

| Risk | Mitigation |
|---|---|
| CQIS accuracy regression vs bf16 serving | int16 residual/nonlinear path, int8 only at matmul inputs, dynamic per‑token scales, early eval harness (E5), static‑scale fallback |
| Sumcheck extension‑field cost dominates | small‑value prover (first rounds in base field), eq‑trick, bucketed partial evaluations (RFC‑0006 §5) |
| Memory of stacked sumchecks at 405B | layer sharding, base‑field first rounds, two‑pass streaming (RFC‑0014 §4) |
| Fused‑opening soundness subtleties (structured randomness) | rely on Diamond–Posen logarithmic randomness + Khatam; optional one‑time proximity certificate; Lean statement (R‑FORMAL) |
| Novel techniques (DPA, epoch batching) wrong | isolated in RFC‑0019 research tracks, not on the v1 critical path |
| Agent‑introduced soundness bugs | INV‑2/INV‑4 gates, soundness‑auditor review, hostile‑review workflow, differential verifier |

## 9. Amendments

### A1 — Re-baseline after the first published system of this shape (RFC-0027, ADR-090)

Status: Accepted (owner-directed). Evidence: [`docs/assessment.md`](assessment.md).
Motivation: §1 lists the open state of the art at 400–1,100x overhead. FlashProve v0.16.0 (2026-11-02) proves a
400B mixture-of-experts model at 111 tok/s on one H100 with zero knowledge, 18.78 MB proofs and 17 to 21 s
verification, about 72 to 94x the cost of serving the same prefill (its own report; statement: greedy tokens of
an integer model, fixed 1,024-token window). The goals below are restated against that bar. Nothing is relaxed.

Added to §3:

| ID | Goal | Metric | Target |
|---|---|---|---|
| G12 | Head-to-head | tokens per second on the published frontier workload (400B mixture-of-experts, 1,024-token windows, batch 24, one H100) | at least the published rate, with G13 and G14 met; then 2x |
| G13 | Proof size, native | bytes per 1,024-token request | at most 4 MB (replaces G5's 200 MB as the working target; G5's wrapper target stands) |
| G14 | Verification, native | seconds on commodity CPU | at most 2 s (tightens G4's 10 s) |
| G15 | Latency | seconds for one request, not a batch | at most 10 s on an 8B model; at most 30 s on the 400B shape |
| G16 | Fidelity reporting | what a model passport states | task benchmarks with paired standard errors and top-1 agreement with the float model, not perplexity alone |

Restated, when RFC-0030 is Accepted: G3 reads "every round at most 2^-128 (`treaty`) or 2^-100 (`standard`) from
proven bounds, with hash queries multiplying the largest round error". FR5's `standard` becomes proven-only.

Added to §7 (success criteria): the gates M1 to M7 of RFC-0027 §4 are the path to criteria 1 to 4; M4 is
criterion 1 at 1,024 tokens, M6 extends it to the frontier workloads, M7 is criteria 3 and 4.

Added to §8 (risks):

| Risk | Mitigation |
|---|---|
| The frontier moves again before a gate is met | the ladder includes the competitor's own workload; re-baseline by amendment |
| A proof about unidentified weights is taken as a proof about a named model | the passport binds the commitment to the published checkpoint digest (task E21-05) |
| Replies served by a floating-point engine never match the integer model exactly | integer serving kernels (R-SERVE) or a gap policy with a stated meaning (Q41) |

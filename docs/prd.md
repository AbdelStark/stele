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

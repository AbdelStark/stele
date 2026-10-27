# Invention register — the Stele techniques (ST‑1 … ST‑11)

Each entry: the idea, what it buys, how novel it is (honest rating), what must be proven before it is
`Accepted`, and where it lives. Novelty scale: **N3** = we believe this is new as stated; **N2** = new
combination/application of known results; **N1** = known technique, specialised. Rating is a claim to be
checked by the `research-spike` workflow, not a fact.

| ID | Technique | Buys | Novelty | Lives in |
|---|---|---|---|---|
| ST‑1 | **Layer‑stacked GKR with residual cuts** — commit only the residual stream at layer boundaries; run every reduction once over the ℓ‑stacked tensor (layer index = data‑parallel index); four sequential weight phases per proof | one weight pass per proof regardless of L, n, batch; layer‑parallel proving; witness recomputed from cuts (memory = one layer) | N2–N3 | RFC‑0006, RFC‑0007 |
| ST‑2 | **Fused opening** — the matmul sumcheck's weight‑side partial evaluation `W̃(·, r_j*)` *is* the interleaved‑code opening row; proximity via logarithmic randomness (DP24/Khatam), no separate random‑combination pass | PCS opening of a 10¹¹‑element polynomial costs zero extra passes | N2–N3 | RFC‑0010 §5 |
| ST‑3 | **Model passport** — certified, reusable weight commitment: one‑time encode + Merkle + proximity certificate + proof that the committed plaintext hashes (SHA‑256/Blake3) to the published checkpoint digest + CQIS fidelity report | registration once, binding to public model identity, provable‑soundness profile at no prover cost | N2 | RFC‑0011 |
| ST‑4 | **CQIS** — canonical quantised inference semantics co‑designed for provability: M31‑faithful static bounds; int8 at matmul inputs, int16 elsewhere, exact int32 accumulation; decomposable tables; output‑side softmax normalisation; implicit range checks via table domains; attained‑max selection sumcheck; blockwise attention accumulation; full‑sequence causal statement for decode | deterministic, hardware‑independent statement; ~1.5–3 lookups per activation instead of ~8 cells | N2 | RFC‑0004 |
| ST‑5 | **Dual‑prime accumulation (DPA)** — run a sumcheck over M31 and over a second 31‑bit prime on the same committed integers (shared systematic Merkle leaves) ⇒ integer identities up to 2⁶² with 32‑bit kernels | wide accumulators (group‑wise scales, long‑context attention, int16×int16) without a 64‑bit field | N3 (CRT is old; its use for sumcheck integer identities with a shared commitment appears new) | RFC‑0019 R‑DPA |
| ST‑6 | **Double‑challenge LogUp** — two independent α challenges over one committed multiplicity vector square the Schwartz–Zippel loss (N/|F|)² | ≥ 2⁻¹⁷⁰ lookup soundness in QM31 for 2³⁷ lookups, +~30% lookup cost, no field widening | N1–N2 | RFC‑0008 §6, RFC‑0012 |
| ST‑7 | **Epoch‑shared weight challenges** — derive the weight‑side point from a public randomness beacon after a public commitment deadline so all proofs in an epoch (any prover) share one weight pass and one opening | per‑proof weight cost → 0 across independent proofs | N3 | RFC‑0019 R‑EPOCH |
| ST‑8 | **Recompute‑from‑cuts streaming prover** and **inference‑topology‑aligned distribution** — proving cluster shaped like the serving cluster (layer shards hold their weights; per‑round all‑reduce of a few QM31s) | no witness storage; near‑linear multi‑GPU scaling | N1–N2 | RFC‑0014, RFC‑0015 |
| ST‑9 | **Bucketed small‑value partial evaluation** — for int4/int8 weights, accumulate the eq‑table into 16/256 buckets per row and multiply once; base×ext MAC → ext add | the weight pass becomes memory‑bandwidth‑bound (≈ 1 byte per weight) | N1 (BDT small‑value family, specialised) | RFC‑0006 §5, RFC‑0014 §3 |
| ST‑10 | **Virtual attention** — scores and probabilities are never committed; QKᵀ and P̂V are proven with O(n·d_h) partial evaluations; only the exp lookup touches n²; max is proven by the table domain + one selection sumcheck | attention proof cost ≈ 1 lookup per score | N1–N2 | RFC‑0009 |
| ST‑11 | **Static bound certificates** — overflow‑freedom of every field identity is a compile‑time property of (model config, CQIS version), emitted by the quantiser and recomputed by the verifier | removes a whole class of soundness bugs; auditable | N2 | RFC‑0004 §6 |

## Proof obligations before `Accepted`

- **ST‑1**: full protocol description with claim‑graph; soundness = sum of component sumcheck losses (RFC‑0012). Obligation: show that stacking does not create cross‑layer claim aliasing (the ℓ‑index is a hypercube variable; eq(ℓ, r_ℓ) binds blocks). Lean statement L‑1.
- **ST‑2**: (i) the row‑combination vector `eq(·, r_j*)` is sampled after the commitment is fixed (it is — commitment precedes the transcript); (ii) apply the logarithmic‑randomness proximity theorem for the chosen code (RS over the circle group: DP24; RAA/expander codes: Khatam) with explicit parameters; (iii) the column spot‑check soundness with fresh column indices per opening. Lean statement L‑2. Fallback: separate random‑combination pass (2 passes).
- **ST‑3**: SHA‑256 in‑circuit cost for 10¹¹ bytes is a one‑time 10³–10⁴ GPU‑s job (recursion wrapper); Blake3 digest variant 10× cheaper. Obligation: define the canonical serialisation of the CQIS artefact so the digest is unambiguous.
- **ST‑4**: fidelity experiments (E5): perplexity + GPQA‑D/MMLU‑Pro/IFEval on Llama‑3.1‑8B and ≥1 MoE; static bound certificates for all shapes in the supported‑model list.
- **ST‑5**: write the extraction argument: both transcripts bind to the same integers through the shared systematic Merkle leaves; field‑specific parity columns; total error = max of the two + collision term. Spike before any implementation.
- **ST‑6**: formal statement: for committed multiplicities m and GKR‑bound lookup values x, two independent α give error ≤ (N/|F|)². Watch: the same `m` must be used in both instances (one commitment, opened twice).
- **ST‑7**: beacon trust model (unpredictability window, liveness), replay across epochs, interaction with ZK; protocol with a public ledger of commitment digests. Research only.
- **ST‑10**: attained‑max selection sumcheck soundness; exp table domain [−2^B, 0] implies s − m ≤ 0 for *all* j (implicit range); interplay with masking for ZK.

## What is explicitly *not* claimed as new
Sumcheck matmul (Thaler), GKR/LogUp‑GKR, small‑value provers, Ligero family, circle FFT, negative‑control
methodology (SASH), full‑sequence causal equivalence of decode. Stele's contribution is the *composition* into a
system whose per‑proof cost is `≈ bytes(weights) + c·|nonlinear values| + commit(residual cuts)` with
treaty‑grade soundness, and the handful of N3 items above.

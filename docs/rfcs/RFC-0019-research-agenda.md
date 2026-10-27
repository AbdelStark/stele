# RFC-0019 — Research agenda

Status: Research · Version: 0.1.0 · Never binds implementation; each track graduates by producing an Accepted RFC amendment.

Each track: question, why it matters (which cost-model term or security property), method, kill criterion, deliverable.

## R-DPA — Dual-prime accumulation (ST-5)
Q: Can two 31-bit sumcheck transcripts over a shared integer commitment replace a 64-bit field for 2⁶²-range identities?
Why: unlocks group-wise weight scales, int16×int16 products, 2²⁰+ contexts without blockwise attention; keeps 32-bit kernels.
Method: write the extraction argument (shared systematic leaves ⇒ one integer witness; parity per field); prototype on the
RMSNorm sum-of-squares; measure 2× vs Goldilocks kernels. Kill: if binding across fields needs > 1.2× hashing or the
soundness argument requires per-field re-commitment of the witness.

## R-EPOCH — Epoch-shared weight challenges via public randomness (ST-7)
Q: Soundness and liveness of deriving `r_j` (and `r_ℓ, r_k`) from a beacon revealed after a public commitment deadline,
so independent proofs share the weight pass and fused opening. Why: `T_weights → 0` per proof even across provers.
Method: formalise as an interactive protocol with a trusted-beacon assumption (drand-like, threshold-signed), bound the
adversary's advantage from grinding commitments before the deadline; ledger integration; ZK compatibility (masks are
per-proof). Kill: any dependency of the beacon on prover-influenceable data.

## R-OCTIC — Challenge field for the treaty profile
Q: OM31 challenges for all sumchecks vs double transcripts vs accepting 2⁻¹¹⁰ for sumcheck terms. Deliverable: bench
of the three on W1; amendment to RFC-0012 D10.

## R-LIGERITO — Succinct openings on the hot path
Q: Best `(column length, levels, code)` for weight and cut matrices in Ligerito mode over M31 with RAA codes; interaction
with the fused opening (the first level's row vector is `B`). Deliverable: parameters in `codes.toml`, proof-size curve.

## R-BF16 — Exact bf16 feasibility study
Q: Cost of proving the *exact* serving arithmetic (bf16 products with fp32 accumulation in a fixed order). Method: limb
decomposition of products (exact in int24), accumulation-order emulation via per-step rounding lookups ⇒ `Θ(MACs)` cost.
Expected: 10³–10⁴× the CQIS cost; the deliverable is the number and a recommendation (likely: treaties mandate CQIS).

## R-HIDE — Hidden architecture
Q: Prove with `plan.json` private (wrapper-only). Deliverable: cost of structure checks in-circuit.

## R-SUBSAMPLE — Sampled layers/segments with commit-before-draw
Q: Given residual cuts are committed up front, can a verifier sample a subset of stages to prove (SASH's sub-sampling,
Seal-then-Sample) with a precise cheating bound? Deliverable: protocol + bound; compatible with ST-1 because every stage is
independent given the cuts.

## R-TABLES — Structured tables with `O(log)` verifier evaluation
Q: Replace 2¹⁶-entry table MLE evaluation by algebraically structured tables (Lasso-style) for `exp_q`, `rsqrt_q` to shrink
wrapper cost. Deliverable: table definitions with error analysis vs CQIS fidelity.

## R-FORMAL — Machine-checked soundness
Lean 4 statements L-1 (stacked GKR composition), L-2 (fused opening), L-3 (LogUp-GKR with selectors and double challenge),
L-4 (attention chain incl. attained max), L-5 (ZK simulator), L-6 (ledger arithmetic). Deliverable: `formal/` proofs
or precise statements with assumptions; the SASH note's call for a public specification of what an inference proof must
bind is answered by `docs/security/binding-spec.md` (task E12-09).

## R-TRAIN — Proof of training/fine-tuning
Reuse of reductions (Kaizen-style) for gradient steps; cost model extension.

## R-SERVE — CQIS serving kernels
int8/int16 CQIS kernels competitive with vLLM throughput (so providers lose nothing by serving CQIS); bit-reproducibility
across GPU generations.

## Numbered open questions (mirror of RFC §7 lists)
Q1 residual-only cuts for MoE routers · Q2 octic vs double-α · Q3 optimal variable order per stacked reduction · Q4
attention tile cache vs recompute crossover · Q5 ZK masks interaction with small-value first rounds (masks are K-valued ⇒
the first rounds lose the base-field trick: measure) · Q6 Blake3 vs Poseidon2 for cut Merkle trees when the wrapper is
mandatory · Q7 proof-size floor for native verification · Q8 int24 wide path with DPA for fidelity-critical models.

Q9: which explicit OM31 modulus/basis and checked signed-recovery contract complete
RFC-0003 §§2,6? Candidate: RFC-0003 A1, supported by `research/r-octic/REPORT.md`.
This does not resolve Q2's profile comparison.

Q9 resolution: RFC-0003 A1 Accepted with the skill-review record; E1-02 implements it.

Q10: resolve the conflicting signed rounding definitions and remainder relation in
RFC-0004 §§3,5.1. Candidate: RFC-0004 A1; counterexamples and exact-arithmetic checks
are in `research/cqis-rounding/REPORT.md`.

Q10 resolution: RFC-0004 A1 Accepted with the skill-review record; E5-01 implements it.

Q11: which byte framing, XOF/rejection algorithm, state update and field-domain
selection make RFC-0012 §1 interoperable? RFC-0012 A1 is the candidate. Its DAG
refinement must retain E2-01's real protocol controls without inventing a toy
verifier to satisfy a primitive-only dependency.

Q12: which precise Fiat-Shamir theorem/query convention supports the instantiated
Stele IOP, and which admissible adversary query cap reconciles FS/H with each
profile target? The existing Q <= 2^100 illustration gives H = 2^-56 under the
stated Q^2/2^256 formula, exceeding the treaty target before other losses. Resolve
in E8-05/E12-09; do not infer certification from a transcript KAT or a placeholder.

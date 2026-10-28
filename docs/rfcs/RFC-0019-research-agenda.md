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

Q11 resolution: RFC-0012 A1 Accepted with same-author skill reviews. E2-00
implements the kernel; E2-01 retains every original acceptance criterion and
waits for E3-01's real consumers. Q12 remains open and blocks profile certification.

Q13: which fixed Poseidon2-M31 permutation parameters and reference vectors
complete E2-03 without implicitly choosing a wrapper sponge or transcript?
Candidate: RFC-0012 A2; independent integer checks and pinned upstream execution
are recorded in `research/poseidon2/REPORT.md`. E2-03 is blocked on acceptance.

Q14: which wrapper hash/transcript mode, encoding, capacity, digest length and
concrete security accounting support E14-01? A permutation KAT supplies none of
these. Eight M31 output limbs have fewer than 248 bits of range and cannot alone
justify a 256-bit digest or a 128-bit generic collision target. Resolve before
using Poseidon2 for wrapper challenges or commitments; retain native BLAKE3.

Q13 resolution: RFC-0012 A2 Accepted after the linked same-author skill reviews
and independent integer/upstream checks. E2-03 implements that primitive; Q14
remains open and blocks any unaccounted wrapper hash/transcript construction.

Q15: which explicit polynomial/instance representation, message encoding, final
evaluation obligation and chained-transcript controls complete RFC-0006 §§1–2?
Candidate: RFC-0006 A1, with independent both-field prototype checks in
`research/sumcheck/REPORT.md` and dependency clarification RFC-0020 A1.
E3-01 is blocked on acceptance; Q12 remains a separate profile-certification gate.

Q15 resolution: RFC-0006 A1 and RFC-0020 A1 Accepted with the linked same-author
skill reviews. E3-01 must deliver the actual core, both-verifier corpus, accounting
gate and benchmark evidence before it is done. Research checks credit no controls.

Q16: which exact leaf/internal/root-of-roots bytes, tree shape, padding and batch
path rules make E2-02 interoperable? Candidate: RFC-0012 A3, with checks in
`research/merkle/REPORT.md`. E2-02 is blocked on amendment acceptance; Q12 remains
an independent profile-certification obligation.

Q17: E4-07 requests the same digest for 1 and N shards. A typed root-of-roots
list changes when its logical partition changes; it cannot also equal an
arbitrary flat-tree root. Which canonical logical shard partition and device
assignment meet that criterion, or which explicit amendment is needed? Resolve
before E4-07 implementation. E2-02 authenticates a fixed descriptor/list only;
it does not claim partition-independent roots or distributed proof parity.

Q16 resolution: RFC-0012 A3 Accepted with linked same-author skill reviews and
candidate byte checks. E2-02 is ready for production implementation and actual
NC-0602; research checks earn no control credit. Q12 and Q17 remain open.

Q18: which coefficient schedule, zero-extension semantics, final obligations and
message encoding complete both RFC-0006 §2 instance batching and §4 virtual-tensor
claim batching? Candidate: RFC-0006 A2 and RFC-0012 A4. E3-02 is blocked on their
acceptance; research checks earn no production control or profile credit.

Q18 resolution: RFC-0006 A2 and RFC-0012 A4 Accepted with same-author skill reviews
and candidate byte/algebra checks. E3-02 is ready for both production modes,
real controls, accounting gates and benchmarks; Q12 remains open.

Q19: which eq-factored zerocheck schedule, skip domain and final claims complete
RFC-0006 §5 without treating a hybrid interpolation as an ordinary MLE?
Candidate: RFC-0006 A3 / RFC-0012 A5. E3-03 is blocked on acceptance; retain both
optimizations, reference parity and the measured improvement criterion.

Q19 resolution: RFC-0006 A3 / RFC-0012 A5 Accepted with same-author skill reviews,
an explicit interactive obligation and both-field research checks. E3-03 is ready
for production implementation and its full parity/control/improvement gates.
The hybrid final is closed through original slice claims; Q12 remains open.

Q20: which exact coefficient/selector semantics, descriptor bytes, elimination
permutation and block-state ownership complete RFC-0006 §§3,6? Candidate A4 is
Draft. The stacking study gives counterexamples to interchanging nonlinear
layer folds or Boolean-product extensions and checks canonical axis restoration.
E3-06 is blocked on the complete amendment and its required reviews; research
checks provide no production control, profile or performance credit.

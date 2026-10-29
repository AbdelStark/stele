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
RFC-0012 A7 proposes v2 all-seed setup accounting, independent of quantum seed
selection in the ideal oracle. Joint composition with quantum FS/H remains required.

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
Candidate public-MLE algebra and padding semantics are in formal/public-mle.md;
the research evaluator agrees with direct M31 tables and retains O(log n) causal
and window evaluation. Actual source authentication, complete wire/ownership
contracts and extension-field production evidence remain open.
The candidate in formal/stacked-ownership.md now fixes logical round ownership,
folded-input redistribution and canonical point restoration for both layer orders.
The independent original-table oracle is research evidence only; full A4 closure
and all production delivery requirements remain mandatory.
The candidate in formal/stacked-statement.md fixes descriptor bytes and A1 reuse;
RFC-0012 A6 and RFC-0020 A2 propose the corresponding absorb/dependency boundaries.
All remain Draft. Binding resolved source bytes is not their authentication;
actual source-resolution/consumer interfaces and production evidence remain open.

Q21: which typed eligibility, deferred-prefix state and actual out-of-range misuse
control complete the small-value strategy without changing the A1 protocol?
Candidate: RFC-0006 A5, with two independent grid builders, both-field A1 parity
and a one-value truncation reproduction in research/small-value. E3-04 is blocked
on amendment acceptance; no production NC or performance credit is claimed.

Q21 resolution: RFC-0006 A5 Accepted with linked same-author skill passes and a
deterministic parity argument. E3-04 is ready for production implementation and
its actual constructor/control/parity/cost/memory gates. The strategy does not
prove range, change A1 bytes, certify a profile or complete the task.

Q22: which source layout, replay cost, integer window schedule and capacity-inclusive
peak bound complete the streaming fallback? Candidate RFC-0006 A6 / RFC-0014 A1
are Draft. The streaming study checks A1 algebra and logical visits, exhibits
nonsequential access, and rules out a universal single-window budget for that
grid/tail construction. It is not a physical two-pass implementation or a memory
measurement. E3-05 is blocked on the complete contract and its required reviews;
all original acceptance criteria remain.

Q23: which concrete M31 linear-time code, canonical setup identity and independently
justified distance/proximity parameters complete RFC-0010 §3? Candidate A1 is
Draft. The code-provenance study checks fixed-map linearity and exact small-code
distances, and exhibits a low-weight word hidden by 1,000 random samples. Binary
RAA parameters and sampled minima do not certify the M31 code. E4-01 is blocked
on the complete construction/API/evidence contract; production ledgers, controls
and profile admission remain separate requirements. The candidate seeded manifest,
bounded sampler and all-seed ideal-oracle argument in formal/seeded-setup.md
strengthen the finite event bound to cover quantum selection without a query cap.
The old classical formula's counterexample remains; actual admission and Q12
composition are still required. RFC-0012 A7 remains Draft.
The identity follow-up in formal/code-identity.md specifies a closed factory,
checked registry export and derived encoder parameters. Research calls regenerate
the map from its identity; false proven flags cannot be promoted by editing TOML.
Native allocation, authenticated consumers, proximity and PCS admission remain open.

Q24: which ordered domains, FFT span, normalization, distance bound and maximum
size define the circle encoder? Candidate RFC-0010 A2 gives a concrete map and
self-contained derivation. The circle study checks 140 complete small encodings,
the extra full-space dimension and a counterexample to the ordinary RS MDS bound.
E4-02 is blocked on A2 acceptance; no production or 2^30 benchmark credit follows
from these checks. The benchmark preserves 2^30 total input symbols at both rates,
using supported rows with all per-row and aggregate lengths recorded explicitly.

Q24 resolution: RFC-0010 A2 Accepted with same-author encoder/rfc/soundness passes
and a self-contained deterministic derivation. E4-02 is ready for implementation.
The large benchmark explicitly covers 2^30 input symbols at each rate; all rows
must actually be encoded, with input/output lengths and counts recorded. A1, PCS parameters,
profile accounting and actual production parity/benchmark evidence remain open.

Q25: which complete nonlinear table definitions, canonical registry bytes and
total integer RMSNorm normalization complete RFC-0004 §§4,5.3? Draft A2 records
the required contract. The exact table study reproduces the exp domain/index
size conflict and valid sum-of-squares inputs without the stated normalized
representation. E5-02 is blocked on A2; research checks establish no generated
table, max-error bound, production lookup control or complete forward pass.

Q25 continuation: formal/cqis-exp.md gives exact alternating-series/dyadic
certificates and an independent positive-series reciprocal oracle for an
endpoint-safe exp candidate. Two rounded short tables have nonmonotonic steps;
a bounded indexed correction restores correctly rounded exp, at explicit full
table and lookup cost. All example entries and error enclosures are checked.
This selects no model scale, representation or canonical identity. Remaining
activation/normalization/registry/fidelity obligations keep A2 and E5-02 open.

Q25 activation continuation: formal/cqis-activations.md defines scaled sigmoid,
SiLU and softcap research candidates. Strict rational intervals preserve the
side of a half-unit boundary where replacing an exponential tail by zero fails.
Full signed-int16 tables and seeded scale/cap cases match an independent exact
oracle; overflow and altered certificates reject. GeLU variants, total RMSNorm,
canonical identities and production consumers remain open; A2 stays Draft.

Q25 GeLU continuation: formal/cqis-gelu.md certifies distinct exact and tanh
variants with rational constants, strict tails and signed half-away. A separate
pi identity, root bisection and positive integral series cross-check both full
example tables and varied-scale cases. Exact/tanh integer outputs differ at
108 example entries. Normalization, canonical identities, scale selection and
native/fidelity evidence remain required; no production admission is claimed.

Q25 normalization continuation: formal/cqis-rmsnorm.md defines a total positive
rational statistic and canonical even exponent/mantissa/remainder, including
zero input. All 49,152 rsqrt entries and 32 exponent transitions are checked;
independent roots and 10,000 rows validate exact candidate behavior, explicit
overflow rejection and approximation bounds. Static wide-arithmetic magnitudes
and base-256 multiplication identities are retained. Canonical identities,
complete native consumers and model evidence remain open under A2/A3.

Q26: which canonical quantiser, zero-scale rule, checkpoint/certificate bytes
and static per-reduction bound schemas complete E5-03? Draft RFC-0003 A2 and
RFC-0004 A3 record the strict field-bound correction and missing contract.
Exact research checks show the advertised dimension endpoints violate p/2 and
the stated upper-only scale inequality admits an undersized scale. E5-03 is
blocked on the complete amendments; no runtime bound, certificate verifier,
NC-0109 result or model quantisation is supplied by this study.

Q22 resolution: RFC-0006 A6 and RFC-0014 A1 Accepted with the linked same-author
skill reviews, deterministic equivalence argument and sequential-source evidence.
The contract fixes explicit schedules, bounded record preparation, preallocated
work/proof/byte buffers and separate full-process/device evidence obligations.
E3-05 is ready for production implementation and its real capacity/parity/control/
ledger gates. No estimator, source study or read count completes those gates.


Q27: which admissible functional distributions, finite proximity/query bounds and
source/commitment consumers complete RFC-0010 §§2,5,6? Draft A3 and
formal/tensor-opening.md give a conditional fresh random tensor lemma, exact query
arithmetic and fixed-point/late-row counterexamples. Arbitrary/batched functionals,
complete native bytes/sampling, extraction/multi-opening semantics and actual
controls remain required. E4-03 is blocked on A3; no profile or PCS implementation
is supplied by the toy checks or an interactive subtotal below a budget.

Q27 continuation: formal/certified-functional-opening.md supplies the candidate
arbitrary/batched mode after a fixed-oracle certificate, with D-e disagreement,
ordered batch RLC and an adaptive lifetime union bound. The exact finite study
exposes aggregated-column cancellation, late values, changed-oracle certificates
and reused-query attacks. Actual certificate/root/cache and packed consumers,
extraction, native bytes, ZK, FS/H composition and production controls remain open;
E4-03 stays blocked on A3 and no complete PCS/profile bound is claimed.

Q23 continuation: RFC-0010 A4 and formal/native-code.md accept only the deterministic
encoder API/map/resource contract. E4-08 now tracks native delivery and is a
prerequisite of E4-01; all original E4-01 criteria and its A1 block remain. Actual
registry/source/PCS consumers, setup/proximity composition, profile admission and
Q12 remain open. The existing research checks do not complete native parity,
malformed/fault controls, compile-fail API checks or full cost/memory ledgers.

Q28: which injective packing/layout and authenticated decomposition reconcile
RFC-0010 §8, RFC-0007 §3/§5 and RFC-0008 §5? Four unrestricted int8/two int16
values cannot fit in one M31 element; even legal packing changes the original
fused row functional. Draft RFC-0010 A6 / RFC-0007 A1 / RFC-0008 A1 and
formal/packed-commitments.md record exact collisions, the fused-row counterexample,
a fixed 30-bit codec candidate and full remaining consumer/range/ZK/cost obligations.
E4-03 remains blocked on A3/A6; no codec test supplies NC-0603, a private
decomposition proof or the actual one-weight-pass fused opening.

Q28 continuation: formal/fused-layout.md proves that even a nonlinear source
codec needs at least T message coordinates to recover all T original coordinates
by fixed affine functionals. It derives the signed direct u=B layout and the
separate short-column u_s-to-B fold, with symbolic costs and a both-field
one-visit prototype. This recommends an explicit weight-layout amendment; it
does not admit that layout, remove private packing requirements, supply a native
pass-count gate or resolve A3/A6, ZK or the full authenticated phase schedule.

Q29: which complete commitment/sumcheck view and mask lifecycle provide privacy
for base-field sources, extension-field claims and repeated passport openings?
RFC-0013 A1 / RFC-0010 A7 / RFC-0011 A1 record the appended-row column leak,
base-mask support gap, joint-view/reuse failures and cumulative-query requirement.
formal/commitment-privacy.md gives exact linear-view conditions and a limited
randomized-row example; neither is a complete simulator or native ZK protocol.
E4-05/E12-01 are blocked on the full amended contract, retaining their actual
controls, proven-only parameters, <=5% overhead and one-weight-pass requirements.

Q30: which complete private-verifier relation and quantitatively composable ZK
argument of knowledge provide a sound, private and affordable wrapper?
Draft RFC-0016 A1 and formal/private-verification.md separate language membership
from extraction of an accepted inner proof, bind the complete expected statement
and verifier, and preserve all native/privacy/cost obligations. The pinned Stwo
inspection identifies privacy code and a 96-bit configuration target, not Stele
profile admission. E14-01 is blocked on A1; Q12/Q14, actual verifier translation,
full extraction/simulation composition, W8 and NC-1203 remain required. Selecting
this path for treaty privacy would need an explicit mandatory architecture
amendment; neither the finite search study nor upstream names choose that change.

Q31: which count/unit and nonzero-denominator contract makes LogUp sound at
the inference shapes? Draft RFC-0008 A2 / RFC-0012 A8 and
formal/logup-characteristic.md give an exact p-copy counterexample, bounded-count
residue/compression lemmas and pole/padding requirements. Extension challenges
and repetitions do not change the characteristic. Static partitions or a complete
weighted-unit construction are candidate repairs with distinct costs and source/
challenge obligations. E3-07 is blocked on A2; actual GKR/PCS/privacy consumers,
NC-0400..0403, c_lu measurement and complete accounting remain required.

Q31 continuation: formal/weighted-logup.md derives a grouped equality-unit mode,
its tuple/identity bound and independent-repetition composition. A virtual tree
applies weights above the groups; single/paired preparation uses one logical
source visit and table-sized accumulators. Exact subset/full-field tests and
schedule attacks retain clear research scope. The actual K-valued commitment,
privacy, source/selector/GKR consumers, bytes, accounting and native cost/control
gates remain open; A2/A8 are Draft and E3-07 remains blocked.

Q31 fraction continuation: formal/fraction-reduction.md and the exact public
study implement the conditional tree and selected-product leaf reductions.
Every original leaf/source claim has a public consumer, including unused final
values. Native private/table-side consumers, full lookup framing/admission,
privacy, NC-0400..0403 and measured c_lu remain required under Draft A2/A8.

Q31 consumer continuation: formal/lookup-consumers.md composes the whole single/
paired schedule and consumes original source/multiplicity claims through actual
Merkle roots and full reveals. The exact table-padding and early-denominator
attacks reject at their consumers. This closes the revealing research computation,
not the private PCS/ZK/native implementation or any original task criterion.

Q31 native prerequisite: Accepted RFC-0008 A3 / RFC-0012 A9 / RFC-0020 A4 fix the
conditional fraction/selected-product contract for E3-07a. Native types, engines,
actual public consumers, controls, shared parity and complete primitive ledgers
are all required. This does not accept A2's whole lookup or reduce E3-07's scope.

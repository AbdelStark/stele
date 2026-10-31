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

Q25 larger-domain continuation: formal/cqis-wide-exp.md gives explicit split
parameters, sub-tables bounded by 2^16 rows, full endpoints and strict absolute
error for B<=31. Independent exact checks cover every sub-table entry in six
wide configurations and sampled products. Split-dependent outputs remain part
of identity; full correction storage is not hidden. Wide index consumers,
canonical bytes and attention-scale/native/model integration remain open.

Q25 identity continuation: formal/cqis-table-identity.md supplies candidate
component descriptor/parameter bytes, signed row order, derived padding and
complete-definition validation. Exact frames and full data encodings reject
identity, shape, entry, padding, order, alias and length tampering. Complete
composition/configuration identities and passport root derivation remain open;
these are not native lookup/identity controls or A2 acceptance.

Q25 function continuation: formal/cqis-function-identity.md separates semantic
function identities from chosen representations, binds RMSNorm parameters and
derives exact component closure. Canonical manifests regenerate every component
data digest from the definition. Independent frame/manifest checks and actual
direct/corrected output agreement support the candidate. Full operation/source
and passport code-root binding, normative review and native delivery remain.

Q25 contract continuation: Draft RFC-0021 and companions RFC-0004 A4,
RFC-0005 A1, RFC-0008 A4, RFC-0009 A1 and RFC-0011 A2 consolidate the exact
functions, certificate algorithms, identity bytes, plan references and table
matrix/code/root record. The full outer plan/passport and real consumers remain
their original tasks; this does not admit opaque configuration blobs or profiles.
Before acceptance, complete coordinated review and executable table-root framing
and mutation evidence; native generators follow acceptance, with all delivery
criteria. E5-02 remains blocked while this contract is Draft.

Q25 contract accepted: RFC-0021 and coordinated RFC-0004 A4, RFC-0005 A1,
RFC-0008 A4, RFC-0009 A1 and RFC-0011 A2 supersede the incomplete A2 proposal.
Exact table-matrix/code/root evidence distinguishes membership from definition
binding and rejects field-congruent integer aliases. ADR-034 and the coordinated
review record preserve all remaining obligations. E5-02 is now in progress for
native generation, canonical validation and the complete parity gates. E3-08,
Q26's certificates, full reference/fidelity, E6 plan bytes, E9/E10 inference and
E12-05 passport delivery remain uncompleted; no profile or native coverage credit.

Q26: which canonical quantiser, zero-scale rule, checkpoint/certificate bytes
and static per-reduction bound schemas complete E5-03? Draft RFC-0003 A2 and
RFC-0004 A3 record the strict field-bound correction and missing contract.
Exact research checks show the advertised dimension endpoints violate p/2 and
the stated upper-only scale inequality admits an undersized scale. E5-03 is
blocked on the complete amendments; no runtime bound, certificate verifier,
NC-0109 result or model quantisation is supplied by this study.

Q26 continuation: the [checkpoint scalar study](../../research/cqis-checkpoint/REPORT.md)
gives exact integer decoding candidates for binary16/bfloat16/binary32/binary64,
preserves subnormals and rejects nonfinite encodings. Exhaustive 16-bit and seeded
wider-format rational/inverse checks pass; a raw-byte dtype-confusion witness
requires explicit source-format binding. This is research preparation only.
Scale selection, zero-row/static policy, canonical checkpoint/quantiser bytes and
per-reduction certificate consumers remain open; E5-03 stays blocked.

Q26 scale continuation: [exact candidate policies](../../research/cqis-checkpoint/QUANTISER.md)
give explicit shared-exponent/per-channel weight scales, int4/int8 symmetric
ranges and zero-safe dynamic/static row conversion. Independent bisection and
rounding checks cover 20,000 weight tensors and 20,000 row decisions, with exact
minimality/error bounds and static overflow rejection. These are research choices,
not Accepted scale/quantiser bytes, native parity or static certificate consumers;
E5-03 and full inference remain uncompleted.

Q26 alignment continuation: the [scale/tied-storage study](../../research/cqis-checkpoint/ALIGNMENT.md)
checks combined mantissas beyond scalar Requant's parameter range, one-round
residual scale alignment and one shared quantised embedding/LM-head tensor.
Exact/NumPy integer parity and concrete double-rounding/transpose counterexamples
make the numerical choices explicit. Artifact/plan/source-role bytes, gain and
attention conversion, static certificate consumers and complete inference remain
open; RFC-0004 A3 is still Draft and E5-03 stays blocked.

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

Q26 record continuation: the [physical tensor study](../../research/cqis-checkpoint/RECORDS.md)
defines candidate shape/dtype/channel bytes, continuous int4 packing and exact
int16 gain conversion. Independent complete-byte and rational/NumPy checks cover
30,000 tensors. A legal payload mutation remains decodable but differs from source
regeneration, preserving the distinct origin-binding obligation. Ordered artifacts,
quantiser identity, source-container/tied-role bindings, static certificates and
actual consumers remain required; RFC-0004 A3 and E5-03 remain Draft/blocked.

Q26 artifact continuation: the [ordered artifact study](../../research/cqis-checkpoint/ARTIFACT.md)
specifies complete research framing for the selected tensor set, a versioned offline
preparation identity and a distinct content digest. Independent outer encoding
checks 10,000 mixed artifacts and exact order/count/metadata rejection. Actual source
container/shard/alias resolution, full CQIS operation plans, static certificate
schemas and production consumers remain open; no artifact/profile is admitted.

Q26 source continuation: the [safetensors study](../../research/cqis-checkpoint/SOURCE.md)
checks actual file hashes, complete buffer metadata and explicit selected/ignored
source tensors before quantisation. Ten thousand files match a pinned upstream
reader; source hashes preserve original header bytes rather than reserialization.
The research source-preparation descriptor still needs inclusion in the complete
Accepted quantiser/passport identity. Shards, source/plan authority, certificates
and real commitment consumers remain open; no source proof or profile is admitted.

Q26 indexed-source continuation: the [shard study](../../research/cqis-checkpoint/SHARDS.md)
checks exact file/name/location coverage, original hashes and payload totals with
an explicit typed bundle identity. Ten thousand bundles and four repartitions of
the complete pinned checkpoint preserve artifact bytes. RFC-0011 A3 remains Draft;
full outer identity, source/plan authority, static certificates, native streaming
and actual source/commitment consumers are still required.

Q26 limb continuation: [static column bounds](../../research/cqis-bounds/LIMBS.md)
account for incoming carries, both equality sides and zero boundary carries.
Ten thousand static configurations and ten thousand exact/NumPy input cases
support the nonnegative lemma; a whole-input range counterexample prevents
digit caps from standing in for source bounds. Signed and biased arithmetic,
complete norm identities, closed schemas and native consumers remain open.
No NC-0109, full certificate contract or end-to-end inference credit follows.

Q26 scalar continuation: the [closed Requant schema](../../research/cqis-bounds/REQUANT.md)
derives six static column certificates from A1 parameters and compares 20,420
native/exact/NumPy decisions. Source-residue aliases and coherent false local
columns expose why the whole source and inter-column bindings are required.
The full schema set, certificate identity/bytes and native proof consumers remain
open under A3; no existing completion or control criterion is weakened.

Q26 norm continuation: the [closed RMSNorm schema](../../research/cqis-bounds/NORM.md)
derives static bounds covering every normalization exponent and output branch.
All wide native intermediates and 11,004 output-row decisions match independent
exact/NumPy references. Coherent false local arithmetic still fails the shared
bindings. Actual proof consumers, certificate identity/bytes and other operator
schemas remain required; full inference and private proving are unfinished.

Q26 record continuation: the [canonical static records](../../research/cqis-bounds/ENCODING.md)
give exact bytes, fixed role order, independent scalar/column derivation and
bounded resources for the existing Requant and RMSNorm arithmetic schemas.
Twenty thousand static configurations and full-byte mutation/truncation checks
support [RFC-0022](RFC-0022-static-arithmetic-records.md). Native derivation,
the other operation schemas, authenticated parameter/source and certificate-set
identity, every actual consumer and NC-0109 remain required under E5-03.

Q20 private-source continuation: the [selection study](../../research/stacked-gkr/PRIVATE-SELECTION.md)
distinguishes authenticated public indices from private witness indices. A
conditional product-tree reduction checks a onehot MLE through original bit-plane
claims, with bounded-degree A1 instances and no category-domain materialization.
Both fields agree with explicit tables and reject changed originals, padding,
public coefficients and stale continuation. Its source oracle is a public test
fixture and its messages are unmasked; no private PCS, range/packing consumer,
ZK construction, production control or E3-06 completion is claimed. A4 stays Draft.

Q20 weighted-source continuation: the [composition study](../../research/stacked-gkr/WEIGHTED-PRIVATE-SELECTION.md)
checks full-layout Boolean selector weights, multiple source axes with padding
holes, arbitrary category placement and broadcast factors in both fields. Zero
weights retain all original claims; scoped frame bytes and a chained missing
absorb mutation are checked. The real stacked-final adapter, authenticated
source/view, bit/range/PCS and joint masking remain open; A4 and E3-06 stay blocked.

Q20 stage continuation: the [private coefficient adapter](../../research/stacked-gkr/PRIVATE-STAGE.md)
consumes the real reference stage A final at its canonical restored point, with
metadata-only framing and a shared transcript. Both-field original consumers,
wrong-coordinate/unused-final mutations and chained missing-frame checks pass.
Public oracle data and unmasked messages do not supply private authentication or
ZK; global ids, private consumers, proof bytes and sparse costs still block A4.

Q20 source continuation: the [typed bit-source study](../../research/stacked-gkr/SELECTION-SOURCE.md)
proves Booleanity, padding and index range through actual A3/A1 reductions, then
maps selection claims to that same original tensor. Both-field consumers reject
false source data and field-congruent integer substitution. Its bit representation
has material message expansion; private PCS, joint masking, compact alternatives
and complete format/plan admission remain open. No commitment format is accepted.

Q20 compact-source continuation: the [two-bit candidate](../../research/stacked-gkr/PAIRED-SOURCE.md)
halves the bit-source message for k>=2 while resolving every virtual bit claim
through actual degree-four A1 to its original symbol tensor. Tests reject direct
polynomial-at-MLE substitution and enforce membership, spare bits, padding and
range. Single-plane consumers preserve linear table work; added proofs, live
working memory, private PCS and joint masking remain explicit costs/obligations.

Q26 attention continuation: the [exact row study](../../research/cqis-checkpoint/ATTENTION.md)
exhibits ignored value scales, ceiling-versus-nearest division, lost block units
and length-selected mode breaking cached-prefix equality. Draft RFC-0004 A6 /
RFC-0009 A2 propose explicit units, fixed absolute blocks and signed division.
Exact/NumPy decisions and prefix comparisons supply numerical evidence only;
full score/RoPE/config semantics, native forward, proof consumers and fidelity
remain required. E5-03/04 and E7-06/07 retain their original criteria.

Q26 composition continuation: the [projected attention study](../../research/cqis-checkpoint/PROJECTED-ATTENTION.md)
composes integer rotation, whole-row Q/K/V scales, explicit score conversion,
GQA, wide head assembly and absolute-position cache eviction. Exact/NumPy checks
also expose why cache row count alone cannot bound occupied blocks. The Draft
A6/A2 continuation keeps table generation/identity, native forward, full proof
consumers and model fidelity open; no task or production control is completed.

Q26 rotary continuation: the [integer-certified coefficient study](../../research/cqis-checkpoint/ROPE.md)
defines base/linear/llama3 frequencies and exact Q14 rounding, with canonical
candidate descriptors and full finite-table checks against independent Arb
intervals. A narrow scaling transition exercises refinement; a counterexample
rejects rounding frequencies before position multiplication. Draft RFC-0004 A7
records the missing contract. Native registry/public MLEs, complete forward,
remaining variants, proof consumers and fidelity remain open; no task is completed.

Q26 block continuation: the [complete dense-block candidate](../../research/cqis-checkpoint/DECODER-BLOCK.md)
composes norms, all seven projections, generated rotations, attention, exact
SwiGLU and residuals with independent arithmetic and full/cache comparisons.
Its int32 gated product requires wider scale/numerator bounds than int16-row
conversion. Draft RFC-0004 A8 / RFC-0003 A3 record this gap. Configuration/source
binding, native model forward, static schemas, proof consumers and fidelity remain
open; numerical block execution is not an inference proof or E5-04 completion.

Q26 model continuation: the [complete causal candidate](../../research/cqis-checkpoint/CAUSAL-MODEL.md)
connects embedding, stacked blocks, final norm/head and greedy stopping, with
full/cache and independent integer comparisons. A pinned public tiny checkpoint
exercises actual prepared tensors through logits and continuation. Draft RFC-0004
A9 records missing boundary semantics. Native GPT-2/Llama forward, fidelity,
canonical config/source roles, static schemas and private proof consumers remain open.

Q26 configuration continuation: the [canonical causal descriptor](../../research/cqis-checkpoint/MODEL-CONFIG.md)
binds ordered physical roles, every runtime unit/policy and function/representation,
then reconstructs a model from separately expected configuration/artifact hashes.
The pinned checkpoint retains identical logits and tokens through this loader.
Draft RFC-0004 A10 records the boundary; complete certificate/registry sets, native
full-model parity, authenticated registration, fidelity and private proof consumers
remain required. A numerical instance identity does not establish a passport.

Q26 scaled-linear continuation: the [closed arithmetic study](../../research/cqis-bounds/SCALED-LINEAR.md)
derives static matrix-output and embedding records from formats, shapes and unit
policies, including gated scales and extreme exponents. Exact integer/NumPy
controls and pinned model role records exercise signed and byte-limb relations.
Draft A3/A8/A9 remain unaccepted; no RFC-0022 schema extension or NC-0109 credit.
Other reduction schemas, the complete certificate set, native parity and actual
source/range/lookup/PCS consumers remain required.

Q26 row continuation: the [row conversion study](../../research/cqis-bounds/ROW.md)
closes candidate static relations for source magnitudes, attained absolute maximum,
ceiling scale and rounding, including a constrained zero-scale path and limb
rejection of gated M31 aliases. Mixed model roles and pinned replay supply
correctness evidence only. Draft A3/A8, E5-03/04 and all original criteria remain
open; actual source/selection/range consumers and complete certificate sets
are still required before inference-proof admission.

Q26 rotary-bound continuation: the [application envelope study](../../research/cqis-bounds/ROTARY.md)
derives the fixed Q14 coefficient absolute-sum limit 23171 and closes int16
rotation/rounding relations in M31 without limbs. Exact/NumPy controls reject
source, pairing, position and passthrough substitutions, including invalid
component-bounded pairs on zero inputs. Model role records and pinned replay
are correctness evidence, not canonical coefficient/source authentication.
Draft A3/A7, full schemas, actual consumers, native parity, fidelity and all
original E5-03/04 criteria remain open; no production NC or performance credit.

Q26 residual-bound continuation: the [one-round alignment study](../../research/cqis-bounds/RESIDUAL.md)
closes static byte-column relations for distinct input/output fractions, exact
addition and signed rounding. A coherent M31 alias changes the correct output
from 1 to -1 under field-only checking; canonical digit relations reject it.
Mixed model roles and pinned replay preserve the earlier numerical fixture.
Draft A3/A8, attention/decoding schemas, complete certificate sets, authenticated
source/range consumers, native parity and fidelity remain open. No original
E5-03/04 criterion, production NC or measured performance claim is completed.

Q26 greedy-bound continuation: the [first-maximum study](../../research/cqis-bounds/GREEDY.md)
closes static int16 attainment/difference/tie relations and explicit greedy
prefix, EOS, length and preceding-position conditions. Exact/NumPy controls,
model prefix replay and pinned decisions supply numerical evidence; same-choice
alternative rows expose the separate model/source authentication obligation.
Draft A3/A9, attention/score schemas, complete certificate sets, actual consumers,
sampled decoding, native parity and fidelity remain open. All original E5-03/04
and E7-08 criteria remain; no production NC or measured performance credit.

Q26 attention-sum continuation: the [signed accumulation study](../../research/cqis-bounds/ATTENTION-SUM.md)
closes conditional raw exact/block sums with static nibble caps, actual-source
arity, restored-value scales and canonical sign. Coherent whole-sum M31 aliases
reject even when all auxiliary column witnesses are rebuilt. Absolute block
positions, independent exact/NumPy rows and pinned model replay supply evidence.
Draft A3/A6 and RFC-0009 A2 remain unaccepted; block rounding, normalization,
score/max schemas, complete certificate sets and actual consumers remain open.
All original E5-03/04 and E7-06/07 criteria, native parity, fidelity and private
inference-proof obligations remain; no production NC or performance credit.

Q26 attention-normalization continuation: the [variable division study](../../research/cqis-bounds/ATTENTION-NORMALIZATION.md)
closes conditional signed nearest normalization with static byte-column caps
and an explicit strict remainder-gap relation. Coherent source/divisor/quotient/
comparison aliases reject after rebuilding every local witness. Exact/NumPy
corpora and model/checkpoint replay provide evidence; Draft A3/A6 and RFC-0009 A2
remain unaccepted. Block rounding/summation, score/max schemas, complete
certificate sets, actual consumers, native parity, fidelity and private inference
remain open. Original E5-03/04 and E7-06/07 criteria and production NCs are unchanged.

Q26 attention-block continuation: the [rounding and aggregation study](../../research/cqis-bounds/ATTENTION-BLOCKS.md)
closes conditional raw-to-rounded block sums with static byte columns, absolute
block IDs and small centered rounded totals. Numerical composition consumes the
raw-sum checker's results and feeds normalization; canonical source and rounding
aliases reject. A distinct pinned block-mode variant preserves baseline evidence.
Draft A3/A6 and RFC-0009 A2 remain unaccepted. Score/max schemas, complete
certificate sets, actual consumers, native parity, fidelity and private inference
remain required; original task criteria and production NCs are unchanged.

Q26 attention-score continuation: the [scaled QK study](../../research/cqis-bounds/ATTENTION-SCORE.md)
adds static dot/scale/nearest-rounding records and byte-faithful signed outputs.
The 10000-configuration corpus includes 5499 valid rows and 4501 static-bound
rejections; coherent p-separated score/product/division aliases reject.
Whole-projection GQA slicing and pinned replay compose with attention sum/block/
normalization arithmetic while preserving all previous fixture fields. Draft
A3/A6 and RFC-0009 A2, original tasks and controls remain unchanged. Complete
schemas, masked maximum/deltas, actual consumers, native parity and fidelity
remain mandatory; this is not an inference proof or performance result.

Q26 attention-maximum continuation: the [masked maximum study](../../research/cqis-bounds/ATTENTION-MAX.md)
adds byte-faithful attainment, differences and first-allowed-tie records. The
10000-configuration corpus has 5874 valid rows and 4126 expected domain
rejections; rebuilt p-separated attainment/difference/prefix aliases reject.
Model and pinned checks compose checked scores/deltas with probability and
attention sum/block/normalization arithmetic, preserving prior fixture fields.
Draft A3/A6 and RFC-0009 A2, original tasks and controls remain unchanged.
Complete set/source contracts, actual consumers, native parity and fidelity
remain mandatory; no inference proof or performance result is asserted.

Q26 gated-product continuation: the [exact product study](../../research/cqis-bounds/GATED-PRODUCT.md)
adds the source multiplication absent from the existing gated row schema.
Three byte roles reject p-separated output and intermediate aliases. Checks
cover 10000 random factor rows, 10000 independent static dimensions, maximum
actual width and model composition through gated conversion/down projection.
Pinned baseline and block-variant fields are preserved. Draft A3/A8 and original
acceptance/control criteria remain unchanged; complete sets, actual consumers,
native parity and fidelity are mandatory, with no inference or performance claim.

Q26 model-norm continuation: the [RMSNorm association study](../../research/cqis-checkpoint/MODEL-NORM.md)
reuses Accepted RFC-0022 bytes for every layer norm and final norm, preserving
all roles when records coincide. Native byte checks cover 10000 parameter sets
and 150 model records; numerical composition and 354 valid native arithmetic
rows cover varied model units/policies, with explicit overflow rejection.
Pinned baseline and separate block-mode fields are preserved. Draft A3/A8/A9,
original acceptance criteria and controls remain unchanged. Complete scoped
bound/registry/source contracts, actual consumers, native full-model parity
and fidelity remain required; no inference proof or performance result.

Q26 bound-set continuation: the [scoped collection study](../../research/cqis-checkpoint/BOUND-SET.md)
frames all twelve existing arithmetic-template families under independently
expected configuration/artifact identities. Its count is 25L+B+5, with no
role deduplication. Checks cover 256 models, 14310 records, maximum 3333-entry
shape, malformed collections and numerically equal models with distinct source
or representation scopes. All prior pinned fixture fields are preserved.
Draft A3/A10 and original criteria remain unchanged. Full plan/source consumers,
function/component data binding, native inference and fidelity remain required;
this is neither a proof receipt nor a performance result.

Q26 model-function continuation: the [function association study](../../research/cqis-checkpoint/MODEL-FUNCTIONS.md)
derives every ordered operation FunctionId/RepresentationId and the unchanged
Accepted canonical manifest from the expected model configuration. Metadata
checks cover 10000 models and 89996 references; complete frames and native
manifest bytes cover direct/corrected/product/max-domain exponential choices.
Role deduplication, substituted representations and changed data digests reject.
Pinned fixture fields remain preserved. Actual range/lookup/source selectors,
complete plan/table roots, native inference and fidelity remain open. Draft
A3/A10 and all original criteria remain unchanged; no proof/performance claim.

Q26 execution continuation: the [explicit dependency study](../../research/cqis-checkpoint/MODEL-FLOW.md)
checks physical source routing and numerical execution with all existing bound
and function roles retained. Rebuilt graph substitutions reject under the expected
configuration; learned values require the separately expected artifact digest.
Attention and row containers remain composites, not admitted stacked tensor views.
Continue with their expansion and actual source/range/branch/index/claim consumers;
full native parity, fidelity and private PCS/ZK/FS remain mandatory. This changes
no original task criteria or production control coverage.

Q26/Q31 range continuation: the [capped scalar consumer](../../research/cqis-bounds/CAPPED-RANGE.md)
connects actual byte membership to source reconstruction, column addition,
Boolean carries and a zero terminal carry through consumed A3 claims. Coherent
field-alias, nonbit and out-of-table attacks reject at distinct real consumers.
Continue with model-derived static caps, signed/wide source representations,
private producing reductions/PCS, range dominance and joint masking. Full-vector
reveals are research evidence, not an inference proof or privacy result.

Q26/Q31 wide-range continuation: the [exact word study](../../research/cqis-bounds/WIDE-RANGE.md)
closes the gap between coordinate-wise limb caps and an arbitrary unsigned
whole-word maximum through actual range_8 and consumed A3 relations. Source
copy, per-column integer faithfulness and zero carry endpoints remain explicit.
Continue with the actual source-to-numerical-operand consumers, signed/nibble
representations, multiplication relations and joint private masking. Revealing
roots remain research evidence, with no production control or profile credit.

Q26/Q31 limb-source continuation: the [input consumer study](../../research/cqis-bounds/LIMB-SOURCE.md)
connects exact whole-input maxima to original byte/nibble operand vectors with
actual range and packing consumers. Canonical digits, padding and high planes
are explicit; a valid packed byte cannot replace the nibble bound. Continue
with multiplication/result/carry consumers, signed/model source relationships,
complete native lowering and private PCS/ZK. Revealing roots and research
controls do not admit an inference protocol or satisfy production NC criteria.

Q26/Q31 product continuation: the [consumed product study](../../research/cqis-bounds/LIMB-PRODUCT.md)
connects actual unsigned operands, result digits and carries through fresh-point
polynomial identity and three consumed A1 sumchecks. The core avoids a replicated
digit-pair grid. Wrong products/carries, coherent wrong-source arithmetic and
row-pair substitutions reject through actual consumers. Continue with signed and
model-derived relations, native lowering/codec and private PCS/ZK/FS; full reveals
and research controls remain insufficient for inference or production NC credit.

Q26/Q31 signed-source continuation: the [signed byte study](../../research/cqis-bounds/SIGNED-SOURCE.md)
consumes actual source/magnitude roots, exact high-bit/sign ranges and byte
carry identities, including INT_MIN, zero and inactive-branch claims. A real
range consumer rejects a false positive INT_MIN whose signed equations all hold.
Continue with signed-operation composition, physical/model-source ownership,
native lowering and private PCS/ZK/FS. Full reveals admit no production cut or
profile and do not complete the original tasks or their native controls.

Q26/Q31 Requant continuation: the [scalar consumer study](../../research/cqis-bounds/REQUANT-CONSUMER.md)
joins actual signed sources, unsigned products, bounded remainder and exact
source-byte routing into the A1 rounding statement. All public constants and
shared words have actual consumers; the zero quotient permits canonical output
zero without erasing its sign claim. Continue with model-owned source routes,
production stacking/native plan, private PCS/ZK/FS and independent review.
Revealing scalar proofs do not complete inference or grant native control credit.

Q26/Q31 maximum continuation: the [attained-magnitude consumer](../../research/cqis-bounds/ATTAINED-MAGNITUDE.md)
proves an integer upper bound and real-row attainment through actual signed,
maximum, gap and indicator ranges. Padding and nonbit-carry controls isolate
otherwise valid false statements. Continue with dynamic scale and code consumers,
committed-index/model ownership, native lowering and private PCS/ZK/FS. The
revealing existential wrapper does not replace private selection or satisfy
the original inference tasks and production negative controls.

Q26/Q31 dynamic-scale continuation: the [scale consumer](../../research/cqis-bounds/DYNAMIC-SCALE.md)
proves exact ceiling from an actual attained maximum and independently expected
scale. The bounded carry offset handles a genuine negative carry without field
alias assumptions; the actual slack range excludes false zero-row scale1.
Continue with row-code and zero-scale consumers, model-owned routes, native
stacking and private PCS/ZK/FS. Revealing row-scale evidence does not satisfy
the original inference tasks or grant production negative-control credit.

Q26/Q31 row-code continuation: the [dynamic row-code consumer](../../research/cqis-bounds/ROW-CODE.md)
connects actual row scales and signed sources to symmetric signed int8 codes,
including zero scale, ties-away and negative rounding to canonical zero. Actual
strict remainder and zero-code consumers reject false statements whose byte
division alone holds. Continue with static mode, model-owned routing, native
stacking/lowering, private PCS/ZK/FS and independent review. The revealing
capacity-limited adapter earns no production control or original task completion.

Q26/Q31 static-mode continuation: the [static row-code consumer](../../research/cqis-bounds/STATIC-ROW-CODE.md)
uses the expected configured scale root and five fully consumed children to
prove signed ties-away codes. Actual bounds reject symmetric-output, strict
remainder and field-alias attacks even when parent field equations hold. A
static domain lemma avoids a redundant gated range after faithful byte division.
Continue with physical/model-owned source routes, native stacking/lowering,
private PCS/ZK/FS and independent review. Revealing research roots and capacity
limits do not satisfy the original tasks or earn production control credit.

Q26/Q31 gated-product continuation: the [actual consumer](../../research/cqis-bounds/GATED-CONSUMER.md)
joins signed factor proofs, bounded byte convolution and output sign before
row conversion. Actual carry sources reject a signed M31 alias satisfying all
parent field relations. The same product root feeds static and dynamic code
consumers with expected units fu+E. Continue with SiLU membership, physical/model
source routes, native stacking/lowering, private PCS/ZK/FS and independent review.
Revealing capacity-limited proofs do not complete original inference tasks or
earn production control credit.

Q26/Q31 SiLU continuation: the [full-table consumer](../../research/cqis-bounds/SILU-CONSUMER.md)
derives all65536 canonical rows from expected function/representation metadata
and joins both lookup columns to actual signed16 sources. The totality bound
rejects E>F globally; E<=F still requires the complete certified generator.
The revealing prototype retains every original claim, selector and multiplicity
consumer. Continue with physical/model-owned routing, native stacking/lowering,
private PCS/ZK/FS and independent review. Capacity limits and canonical-u32
research roots change no original criteria or production control obligations.

Q26/Q31 RMSNorm continuation: the [statistic consumer](../../research/cqis-bounds/NORM-STATISTIC.md)
duplicates actual signed-source magnitude bytes into both roles of one batched
sum-of-products proof. Original consumers reject changes even at zero factors,
and the byte/product relation rejects a whole-word M31 alias. The independently
expected statistic root preserves enforced high padding. Continue with numerator,
normalization exponent/remainder, actual rsqrt membership, final products/branches,
model ownership and private proof composition. This2048-element revealing
adapter changes no original criteria or production control requirements.

Q26/Q31 numerator continuation: the [RMSNorm numerator consumer](../../research/cqis-bounds/NORM-NUMERATOR.md)
binds the full statistic byte root, its actual whole-value bound and all
configuration-derived factors before exact sum-of-products verification.
A larger generic product bound cannot admit Smax+1, and a valid output range
cannot hide an N+p alias. Actual statistic/numerator roots compose. Continue
with normalization exponent/remainder, rsqrt membership, final branches and
physical/model/private source ownership. Original inference criteria stay open.

Q26/Q31 exponent continuation: the [RMSNorm factor consumer](../../research/cqis-bounds/NORM-EXPONENT.md)
uses a fully ranged one-hot selector, two consumed A3 relations and an actual
sum1 A1 to bind the bounded exponent and both exact factor byte vectors.
Zero-cap padded indices and empty selection cannot authorize arbitrary factors;
all original and public final claims remain consumed. Continue with the same
roots in scaled numerator/divisor, strict mantissa/remainder and actual rsqrt
consumers. This relation alone does not prove normalization or private/model
ownership; original inference criteria and production controls are unchanged.

Q26/Q31 scaled continuation: the [RMSNorm scaled numerator consumer](../../research/cqis-bounds/NORM-SCALED.md)
preserves the actual full numerator root while consuming its exact whole bound
inside the closed scaled role. Verified exponent bytes supply its only right
factor, including zero-product cases. The output retains every high slot and
the full153-bit static envelope. Continue with the configured divisor relation,
mantissa and strict remainder, actual rsqrt membership and final output branches.
This reveals sources and proves one composed role, not unique normalization,
private/model ownership or complete inference; original criteria stay open.

Q26/Q31 divisor continuation: the [configured divisor consumer](../../research/cqis-bounds/NORM-DIVISOR.md)
reuses the scaled consumer's actual exponent selection, fully consuming all
16 divisor bytes against the expected-parameter public grid. The same source
proof now binds A and D, including configurations whose divisor has124 bits.
Continue with M in[16384,65535], actual MD=M*D, A=MD+R and strict0<=R<D
before claiming a normalized interval; complete rsqrt membership and output
branches remain required. Original criteria, native controls and physical/model/
private ownership obligations are unchanged.

Q26/Q31 mantissa-product continuation: the [actual bounded source consumer](../../research/cqis-bounds/NORM-MANTISSA-PRODUCT.md)
binds M in[16384,65535] from a complete offset range and consumes the same M
and full divisor source in the closed MD product. A valid bare product below
the mantissa minimum or with changed M at D=0 cannot bypass the parent join.
Continue with A=MD+R and strict0<=R<D using these same roots, then actual
rsqrt membership and output branches. This standalone role permits D=0;
configured positive D requires upstream composition. Original criteria and
native/private/model proof obligations stay open.

Q26/Q31 decomposition continuation: the [consumed normal_sum role](../../research/cqis-bounds/NORM-SUM.md)
binds actual MD,R,A roots with fixed unit factors and full high-slot retention.
A genuine different-MD sum with the same result cannot replace its pinned
upstream product. R=D intentionally remains valid for this isolated equality;
continue with strict0<=R<D before claiming the unique normalized interval,
then consume actual reciprocal membership and wide output branches. All
original task, native control and private/model requirements remain open.

Q26/Q31 strict-remainder continuation: the [actual byte/carry consumer](../../research/cqis-bounds/NORM-REMAINDER.md)
proves R+G+1=D from three full ranges, Boolean carries, fixed endpoints and
actual byte columns. Genuine ranged R=D, zero D and whole-field aliases fail
the strict relation. Paired A/D, bounded M/MD and the decomposition now compose
with the same R/D roots in revealing research. Continue with the complete
canonical rsqrt membership and wide signed output branches; retain all original
native/model/private, physical-layout, fidelity and control obligations.

Q26/Q31 reciprocal continuation: the [full canonical lookup consumer](../../research/cqis-bounds/NORM-RSQRT.md)
binds actual one-field M/J roots to all49152 valid tuples and excludes all
canonical padding rows from membership. The complete generator/encoding and
all source/multiplicity/public claims remain mandatory. Continue with same-root
J and same-exponent wide signed outputs, retaining every original native,
physical/model/private, fidelity and control requirement.

Q26/Q31 output-factor continuation: the [same-exponent public-grid consumer](../../research/cqis-bounds/NORM-OUTPUT-FACTORS.md)
binds every rounding/left-shift factor byte and branch flag using the actual
indicator already verified for paired A,D. It preserves the whole child and
all originals, including inactive factors and high zero slots. Continue with
actual signed X/H magnitudes and xy*J, then the two wide signed output branches
using these same roots. Original task, native/stacking/physical/model/private,
fidelity and control obligations remain open.

Q26/Q31 full statistic continuation: the [full-row consumer](../../research/cqis-bounds/NORM-STATISTIC-FULL.md)
uses three byte-column sums from the same verified signed16 row, closed carry
ranges and deterministic zero-input tail columns. It retains the existing
raw/statistic root layouts and every original claim over the full norm domain.
Continue with complete proof/control evidence and actual numerator composition;
configured output branches, native/physical/model/private ownership, fidelity
and original end-to-end acceptance remain open.

Q26/Q31 quotient-product continuation: the [full-row adapter](../../research/cqis-bounds/NORM-QUOTIENT-PRODUCT.md)
uses one batched byte-column relation for qd=q*B, split actual result ranges
and closed carry families. Only statically zero families become public zeros;
no source claim is removed for an observed zero quotient. Continue with actual
same-exponent factor/signed-output composition, bias and division equality,
strict remainder and the selected output branch. Original native/physical/model/
private inference, fidelity and negative-control requirements remain open.

Q26/Q31 exponential continuation: [complete canonical output consumers](../../research/cqis-bounds/ATTENTION-EXP.md)
join actual difference/index bytes to every valid component row and bounded
outputs for direct nearest, product and corrected nearest. Product uses floor;
corrected output consumes the full input-indexed correction. File padding
cannot authorize membership. Complete maximum-source composition and all
field/full-row/attack evidence remain required. Continue with probability
sums, value products and complete attention; native/private/model ownership,
fidelity and original task/control criteria remain open.

Q26/Q31 probability-sum continuation: [actual masked source aggregation](../../research/cqis-bounds/ATTENTION-PROBABILITY-SUM.md)
consumes complete source/scalar ranges and the A1 source claim, retaining the
full four-byte Z root. Zero block contributions remain valid; whole-row Z>0
comes from actual attained maximum and canonical exponential composition.
Continue with restored value products and output normalization on these exact
roots. Full-sequence key completeness, physical/model ownership, fidelity and
native/private inference remain open; no original criterion or control is waived.

Q26/Q31 restored-value continuation: can [actual code/scale consumers](../../research/cqis-bounds/ATTENTION-VALUES.md)
bind D=s*V for all entries while preserving prepared-row two's-complement
code roots, per-position scale association and dynamic zero-scale rules?
The proposed offset relation retains every original claim, including at
zero scale. Implement tests first, then verify the planned account with
actual receipts. Complete source ownership and subsequent weighted-sum/
normalization consumers remain required; no native or private claim follows.

Q26/Q31 weighted-offset continuation: can [one batched column identity](../../research/cqis-bounds/ATTENTION-OFFSET-SUM.md)
prove every O_c=sum_j P_j*U_jc using complete source/output/carry ranges and
actual original-point consumers? Test M31 aliases, compensating channel errors,
zero factors and maximum carry geometry before implementation. Keep separate
polynomial-identity and A1 errors. Signed sums, source ownership, normalization
and native/private inference remain required; no original criterion is waived.

Q26/Q31 offset-base continuation: can [complete scalar product consumption](../../research/cqis-bounds/ATTENTION-BASE.md)
bind H=S*Z to the actual probability-sum root and configured restored-value
bound, including Z=0? Require source-join, whole-product alias and full-root
controls before signed O-H composition. No original criterion or native/private
inference obligation is waived.

Q26/Q31 signed-attention continuation: can [canonical O-H consumers](../../research/cqis-bounds/ATTENTION-SIGN.md)
bind magnitude/sign to actual weighted-offset and scalar-base sources while
excluding negative zero and modular aliases? Require all original-point,
broadcast, range/carry and complete source-composition controls. Continue with
block rounding and normalization; original inference criteria remain open.

Q26/Q31 continuation: [consumed attention block rounding](../../research/cqis-bounds/ATTENTION-BLOCK-ROUNDING.md)
asks whether separately bound absolute-block magnitude sources can retain all
original-point obligations through one dense rounding proof, including c=62.
Test coherent remainder overflow, bias removal and high-product truncation.
Signed block aggregation and normalization remain required before inference.

Q26/Q31 continuation: [signed attention block totals](../../research/cqis-bounds/ATTENTION-BLOCK-SUM.md)
asks whether actual signs and rounded quotients retain all original consumers
through channel batching, including q=0 and sparse absolute block ids. Require
complete source joins and reject compensating channel errors before inference.

Q26/Q31 continuation: [canonical accumulated block sign](../../research/cqis-bounds/ATTENTION-BLOCK-TOTAL-SIGN.md)
uses the static small total bound to test complete sign/magnitude consumption
without a wide carry grid. G=0 and negative raw signs rounding to zero must
retain all upstream consumers while the final total sign remains canonical.

Q26/Q31 continuation: can complete per-block probability sums compose into
one faithful eight-byte total up to 2^34 using the existing limb product?
[Scope and kill criteria](../../research/cqis-bounds/ATTENTION-GLOBAL-PROBABILITY-SUM.md)
precede tests/code. One shared globally attained maximum and complete source
ownership remain required; independent block normalization is invalid.

Q26/Q31 continuation: can complete range and limb-product consumers prove
a positive, correctly scaled attention denominator across exact/block modes,
including D=2^64? [Scope and kill criteria](../../research/cqis-bounds/ATTENTION-DENOMINATOR.md)
precede tests/code. Actual upstream roots, global attainment, numerator
scaling, private lowering and original criteria remain required.

Q26/Q31 continuation: can complete byte-column consumers scale all actual
attention magnitudes without truncating sixteen-byte outputs or reducing the
channel domain? [Scope and kill criteria](../../research/cqis-bounds/ATTENTION-NUMERATOR.md)
precede tests/code. Fixed channel groups preserve existing range capacities;
actual magnitude sources and all signed-normalization consumers remain required.

Q26/Q31 continuation: can the complete sixteen-byte denominator source bind
2D through the existing limb product, including the 2^65 boundary and every
original consumer? [Scope and kill criteria](../../research/cqis-bounds/ATTENTION-DOUBLED-DENOMINATOR.md)
precede tests/code. Strict remainder and signed-normalization composition
remain required; a standalone zero product does not establish positivity.

Q26/Q31 continuation: can full-width W=2U+D bind actual scaled magnitudes
and a shared denominator without weakening range capacity or source joins?
[Scope and kill criteria](../../research/cqis-bounds/ATTENTION-BIASED-NUMERATOR.md)
precede tests/code. All three group families, ragged padding and five actual
original consumers remain required before signed-normalization composition.

Q26/Q31 continuation: can all bounded quotients consume the actual shared
denominator through full sixteen-byte products and two-byte carry groups?
[Scope and kill criteria](../../research/cqis-bounds/ATTENTION-QUOTIENT-PRODUCT.md)
precede tests/code. Seven actual originals, high carry bytes, both full group
families and the strict division relation remain required.

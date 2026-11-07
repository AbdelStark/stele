# RFC-0005 — Tensor IR, claim graph, witness capture

Status: Accepted · Version: 0.1.0 · Depends: RFC-0004

## 1. Tensor IR
A model is a DAG of `Op`s over `Tensor`s with static shapes (padded to powers of two per dimension; padding is zero and
is excluded from lookups by selectors). Kinds: `Committed` (cuts, multiplicities, aux), `Weight` (passport-committed),
`Virtual` (never committed), `Public` (tables, masks, RoPE tables). Ops (each has exactly one reduction in RFC-0006–0009):
`MatmulW{type}`, `MatmulA` (activation×activation), `Requant{bits}`, `Table{id}`, `Zerocheck{poly}`, `Add`, `Select`,
`RMSNorm`, `RoPE`, `Softmax` (composite), `Gather`, `Argmax`, `Sample`, `Route` (MoE), `Window`.
Lowering from HF config + safetensors is in `stele-ir::lower`; unsupported ops fail loudly with the RFC-0017 table id.

## 2. Stacking
Every per-layer op instance is merged into one *stacked* op over the hypercube `(ℓ, …)`; per-head ops over `(ℓ, s, …)`.
A stacked tensor's MLE has the layer bits as its most significant variables. Weights of one type are one stacked
`Weight` tensor `W_type(ℓ, k, j)` (RFC-0007 §2). Padding for ragged MoE (RFC-0017 §4).

## 3. Claim graph
Nodes = tensors; edges = reductions. A proof is a topological traversal from the start claims (`R̃_{ℓ+1}(ρ)`) to the
PCS openings. Each reduction declares: inputs (claims it consumes), outputs (claims it emits), transcript messages,
soundness lemma id, cost formula. The verifier executes the same graph (RFC-0016 §2). Multiple claims on one virtual
tensor are merged by the RLC batch reduction (RFC-0006 §4) *before* the tensor's producing reduction runs.

## 4. Witness capture
The harness runs the CQIS forward pass once and emits only: token ids, residual cuts `R_0..R_L` (int16), scales,
selection indices (`j*`, argmax, scale-attainment), multiplicities per table, norm limbs. The prover **recomputes**
every virtual tensor of layer `ℓ` from `R_ℓ` and the weights when the stage needs it (RFC-0014 §4). Capture and
recompute share one kernel implementation; a digest of every virtual tensor is checked in debug builds.

## 5. Determinism
Lowering, padding, stacking order, head order, chunking decisions and table ids are functions of `cqis_id` only.
`stele-ir` prints a canonical plan (`plan.json`); the verifier derives the identical plan.

## 6. Amendment log

### A1 — Function and representation references in the plan

Status: Accepted. Companion RFC-0021 and RFC-0004 A4. Review: [coordinated skill sign-off](../../agents/reviews/cqis-functions-contract-accepted.md).
Motivation: a component table identity cannot bind a complete exp composition or
RMSNorm's dimension/scales/epsilon, and a function set cannot bind operation order.

Addition to §§1,3,5: each nonlinear operation names its RFC-0021 FunctionId and
selected RepresentationId, with the complete checked descriptors available in
the authenticated function manifest. Its input/output tensor identities, shape,
scale/gain sources and call position remain explicit plan data. The verifier
derives/checks the exact component closure and all integer relations; a Table op
after lowering names an actual component TableId. No proof-supplied alternative
representation or standalone manifest may choose the plan. Unknown/unbound
operations, identities, source references or dimensions reject before proof use.

This fixes the semantic references, not the entire plan's canonical byte codec.
E6 still requires that complete contract and verifier derivation before plan
admission. Existing private/virtual source, range, selector and claim-consumer
obligations remain. NC-0412/0413 cover real configured-function/representation
substitution when those consumers exist; research/primitive tests earn no credit.
No challenge, loss line, cut, weight pass or measured constant is introduced;
lowering/validation costs remain T_misc and actual reductions retain c_a/c_lu.

### A2 — Explicit Requant advice cut and operation ownership

Status: Accepted. Companion RFC-0023 and RFC-0007 A3; questions Q26/Q28.
Motivation: sign, digit and remainder tables need actual fixed sources before
lookup/arithmetic challenges. A virtual-tensor label supplies no such fixation.

Addition to §§1,3: RFC-0023 alone names the Requant advice cut, its exact
byte-plane schema, ownership and consumers. It deliberately fixes information
determining the accumulator/result; it is not a claim that these values remain
uncommitted. Every plane reaches the whole-source range lookup, all prescribed
integer/padding constraints and the actual certificate-bound functional groups.
The output remains a derived claim consumed through actual A1, not an extra root.

The expected operation statement is not plan.json, full cqis_id or an arbitrary
plan constructor. Full configured lowering/source/range ownership and E6 criteria
remain. No generic auxiliary commitment, arbitrary Table output, callback or
matmul integer splice is authorized. RFC-0023's centered/wider bridge conditions
remain explicit prerequisites for that integration. Soundness: the exact four
RLC events plus existing child losses are in RFC-0023/RFC-0012 A13. Costs include
the actual new cut, complete byte lookups and arithmetic/source consumers;
no measured constant or weight-pass change. Affected tasks: E7-01c and its native
successor; E3-07/E5-03/E6/E7 retain all original acceptance criteria.

### A3 — Embedded accumulator bytes in the centered linear advice cut

Status: Accepted. Companion RFC-0024; questions Q26/Q28.
Addition to §§3,4 and A2: RFC-0024 extends the named Requant advice cut with
the four offset accumulator bytes and full-width centered cap. Its fixed schema
uses one advice source, with no separate accumulator/input/output commitment.
The actual A3 tail supplies the equality point consumed by signed matmul and
its original byte-range-verified X/W sources. External X ownership grants no
permission to commit a model's virtual activation. Capture is request-specific,
untrusted witness work; its weight reads and registration are charged separately.
No plan format or generic auxiliary cut is admitted. Soundness adds the explicit
SZ event in RFC-0024 §5; all real child/lifetime losses remain. Advice/range costs
change by the exact schema counts, with no measured constant. E7-01e/f own this
contract and delivery; all original E3/E5/E6/E7 and W8 criteria remain.

### A4 — Model-wide template and request-specific plan instance

Status: Draft. Question Q26; task E5-03b. Motivation: §5's cqis_id-only plan
cannot select actual causal/decode rows for requests with different lengths.
Companion: [RFC-0025 public input](full-model-public-input.md).

Proposed replacement for §5's plan dependency: the passport binds a complete
canonical model-wide plan template, including approved lowering, source roles,
layouts and profile configuration. Derive each complete plan instance from that
same template, Model, RequestBoundary, generated length, stop reason, I/O mode
and approved profile configuration. N=q+g selects real/padded causal rows;
generated rows retain absolute previous/selected-token positions. Context n still
governs static Bounds. A request cannot choose an operation, source or tighter
bound from observed values. Model-wide physical ordering remains unchanged.

The public input binds H of this complete instance, distinct from the passport's
template digest. Neither hash permits an arbitrary supplied plan. To avoid cycles,
the plan omits its own hash, passport_root, actual I/O roots and ledger_id; roots
are checked against its prescribed role/layout/context at their actual consumers.
The complete template/instance codecs, native derivation, claim/transcript/source
schedule and private commitment schemas remain required E6 work before admission.
This amendment supplies no operator, cut, challenge, profile or consumer bypass.
Existing accounting and NC-1201/statement/source controls remain required.
Derivation contributes T_misc; no measured constant or weight-pass change.
Affected tasks: E5-03b, E6, E8, E12-05 and E14, with all original criteria retained.

### A5 — Accept template and request-instance separation

Status: Accepted. Question Q26; task E5-03b.
Review: [coordinated skill sign-offs](../../agents/reviews/full-model-cqis-draft.md#coordinated-acceptance-sign-offs).

Motivation: a model-wide passport and actual request geometry have different lifetimes.
Exact replacement for §5's plan dependency: adopt A4's complete template/instance
distinction under [RFC-0025's public-input contract](full-model-public-input.md).
Derive actual/padded geometry and the instance from the complete earlier template,
Model, RequestBoundary, g, reason, I/O mode and approved profile configuration.
Retain static context bounds, absolute positions and original physical ordering.
Neither the instance nor ledger embeds its own digest or the later identities
excluded by that contract. Supplied roots do not select owned source contexts.
A4's Draft proposal is superseded by this entry.

E6 still owes complete codecs, owned claim/point/source and transcript schedules,
private commitment contracts and actual consumers before native admission.
No new reduction, cut, challenge, loss, profile or weight pass is defined.
Derivation is T_misc without a measured constant. All original controls plus
NC-1204 remain required. Affected tasks: E5-03b, E6, E8, E12-05 and E14.

### A6 — Wide int24 residual cuts (companion of RFC-0004 A14)

Status: Accepted. Task E5-05a. Review: [E5-05a sign-offs](../../agents/reviews/wide-residual-a14.md).
Exact addition to §4's harness cuts `R_0..R_L (int16)`: in a wide Model (RFC-0004 A14: every
rmsnorm_q at version 2), `R_1..R_L` are int24 (R_0 stays int16); captured cut tensors keep one int24 per element. Non-wide Models are unchanged.
RFC-0004 A14 records the motivation, the ledger impact (no challenge, loss or profile
change) and the cost impact (the cut commit/opening message count doubles; cut storage is
1.5x the int16 bytes). Affected tasks: E5-05c, E6-02/E6-03, E7-10.

### A7 — Group scales and digit rows (companion of RFC-0004 A15)

Status: Accepted. Task E5-05d. ADR-063. Review: [E5-05d sign-offs](../../agents/reviews/grouped-rows-a15.md).
Exact addition to §4's captured `scales`: a grouped row (RFC-0004 A15, Policy mode 2) captures
n/g group scales and n/g local attained-maximum indices j_k in [0,g-1] (global position
k*g+j_k). Its digit rows b_t (t < T) and the T accumulators per projection output are virtual.
They are recomputed from the codes, the group scales and the weights, and are never cuts or
RFC-0023 advice.
Addition to §3: a grouped affine adds the following claim-graph edges, each owned by a
reduction with an RFC-0004 A15 control:
- group scale ↔ its group's attained maximum (NC-0131);
- code ↔ the scale of floor(i/g) (NC-0132);
- fold F ↔ s*|q| (NC-0133);
- digits ↔ signed fold, joined over Z in byte columns with exact digit ranges (NC-0134);
- digit-row accumulators in the window U_t < 2^29 ↔ signed A' recombination over Z (NC-0135);
- group size ↔ Model Policy (NC-0136).

The digit-row matmul is the existing matmul edge with the digit index in the row index
(RFC-0007 A6). Its X-side claim splits into T digit-row claims, which enter the RLC batch of
§3 before schema 23's consumer. Ungrouped Models are unchanged. Ledger and cost impact are in
RFC-0004 A15. Affected tasks: E5-05d, E5-05f, E6-02, E7-01 family.

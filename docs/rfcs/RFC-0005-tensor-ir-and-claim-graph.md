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

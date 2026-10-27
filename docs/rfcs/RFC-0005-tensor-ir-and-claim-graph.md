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

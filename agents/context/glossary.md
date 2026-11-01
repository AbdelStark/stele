# Glossary (use these words exactly)

- **claim** — `(tensor, point, value)`: an assertion `f̃(point) = value`.
- **reduction** — a sub-protocol that consumes claims and emits claims (never "gadget", never "component").
- **stage** — one stacked reduction executed across all layers/heads in one transcript segment.
- **stacked tensor** — a per-layer (or per-head) tensor viewed as one tensor with the layer/head index as leading hypercube variables.
- **cut** — a committed tensor that breaks sequential dependency; the residual stream `R_ℓ` and the explicitly scoped Requant advice cut of RFC-0023 (RFC-0007 A3).
- **virtual tensor** — any tensor never committed; its claims are reduced to other tensors.
- **weight pass** — one streaming read of a stacked weight type to compute `B[ℓ,k] = W̃(ℓ,k,r_j)`.
- **fused opening** — PCS opening whose row vector `u` equals the weight pass output `B`.
- **functional opening** — PCS proof of `aᵀ M b` for verifier-computable `a, b`.
- **passport** — the registered artefact set of a model (RFC-0011).
- **CQIS** — the canonical integer semantics; `cqis_id` identifies version + config.
- **bound certificate** — static overflow-freedom statement per reduction instance.
- **range discipline** — every committed element's range is enforced exactly once by a dominating lookup.
- **attained** — a prover-chosen extremum (max, scale) proven to be realised by a committed index.
- **profile** — `standard` or `treaty` parameter set (RFC-0002 §8).
- **ledger** — the soundness error accounting (RFC-0012 §4) or the bench result file (RFC-0018).
- **control** — a negative test that must be rejected for a stated reason.
- **digest gate** — CI check that proofs on fixed inputs are byte-identical to recorded digests.
- **parity gate** — CI check that CUDA and CPU produce identical bytes.
- **plan** — `plan.json`, the canonical lowering of a model config to stages, derived identically by prover and verifier.
- **M31/CM31/QM31/OM31** — base field and its degree-2/4/8 extensions. **K** — the challenge field in force.
- source context: the verifier-owned field, code, dimensions, layout, policy, identity and root of RFC-0010 A9.
- registration certificate: the full proximity proof verified for one source context.
- verified certificate: an opaque handle created only by complete registration-certificate verification; it retains the original conditional loss record.
Forbidden synonyms: "circuit" (say reduction/claim graph), "trace" (nothing is traced), "gadget", "constraint system",
"prover-side randomness".

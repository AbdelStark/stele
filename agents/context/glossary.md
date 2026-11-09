# Glossary (use these words exactly)

- **claim** — `(tensor, point, value)`: an assertion `f̃(point) = value`.
- **reduction** — a sub-protocol that consumes claims and emits claims (never "gadget", never "component").
- **stage** — one stacked reduction executed across all layers/heads in one transcript segment.
- **stacked tensor** — a per-layer (or per-head) tensor viewed as one tensor with the layer/head index as leading hypercube variables.
- **cut** — a committed tensor that breaks sequential dependency; the residual stream `R_ℓ` and the explicitly scoped Requant advice cut of RFC-0023 and its RFC-0024 embedded-input mode (RFC-0007 A3/A4).
- **virtual tensor** — any tensor never committed; its claims are reduced to other tensors.
- **weight pass** — one streaming read of a stacked weight type to compute `B[ℓ,k] = W̃(ℓ,k,r_j)`.
- **fused opening** — PCS opening whose row vector `u` is the retained row the weight pass built `B` from: `u = B` under the signed embedding, `u = B + 2^(w−1)` under offset (RFC-0007 A1).
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
- source version: the field-source byte format of RFC-0010 A9/A3; version 1 is a Circle source, version 2 a v2 expander source.
- query policy: the verifier-derived rule fixing a source's certificate and opening query counts q_c, q_o (Policy 1, RFC-0010 A3); it is not a profile parameter set.
- message embedding: the injective map from one original source value to its one committed M31 message element, signed or offset (RFC-0010 A6).
Forbidden synonyms: "circuit" (say reduction/claim graph), "trace" (nothing is traced), "gadget", "constraint system",
"prover-side randomness".

- **byte-range handle** — opaque completed all-one range_8 A5 result for one exact original certificate, borrowing its genuine owners and retaining its conditional event/lifetime obligations (RFC-0024 §1.1).
- **point-equality record** — PointEqualityRecord for the fixed-polynomial SZ loss at the actual A3 tail; it introduces no new challenge or executed sumcheck (RFC-0024 §5).
- **grouped row** — an activation row converted under Policy mode 2, with one dynamic group scale per g consecutive features (RFC-0004 A15). This is distinct from a grouped lookup (RFC-0008 A5) and from GQA key/value groups (Shape.groups).
- **group scale** — s_k = ceil(max|X|/127) over group k of a grouped row; indexed by the high log2(n/g) row-index bits (RFC-0004 A15).
- **fold** — the magnitude F = s_k*|q_i| of a grouped-row code times its group scale, joined to its digits in byte columns (RFC-0004 A15 schema 23).
- **digit row** — row t of the signed radix-256 digits of the folded values; each is one field matmul input, extending the matmul row index (RFC-0004 A15, RFC-0007 A6).

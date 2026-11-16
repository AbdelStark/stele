# E8-02f3a: A16 registry specification soundness review

Reviewer: `registry_spec_review`, soundness-auditor and other-lane C reviewer.
Integration owner: `codex-root`, lane V. Fixed base:
`b5ab311f5d676c0213c00044dc0710901ceb9c60`. Reviewed specification and reference
artifacts at `ae956599c84c7c9bfbcbddb3d7aff2146dc9a083`.

**Verdict:** approve A16 through Workflow 02's full path on the soundness axis and
as lane C reviewer. This is specification approval, not approval of a registered
verifier implementation. The RFC-author and lane V approvals, acceptance bookkeeping
and current-base required gates remain the integration owner's responsibility.

## Trust boundary and specification findings

A16 fixes the remaining premise precisely: the caller authenticates a correct entry
independently of per-proof files. Its publisher is trusted for CQIS identity,
metadata and the static relation. Matching a digest does not establish the static
relation's correctness. The caller also compares the decoded request with its own
expected request when that is the intended statement.

The static digest covers the exact Model, Scales, Preparation and record bytes,
with ordered roots encoded separately. The model identity uses the A15 record code
count, not its public-file byte length. Certificates remain outside these digests
and are verified by the existing replay. The original relation digest remains in
the transcript; the normalized bytes are never validated or proved.

Production `Layout::declare`, embedding and argmax declarations were inspected to
audit the contract. Their only request inputs beyond T are the columns A16 names.
The gathered mantissa width varies with selected tokens; other embedding widths
depend on static metadata. Checking that width before normalizing it to unsigned 1
therefore makes the template stable without weakening original-relation bounds.
Both shift branches, saturation, padding and block indices agree with the text.

The final revision addresses the untrusted relation allocation boundary: the
trusted entry pins its byte length before decoding; counts are bounded by remaining
bytes; decoding cannot expand a domain from an untrusted log length. Plan derivation
and validation follow template authentication. A changed-length malformed column
therefore fails with RegistryTemplateMismatch before request-column checks; the
vector documentation distinguishes those helper cases from wrapper precedence.

No blocking missing requirement, unintended protocol behavior or scope expansion
remains. Publication, independent wrapper implementation and actual composed controls
are explicitly serial follow-up tasks, not claimed as completed in this change.

## Evidence and adversarial checks

I reran `research/plan-registry/vectors.py` against `/tmp/stele-a16-windows` using
the supplied Python environment; its output is byte-identical to `vectors.json`.
The corpus has seven small codec cases, 19 column mutation cases, three wrapper
precedence cases, a sparse two-block mapping, 12 production declaration variants
and two complete production-window pins. The generator verifies every production
request column against the specified integer computation and checks template
equality across selected widths and checked ranges.

Three isolated mutations were made only in copies under `/tmp`: retain the
original request width, omit the request-value equality check, and read each
embedding block from the first token block. All three failed the generator's
assertions; omitting value equality specifically failed with
`missed value mutation G/embedding/O0`.

I tried to break it by retaining token-dependent widths during normalization, and
the control `research/plan-registry/vectors.py` template-equality assertion rejected it.

These are specification-vector checks, not executed NC-1325..1334 credit. The
composed controls are feasible without a verifier bypass: a onehot-bit change can
select an otherwise zero embedding row, and a static coefficient can multiply an
identically zero factor. The producer must rebuild each proof against the changed
relation, show low-level A15 acceptance, then show the registered verifier's exact
pre-replay rejection. E8-02f3b must execute those controls.

## Workflow 03 checklist

- Public items: A16 §§1-5 specify the entry, request checks, normalized digest,
  errors and future publisher/API contract. No runtime public item is added here.
- Challenges: none added or reordered. Existing first absorbs still bind the
  public input, original relation digest and model roots before claim challenges.
- Claims and consumers: existing A15 public evaluations, reductions and source
  openings are unchanged. The new comparisons precede replay and use exact bytes
  or integer values, not another prover-supplied claim.
- Bindings and controls: NC-1325..1334 name key, static, root, request-value/width
  and template bindings. Catalog and exact coverage snapshot retain them as todo;
  E8-02f3b owns actual entry-point execution, including NC-1328/1334 composition.
- Ledger: no SC/SZ/RLC/LU/PCS/MASK term changes. Three digest invocations, their
  compression work and publisher/adversary/repeated-attempt queries enter global
  H under RFC-0012 A15/A17 and RFC-0002 §4 assumption A1. No trust premise is
  converted into a probability; no new theorem or conjectural bound is asserted.
  The runtime accounting instance and gate belong to the implementation task;
  the integration owner runs the current specification change's native gate.
- Bounds: original Relation::validate remains mandatory. Entry dimensions and
  relation-length limits are static trusted metadata; witness data supplies no
  bound. Normalized mantissa widths are only hash-preimage bytes.
- Padding/masks: padded vocabulary positions and unchecked argmax rows are zero;
  no unchecked next token is read. Multi-block token indexing is pinned.
- Determinism: canonical encodings preserve list order, names and IDs. Request
  widths, decimal block names and normalization have one specified result.
- Parity: no CPU/SIMD/CUDA runtime code changes. Production declaration exports
  agree with the vector computation; no GPU change requires a new parity run.
- Cost model: only verifier T_misc gains request comparison and hashing. A16 gives
  formulas, not measured performance claims; no benchmark ledger is introduced.
- Verifier constraints: no verifier dependency or no_std behavior changes here.
  The future decoder must use fallible allocation, checked arithmetic and trusted
  size bounds, with original validation before proof parsing.
- Glossary: existing column, relation, model root, claim and profile vocabulary is
  retained; the new trusted registry is explicitly defined.
- Tier: byte-5 development only, no security level, standard/treaty admission or
  ZK replay. Byte 4 is outside the amendment.
- Commit rule: no new committed or virtual column, advice or source is introduced.
- Plain checker: unchanged. The Rust declaration exporter calls validate on all
  12 original variants; I consumed its exports and reran their vector comparisons.
  I did not independently rerun the full Rust checker/prover suite.
- Segments: no new cross-segment read or carried column.
- Proof bytes: no runtime or encoding change to honest proofs. Both current
  complete-window public/proof/relation hashes are pinned by the reference corpus.
- Ladder: the supplied one-layer T16 and eight-layer T64 dumps are made by the
  existing prove-then-verify exporter. I verified corpus/hash reproduction; the
  integration owner owns L0/native gates. No performance comparison is claimed.

Remaining risk: a malicious or incorrect trusted publisher can authenticate an
incorrect static declaration. A16 states that premise; only independent plan
derivation removes it. Runtime implementation, live controls and full gates were
not duplicated in this specification review.

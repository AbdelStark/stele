# E8-02f3b — independent standards review

Reviewer: `registry_impl_standards_review`, other-lane B/P review.
Base: `78ac6c93d3396f5d9e7262b5fbe4e16d48f61d16`.
Implementation: `c1fbb0dd98a3e59ceb050caf6832f077799cfec9`.
Gate/provenance correction also reviewed: `f487909d9daf9f629ef35606bc68f9cc0338cbbf`.

**Decision: APPROVE for standards and the B/P-owned integration surface.** No
unresolved documented standards violation or actionable design-smell finding.
This is not the separate soundness-auditor sign-off or permission to omit required
workspace/native, current-base and intended-merge-tree validation.

Sources read: root AGENTS.md; invariants, glossary and architecture; code,
forbidden, security, soundness and review-checklist guardrails; Workflows 01, 03,
08, 10 and 12; PR template; RFC-0027 tiers/lanes, RFC-0020 dependency rules,
RFC-0026 A15/A16; ADR-128/131/133 and Proposed ADR-134.

## Scope, independence and policy

The scope reaches the independent API and decoder helpers, its tests, the separate
control harness and registration/catalog, dependency policy/lockfile, native
admission inventories/pins/receipts, task claim and provenance. It introduces no
production publisher or CLI; E8-02f3c remains the serial successor. A16 expressly
requires every new control in this implementation, so the large combined diff is
not an actionable demand to split the controls away from their binding.

I approve ADR-134's exact harness-to-verifier edge. The separate harness described
by RFC-0020 §1 may call both implementations; this does not authorize a core
prover-to-verifier edge. `deny.toml` still forbids core imports of the harness and
forbidden verifier dependencies, including aliases, build and dev edges tested by
the policy regression. The verifier manifest remains field/hash only. The
follow-up admits precisely the new dependency and `src/registry.rs` in
`controls_layout`; it retains exact inventory comparison and rejects removal,
substitution and missing-source mutations.

I inspected the external snapshot and comparison record under
`/Users/abdel/dev/stele-validation/e8-02f3b-independent-initial/` and its sibling
comparison report. All snapshot hashes match; the final development/relation/lib
files equal the snapshot, and registered runtime differs only by test-module
wiring. This corroborates the recorded fresh-author/spec-first sequence; it does
not independently reconstruct the author's complete reading history.

The API and opaque success verdict state **trusted plan registry; development:
no security level**, preserve caller responsibility for the expected request and
disclose publisher/distribution trust. The original relation reaches A15 replay.
No independent model derivation, profile promotion or measured speedup is claimed.
Separate test codecs and production-fixture helpers preserve independence rather
than justify a shared abstraction. No heuristic smell warrants additional code.

## Executed checks and rejection experiment

- Python 3.12 targeted native receipt/pin regression, forbidden dependency-edge
  regression, quarantine checks and the corrected controls-layout regression:
  passed. The system Python 3.9 invocation first failed to import `tomllib`; it
  did not execute these tests and earns no credit.
- Actual release `catalog::rejects_registry_binding_tampers`: passed all ten
  controls. NC-1328/1334 require low-level A15 acceptance of rebuilt proofs before
  exact registered rejection; their production plain checks also executed.
- Registered integration target with `STELE_DEV_REPLAY_DIR=/tmp/stele-a16-windows`:
  all tests passed, including both named pinned-proof receipts. Registered unit
  target passed with all twelve declaration receipts and the blocked embedding
  case. Declaration receipts claim no proof acceptance.
- No-default-features verifier library check and an assert-based check of every
  verifier admission pin and snapshot hash: passed.

I tried to break it by changing the registry key, static bytes, ordered root,
request columns/width and static coefficient, and the controls NC-1325..1334
rejected them with their specified registry errors. I also suppressed required
receipts and changed dependency/source inventories in isolated regression
fixtures; the admission and policy checks rejected those cases.

## Workflow 03 checklist

| Question | Assessment |
|---|---|
| New public items and RFC | `registered::verify`, `Verified` and registry errors implement A16 §§1–4; documentation identifies their trust/claim boundaries. |
| Challenges and absorb order | No new challenge. Original relation/public bytes reach unchanged A15 replay; registry bytes never enter its transcript. |
| Emitted claims and consumers | No new proof claim; request checks precede existing replay and public evaluations/openings. |
| Binding controls | NC-1325/1327 key/roots; 1326 static; 1328–1333 request values/width; 1334 template; all executed. |
| Ledger/accounting | No SC/SZ/RLC/LU/PCS/MASK term changes. A16 §6's three digest invocations and global H/compression obligations remain explicit; required complete accounting gate belongs to coordinator. |
| Bound certificates | No new arithmetic relation instance; original relation validation remains after template binding and before proof parsing. |
| Padding/masks | Request code checks zero padded vocabulary/unchecked rows; tests exercise the request rules. Proof padding/masks unchanged. |
| Determinism | Ordered byte scans and vector iteration; no runtime hash-map iteration or timing-dependent reduction. |
| Parity | No GPU/SIMD change. Both registered CPU windows accept their exact existing public/proof/relation pins; GPU parity is not applicable to this diff. |
| Cost model | Added deterministic verifier work belongs to `T_misc` under A16 §6; no measured constant changed or benchmark result claimed. |
| Verifier bounds | `no_std` check passed, fallible allocations retained; relation length checked before decoding, counts checked before allocation, request domains constrained by trusted entry. |
| Glossary | No new forbidden synonym in the changed implementation. |
| Tier | Development only; success and API explicitly claim no security level. No promotion. |
| Commit rule | No committed or virtual column introduced. |
| Plain checker | Actual control fixture ran honest and both rebuilt-relation checks. No numerical module changed; existing near-miss suite remains a required coordinator gate. |
| Segments | No segment or carried-column behavior changed. |
| Proof bytes | Both pinned one/eight-layer proofs accepted unchanged; no proof encoding amendment or digest rerecording required. |
| Ladder | L0/L1 pinned windows exercised. No before/after performance pair; final required ladder/native and exact-tree receipts remain coordinator responsibilities. |

Skipped duplicate full workspace/native suites because the coordinator owns that
single gate run. Registry correctness/distribution and the later publisher/CLI
remain explicit limitations; this review grants no profile admission.

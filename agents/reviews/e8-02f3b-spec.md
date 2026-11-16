# E8-02f3b: registered verifier soundness review

Reviewer: `registry_impl_spec_review`, soundness-auditor and other-lane C reviewer.
Integration owner: `codex-root`, lane V. Fixed base:
`78ac6c93d3396f5d9e7262b5fbe4e16d48f61d16`. Implementation reviewed at
`c1fbb0dd98a3e59ceb050caf6832f077799cfec9`, including gate-only follow-up
`f487909d9daf9f629ef35606bc68f9cc0338cbbf`.

**Verdict:** approve on soundness and lane C review axes at the follow-up head.
No remaining implementation or scope finding. This does not assert completion of
the integration owner's workspace/native/current-merge-tree gates.

Read AGENTS.md, the soundness-auditor skill, security/code/soundness/forbidden
guardrails, invariants, glossary, the full review checklist, Workflows 03 and 10,
RFC-0016, RFC-0020, Accepted RFC-0026 A15/E1 and A16, ADR-128/131/133/134, and the
E8-02f3b acceptance criteria. RFC-0030 was read as required review background, not
as Accepted implementation authority.

## Contract and dependency assessment

Entry/public/key/static/relation-length/decode/request/template/replay ordering
matches A16. The public parser retains exact range and next-token presence rules;
token bounds precede key checks. Model identity uses record code counts, while the
static digest retains original blob byte lengths and ordered roots. Certificates
remain untrusted and reach the unchanged A15 verifier.

All relation list allocations are bounded by remaining encoded bytes, including
the newly checked reference-variable and factor counts. The trusted byte length is
checked before decoding. No domain is expanded from an untrusted log length during
preflight. Request allocation and dimensions derive from the trusted entry, with
fallible reserves; complete canonical decoding precedes request checks.

Reserved names, canonical block suffixes, unique presence, kind, exact values,
unsigned width and log length are checked before normalization. Only request value
bytes and widths change in the template preimage. All remaining bytes, names,
counts and order stay fixed. Original bytes and widths reach `development::verify`,
and therefore original validation, plan derivation, relation digest, public
evaluations, certificates and openings. No proof byte is read in preflight.

I approve ADR-134's exact `stele-negative-controls -> stele-verifier` edge. RFC-0020
§1 locates this outside the core, while §2 requires that "stele-prover never imports
stele-verifier". The local harness dependency satisfies A16's actual-entry-point
controls without changing RFC-0016 §3's verifier runtime dependencies. The alias
regression permits that edge and rejects all existing forbidden core edges,
including prover-to-verifier and core-to-harness. No external dependency is added.

At the initial head, the separate `controls_layout` exact inventory omitted the
new harness dependency and source. This prevented the task's required "native gates
pass" criterion. Follow-up `f487909d` fixes only those two inventory entries and
adds rejection cases for removing/substituting the edge and removing `registry.rs`.
I inspected and reran that regression successfully. It does not loosen other edges.

## Executed evidence and attacks

Independently executed on the reviewed source:

- `cargo test --release -p stele-verifier --test registered --locked --offline -- --nocapture`
  with `STELE_DEV_REPLAY_DIR=/tmp/stele-a16-windows`: 10 tests passed; both named
  one/eight-layer pinned full-proof receipts appeared.
- The same environment with `--lib registered::tests`: 2 tests passed, including
  the block mapping and all twelve named declaration receipts. Declarations alone
  are not counted as complete proofs.
- `cargo test --release -p stele-negative-controls --all-features --test catalog rejects_registry_binding_tampers --locked --offline -- --exact --nocapture`:
  passed, executing all ten NC-1325..1334 at the real registered entry point.
- `cargo check -p stele-verifier --no-default-features --lib --locked --offline`:
  passed. `cargo test --release -p stele-ir --lib relation::tests --locked --offline`:
  all 27 honest/near-miss plain-checker tests passed.
- Python 3.12 dependency-policy regression
  `scripts.tests.test_scaffold.ScaffoldTests.test_rejects_forbidden_dependency_edges`
  and follow-up inventory regression
  `scripts.tests.test_field_pcs_bench.FieldPcsBenchTests.test_rejects_production_benchmark_dependency_and_undeclared_example`:
  both passed.

NC-1328 changes exactly one embedding onehot scalar over a zero Token row;
NC-1334 changes exactly one coefficient on a zero public factor. Both retain the
plain checker, ordinary relation prover, original sources and certificates, and
low-level A15 acceptance before the required registry rejection. The fixture caches
only real producer outputs; each control reruns honest and tampered verification.

I tried to break it by supplying an honestly rebuilt proof for a changed embedding
onehot and by changing a static coefficient, and the control NC-1328/NC-1334 rejected
it with RegistryRequestMismatch/RegistryTemplateMismatch after A15 accepted it.

In an isolated three-crate copy, I removed request-value equality, removed template
digest equality, and corrupted normalized widths. Each mutation made its targeted
registered test fail; the original isolated source was restored. No shared runtime
source was mutated. Logs remain in the reviewer temporary directory
`stele-e8-spec-mutations-kb74640o`.

I verified all five initial snapshot hashes in the external provenance directory
`/Users/abdel/dev/stele-validation/e8-02f3b-independent-initial/`. The current runtime
matches that pre-comparison snapshot except for `cfg(test)` module wiring. The
author's fresh-context/read-boundary record and the coordinator's milestone
acknowledgement support ADR-128/131 provenance; runtime did not change after vector
comparison. This review inspected production controls independently.

## Workflow 03 checklist

- **Public items:** `registered::verify` and opaque `Verified` implement A16
  §§1–4; five registry errors implement its specified preflight errors. Display,
  Debug and API documentation state the trusted registry and no-security-level
  boundary, including the caller's expected-request responsibility.
- **Challenges:** none added. A15 replay still initializes its transcript with
  the full public input, absorbs the original relation digest and model roots,
  then runs the existing certificate/identity/lookup/matmul/opening schedule.
- **Claims/consumers:** none added or moved. Integer request comparisons are
  recomputed from authenticated metadata and public tokens; they are not compared
  only with another prover claim. A15 retains its original claim points and
  public-evaluation/source-opening consumers.
- **Bindings/controls:** NC-1325/1327 key and ordered roots; 1326 static bytes;
  1328 embedding onehot; 1329/1330 gathered mantissa value/width; 1331/1332/1333
  argmax onehot/below/rows; 1334 static template. All executed with exact errors.
  Additional tests cover malformed, duplicate, missing, extra, relabelled,
  wrong-kind/length, invalid-token and unsupported-profile cases.
- **Ledger:** no SC/SZ/RLC/LU/PCS/MASK line or theorem changes. A16 §6 adds three
  digest invocations and their compression work to global H; publisher, adversary
  and repeated attempts remain part of that population. Registry trust is not a
  probability or profile admission. I did not independently run the full
  soundness-accounting/native gate; that remains an integration gate.
- **Bound certificates:** no new arithmetic relation instance. Trusted dimensions
  and byte length bound preflight; the original relation still passes A15/E1 static
  validation. The normalized width is never used for arithmetic validation.
- **Padding/masks:** embedding vocabulary padding, argmax vocabulary padding and
  unchecked rows are zero; unchecked rows do not read next-token values. Positive,
  negative and saturated mantissas and split-block indices have exercised vectors.
- **Determinism:** ordered arrays and byte offsets only; no hash-map traversal,
  timing input or parallel reduction order. Canonical decimal suffixes are enforced.
- **Parity:** no SIMD/CUDA implementation changed. Both pinned CPU full proofs
  retain exact public/proof/relation hashes; GPU parity was not rerun or claimed.
- **Cost model:** verifier `T_misc` gains A16's request comparisons and hashes.
  No measured performance claim, benchmark constant or weight pass changes; no
  before/after performance ledger is claimed by this review.
- **Verifier:** `no_std` check passed; runtime dependencies remain field/hash only.
  New code uses typed errors and fallible allocation, with no unsafe, floats,
  recursion, panic/unwrap/expect path, or proof-derived preflight domain allocation.
- **Glossary:** existing relation/column/root/claim/registry terminology retained.
- **Tier:** development byte 5 only. Byte 4, ZK, independent full-plan derivation
  and standard/treaty admission are neither implemented nor claimed.
- **Commit rule:** no new committed or virtual columns, sources, advice or cuts.
- **Plain checker:** 27 original honest/near-miss tests passed; the control fixture
  also plain-checks the honest relation and both altered relations before proving.
- **Segments:** no cross-segment read or carried-column behavior changes.
- **Proof bytes:** original relation replay and proof encodings remain unchanged;
  both full-window proof hashes match the existing A16 pins. Registry bytes never
  enter the transcript. The intentionally rebuilt control proofs prove their
  altered relations under A15 and do not replace honest pins.
- **Ladder:** supplied one-layer T16 (L0) and eight-layer T64 (L1) pinned full
  proofs were accepted by this review. Fresh production generation and complete
  current-base native/workspace gates remain the integration owner's checks.

Remaining premise: the caller must authenticate a correct trusted entry and compare
the decoded public request with its expected request. This change does not remove
publisher trust. I did not duplicate the full workspace/native or GPU gates.

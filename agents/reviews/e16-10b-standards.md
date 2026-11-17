# E16-10b standards review

Reviewer: Codex, independent lane B reviewer of lane V work (PR #397).
Fixed base and verified merge base: `afb147a374fd44d7fdca2cad28689f8dbc5b1110`.
Implementation reviewed: `40b9cb97e08007b6614f9035ec3420673bcb66e6`.
Final reviewed head: `e819ebf286191f5e304723010f1e817a2219c700`.
Diff: `git diff afb147a374fd44d7fdca2cad28689f8dbc5b1110...e819ebf286191f5e304723010f1e817a2219c700`.
Commits: claim `3b6e809b`, implementation `40b9cb97`, documentation `e819ebf2`.

## Disposition and findings

I approve the standards axis at the final reviewed head. No unresolved
documented-standard violations or heuristic smell findings.

One minor violation was found and resolved: the new public runner at
`tests/negative-controls/src/development_bindings.rs:93` lacked item documentation.
`agents/guardrails/code.md:3` requires public functions to document their claim,
and Workflow 01 item 5 requires public-item docs. The two-line comment in
`e819ebf2` documents the control scope and rejection contract; that commit changes
no behavior. This requirement is not enforced by the workspace lints.

The supplied smell baseline was considered as judgement, subordinate to repository
rules. The three small standalone wrappers implement Workflow 08's separate-target
requirement; their repetition does not justify an abstraction. Fixed `ColumnId`
selectors are deliberate fixture declarations, guarded by column-name, width,
value and restoration assertions. The fixture reuse removes repeated expensive
construction without sharing mutable proof state.

Read AGENTS.md, invariants, glossary, all guardrails, Workflows 01/03/08/10/12,
the negative-control-author and soundness-auditor skills, the two-axis review
skill, the control README, task E16-10b and RFC-0026 §§2.3/4/9/A17/A18. RFC-0030
was read as Draft guidance, not an Accepted contract. No CONTRIBUTING.md,
CODING_STANDARDS.md or nested AGENTS.md was found.

## Control and inventory checks

The new module, registrations and standalone targets require `controls`.
The manifest retains ADR-108's off-by-default feature map; the gate checks that
map exactly. Removing any new source or target fails the inventory test.
No dependency, production API, verifier predicate or proof encoding changes.

`fixtures()` returns an immutable cached slice. Producers build fresh executors,
transcripts and owned proof containers; proof hooks clone before mutation.
Cached construction errors remain errors. The shared fixture path preserves
NC-1303/1307 behavior. Unknown runner ids fail before fixture construction.

`check_control` and `check_proof_control` still require honest acceptance, a
non-no-op mutation and the exact typed verifier error. Producer failure,
acceptance and wrong errors cannot return success. `catalog::report` executes
registered controls and rejects missing, failed, duplicate or mismatched
registrations; the independent failure-path test passed. Static inventory
reconciles to 246 controls, 120 binding categories, 150 done controls,
78 covered proof categories and 96 missing controls; this arithmetic alone
does not grant execution credit. The parent's full runtime catalog test then
completed successfully: all eight tests passed, including the actual
execution-backed coverage assertions in
`accepts_repository_catalog_without_crediting_stub`.

A17's Policy 1 and Policy 2 errors remain distinct. A18 grants only the declared
profiles 3/5 cases. The catalog explicitly limits the early nonce rejection and
does not claim exhaustive Merkle evidence. The E16-02 claim is corrected without
removing NC-1310's Accepted exception.

I tried to break it by incrementing entry zero of `L0/norm1/S_0` within its
declared width, honestly recommitting it while retaining reference identity
rounds, and the control NC-1302 rejected it with exactly
`Engine(Sumcheck(FinalEvaluationMismatch))` on L0 and L1 under profiles 3 and 5.
The same run accepted the honest proofs and required the plain checker to reject
the one-value near miss as identity `L0/norm1/S/0` at point zero.

## Workflow 03 checklist

- [x] Public items: the control runner implements RFC-0026 §§4/9 and A17/A18; its docs are present at the final head. The crate-private fixture exposure serves only the sibling control module.
- [x] Challenges/absorbs: no new challenge or label; the replay starts a fresh production transcript from the ordinary public input, then uses the existing relation producer and unchanged verifier order.
- [x] Claims/consumers: NC-1302 uses genuine changed-witness finals; NC-1308 uses the existing controls-only routing selector and genuine batches/openings. The actual composed verifier consumes each proof with its independently derived claims.
- [x] Bindings/controls: no new production binding; NC-1302/1306/1308 add composed coverage for existing bindings. One-entry/root/prefix and restoration assertions retain Workflow 08's single semantic tamper.
- [x] Ledger: no accounting line changes; the accounting-union gate was not rerun by this reviewer.
- [x] Bound certificates: no new relation instance kind or dynamic bound; the existing layout and verifier validation remain unchanged.
- [x] Padding/masks: unchanged production semantics; the routing producer requires the next real same-group column, with equal values, rather than padding.
- [x] Determinism: fixed ordered fixture loops and immutable OnceLock cache; no new RNG, hash-map iteration or timing-dependent reduction.
- [x] Parity: no CPU/SIMD/CUDA implementation change; no independent GPU parity claim.
- [x] Cost model: no production cost term changes or performance claim; no performance ledger pair is needed for this control-only slice.
- [x] Verifier: unchanged source/dependencies and no bypass; assertions are confined to the separate test harness and existing controls-only producer.
- [x] Glossary: no forbidden synonym introduced.
- [x] Tier: development only, with no security-level, zero-knowledge or promotion claim.
- [x] Commit rule: no new committed or virtual columns; only the adversarial witness changes.
- [x] Plain checker: independently executed NC-1302, including honest checks and the exact in-width identity near miss on both rungs/profiles.
- [x] Segments: no relation or cross-segment read changes.
- [x] Proof bytes: the regenerated honest proofs must equal ordinary composed proofs; routed proofs preserve every pre-opening section. Production bytes and pins are not edited; full digest evidence remains an integration gate.
- [x] Ladder: independent NC-1302 covers L0/T=16 and L1/T=64 at profiles 3/5. Supplied GREEN evidence covers all fourteen new composed cases. No benchmark comparison or other-profile credit is claimed.

## Checks and limits

Independently executed:

- `target/release/deps/nc_1302-09668dfea419f75c --exact rejects_nc_1302 --nocapture`: passed all four cases, using the implementation binary already built for `40b9cb97`; the final delta is documentation only.
- `target/release/deps/catalog-b68d9b6a794d6910 rejects_unexecuted_or_failed_coverage --exact --nocapture`: passed.
- `uv run --no-project --python 3.12 python -B -m unittest scripts.tests.test_field_pcs_bench.FieldPcsBenchTests.test_rejects_production_benchmark_dependency_and_undeclared_example`: passed. The system `python3` attempt could not import `tomllib`; rerunning under 3.12 resolved that environment issue.
- Independent catalog row/range inventory assertions and `git diff --check` through `e819ebf2`: passed.

Inspected supplied `/tmp/e16-10b-red-all.log` (three unregistered-control failures),
`/tmp/e16-10b-green.log` (all fourteen composed cases), and the targeted Clippy,
default-Clippy and inventory logs. The completed `/tmp/e16-10b-catalog.log`
records all eight catalog tests passing. Also inspected the existing harness self-tests
for no-op mutations, producer errors, honest rejection, acceptance and wrong
errors; these self-tests were not independently rerun here.

Skipped duplicate full-workspace/native suites, broad plain-checker tests and GPU checks.
Remaining risk: proof pins and passing current-main merge-tree gates remain integration requirements; this standards approval does not certify them.

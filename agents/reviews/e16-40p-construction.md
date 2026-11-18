# E16-40p borrowed GKR construction review

Development research, lane V. Reviewed diff:
`4dbbfd474ba692345e8213c735e401709586ad5c...47e5c70ac8fd580fc826136bda613c77c9711345`.
Task claim `ca1e2d5e`, tests-first commit `dde025aa`, implementation `47e5c70a`.
The initial test failed because the construction types and method did not exist.

## Spec — owning lane P

Reviewer `gkr_construction_spec_review`: PASS, no blocking findings or scope creep;
owning lane P approves this interface.

Construction borrows production columns, layers, selectors, table rows and
challenge vectors. Allocations contain descriptors, terms or small mask blocks;
no full factor, selector, tuple, owner or equality arrays are materialized.
Comparison with `lookup::factors` and `combined` confirms factor order, equality
placement, selector halves, mask coordinates, shifts, table padding and degree.
Compact terms come directly from `compact_terms`.

Tests cover heterogeneous members, multiple tuple coordinates, permutations,
selectors, padding, first/interior/simple/compact leaves, first-and-leaf cases,
and Balanced/Narrow lifetimes. They compare every factor and mask before folding,
every round, folded tables and compact finals. Ordinary and observed proofs,
encoded bytes, transcript continuation and disclosure agree. Validation, callback
errors and wrong-model rejection remain covered. Changed finals reject with
`ClaimMismatch`; malformed finals produce `ProofShape`; a changed construction
scale fails the reference comparison.

No challenges, bindings, commitments, virtual columns, bounds, verifier code,
protocol behavior or ledger formulas change. Observation follows existing public
aborts and final checks. Private witness references remain callback-scoped; no
logging or inventory path is added. RFC-0014 A1's distinction between host
preparation and device-memory evidence is respected. No performance claim or
device consumer appears, consistent with Workflow 12.

The reviewer independently ran the GKR benchmark tests without `std`: all passed.
Full workspace, Clippy and ladder suites were outside this focused review.

## Standards — lane B

Reviewer `gkr_construction_standards_review`: PASS, no documented-standard
breaches or actionable heuristic smells.

Module, exports and call site remain behind off-by-default `bench`; `alloc`/`core`
preserve the crate's `no_std` boundary. Construction exposes immutable,
step-scoped borrows and owned descriptor/mask copies. Private witness material is
documented; nothing is logged or added to public inventory. Callback output cannot
supply proof values. Construction and callback errors propagate. Actual production
helpers supply ordinary and compact terms.

Tests compare factors, masks, terms, rounds and compact finals, including a
one-value near miss. Existing proof-byte, transcript, disclosure and callback-error
checks remain. No dependency, CUDA, protocol, challenge or binding changes appear.
Descriptor work is explicitly host preparation; no performance claim requires a
new ledger. The E16-40o to E16-40p lane-V stack complies with Workflow 12, and no
device consumer lands in this interface change.

The adapter mirrors production factor dispatch, creating some maintenance
duplication. Shared term builders and independent parity tests address that risk
without expanding this change into a core refactor. This review was read-only;
the reviewer did not repeat tests.

## Validation and merge boundary

Author checks passed at `47e5c70a`: reductions all-target/all-feature Clippy with
warnings denied; focused GKR/lookup/batch tests with `bench,std`; GKR tests with
`bench` without `std`; default `no_std` reductions/verifier check; CUDA research
all-target Clippy; formatting and diff checks. All eight factor forms are exercised.
The external validation logs are `stele-validation/e16-40p-*.log`.

Full workspace/native/ladder and current-main/intended-merge-tree validation remain
required in stack order. PR #401 is the one branch awaiting mandatory CI; no
cumulative full suite was queued. The device consumer waits for this interface
to merge. Neither review grants GPU execution, integrated-proof parity, complete
device-memory qualification, measured acceleration or ADR-127 GO credit.

## Earlier stack placement, unchanged implementation

The replacement branch `task/E16-40p-gkr-construction-interface` places this
independent interface directly after E16-40h and before E16-40i. Its only task
dependency, E16-40g, is already merged. The original branch and pinned qualification
packages remain preserved. The original review conclusions above apply unchanged.

Original base `4dbbfd47` and replacement base `984023f0` have the same reductions
tree, `2fc4c83ebafea6d80f7db7bad3494951dd876685`. Original and replacement
implementations have the same reductions tree,
`41d6ca9de7e903d2550cd93990a719fd4fe8a918`. The reductions diff is byte-identical:
SHA-256 `2dc2d0f0ca29b36cfe3fdc11c1ff81848ca8c39561d8353e62bb1c5d2aedf88c`.
Only task placement and this review record differ.

At replacement implementation `791d3ff4`, focused GKR/lookup/batch tests with
`bench,std`, no-default-feature reductions/verifier checking, reductions
all-target/all-feature Clippy with warnings denied, formatting, task-graph,
documentation-link and diff checks passed. Logs are
`stele-validation/e16-40p-interface-{tests,no-std,clippy}.log`.
PR #401 has merged; PR #403 is the single branch running full CI. This interface
remains draft until its turn for full workspace/native/ladder validation against
current main and the intended merge tree. Its device consumer still waits for merge.

## Native inventory repair

Full CI1073 (`44249901696`) rejected the two new construction files because the
native gate's exact reductions inventory had not been updated. No proof failed;
the native gate stopped at file admission. Tests-first `7aa3adb8` adds each path
to the missing-file controls; `bacd5a62` admits exactly
`src/zk_gkr_construction.rs` and `tests/common/gkr_construction.rs`.
The exact-set comparison and unreviewed-file rejection remain unchanged.

Honest admission failed before the repair. The two focused inventory tests and
all 16 field-source gate tests pass afterward. Logs:
`stele-validation/e16-40p-{layout-red,layout-green,field-source-gate}.log`.
Fresh `construction_inventory_spec_review` (owning lane P) and
`construction_inventory_standards_review` (lane B) both PASS the pinned
`1a6599b7...bacd5a62` delta, independently running the focused tests.
Full CI must pass again on the resulting head and current-main merge tree.

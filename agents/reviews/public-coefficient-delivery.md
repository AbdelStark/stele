# Public coefficient primitive delivery

## Task
E3-06a — public coefficient arithmetic (branch task/E3-06a-public-evidence).
E3-06a remains in progress pending gated merge. E3-06 remains blocked on A4.
No stage or end-to-end completion claim is made.

## RFC sections implemented
RFC-0006 A7 and RFC-0020 A3. Six immutable, checked mathematical coefficients
now evaluate in no_std Rust. Masks retain two 16-element field-state arrays;
source-vector allocations are checked against an explicit total entry budget.
The current crate imports only field; the permitted sumcheck edge is unused.

## Bindings added and controls
No protocol bindings or NC registrations added. Independent direct Boolean-table
sums check 10,000 queries per kind per extension field (120,000 total), plus
unequal source axes, full source-axis sets, large masks, scalar axes, malformed
shapes, wrong characteristic and resource limits. The gate rejects an altered
DP result, a missing OM31 test, added stage code and an extra dependency section.
NC-0203 and committed-source/CQIS authentication remain actual consumer work.

## Soundness ledger
No challenge, transcript, SC record, certificate or proof bytes change.
`soundness-accounting.sh` passed with the existing 12-label registry and actual
sumcheck/batch/zerocheck/streaming records. Existing catalog coverage remains
3/17 bindings and 14/72 controls; one configuration control is separate.

## Cost model
T_misc obtains the A7 explicit evaluator work/storage bounds. No measured
constant, weight-pass count, benchmark result or profile admission changes;
there is therefore no new benchmark ledger or timing claim.

## Gates
- Passed: fmt, workspace/all-target Clippy with warnings denied, workspace tests.
- Passed: digest, negative-controls, soundness-accounting, ledger validation.
- Passed: RFC status, docs links, glossary and Rust policy, wasm32-unknown-unknown no_std compilation.
- Passed: cargo-deny 0.20.2 bans, scaffold/dependency rejection tests, targeted
  gate mutations (including rejection of unvalidated GKR implementations).
- GPU unchanged; no GPU parity result claimed. Native encoder full-byte digests
  and sealing checks pass. The inference digest remains an E8-06 scaffold guard.
  Hosted CI and merge remain required; full inference/profile gaps remain.

## Determinism / padding / masks
Fixed axis/bit/state order. Validity and selectors enter Boolean weights before
extension; all final points use canonical axis order. Sources remain immutable
borrows, never a flag or callback claiming verification. Dimension validation
precedes indexing; checked vector sizes precede allocation. Safe Rust only.

## Soundness-auditor review
Reviewer codex-root, also author: same-author review, not independent audit.
The complete Workflow 03 checklist is in public-coefficient-a7.md. Production
review confirms no new claim/challenge, unchanged ledger, no integer identity,
explicit padding, deterministic traversal, no GPU code and no new dependency
beyond the approved downward field edge. No panicking operation on admitted
queries was found; all index/cast bounds follow checked shapes/vector lengths.
I tried to break it by selecting the wrong DP acceptance state, omitting the
OM31 test, and adding unvalidated stage code, and the control gate regression
tests rejected it. These are gate/arithmetic tests, not inference NC credit.

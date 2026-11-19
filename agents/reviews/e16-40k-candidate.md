# E16-40k: generated-round candidate review

Reviewed change: `cb46de3c...0dd0818f562fc667f851f43b1e8d58ceab9e63bd`.
Research-only candidate; no successful hardware qualification or performance
result is established by this review.

## Spec / owning GPU

Reviewer `/root/prepare_fix_spec_review`: **PASS to enter H100 qualification**.
The wrapper delegates to existing `qmul`. Both `prepare` and `round` consume
`round_source`; factor/coefficient order, base/mixed paths, ±1 handling, fixed
reductions, canonical stores and invalid-value rejection remain unchanged.
The fixture exactly equals original inventory case 9, and its base mode, seed,
values, coefficients and reduced geometry are preserved. The regression checks
initial tables, every polynomial and every folded table. Its preparation limit
requires the documented external deadline to stop a hung driver call.

The reviewer verified all diagnostic payload hashes and the separate terminal
readback. The wording distinguishes observed phases from the hypothetical
compiler-expansion cause. No new core backend, protocol, proof byte, dependency,
performance or GO claim. No actionable Spec finding.

## Standards / another lane

Reviewer `/root/prepare_fix_standards_review`: **PASS to enter qualification**.
The helper has a concrete compiler purpose. No documented-standard breach or
material code-smell finding. Workflow 03 checklist: no new public Rust interface,
challenge, claim, binding, accounting, static bound, padding rule, committed
column, segment dependency or verifier change. Arithmetic order is unchanged;
GPU parity and proof gates remain pending. Preparation concerns `T_misc`; no
measured movement is claimed.

The reviewer reran all 17 default research tests and six diagnostic controls.
Malformed inventories, incomplete/forged receipts, non-phase timeouts and
nonzero exits were rejected; the descendant-cleanup control passed. Fixture,
seed and all diagnostic digest pins were independently verified.

## Validation and limits

Default research tests, CUDA all-target Clippy with warnings denied, workspace
and research formatting pass. Candidate hardware execution, mandatory full
workspace/native/parity gates, and qualification of acceptable runtime remain
open. All original 1,000-case and allocation-accounting requirements remain.
Compact finals, raw-kernel qualification, actual-size coverage and full-proof
parity remain outside this candidate qualification.

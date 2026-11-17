# E16-40k: bounded preparation diagnostic review

Scope: one external diagnostic of unchanged E16-40d source
`8038e131e93d59c08328c7c94a979f3c551058e1`, after the terminal and reported
[job 6685 failure](e16-40d-h100-failure.md). This does not qualify a kernel,
complete E16-40k, establish a performance result or reopen ADR-127.

The diagnostic runs original cases 0 and 9, each at rounds 0 and 1. It separates
setup, device construction, NVRTC, module loading, function lookup and, for round
0, the original full preparation and round/fold path. Initial tables, all round
polynomials and every folded factor/mask table are checked against the CPU.
Compiler options and generated CUDA remain those of the original candidate.

The capture requires both passing controls and all four case/round receipts.
It records phase deadlines and kills the isolated process group, including a
TERM-resistant child after its leader exits. Only a case-9 phase timeout can
establish a reproduced stall. Whole-probe or campaign exhaustion is an incomplete
diagnostic and fails. All outcomes explicitly exclude parity/performance credit.

Local packaging initially exposed the archive's `source/` prefix; extraction now
strips exactly that component. Spec review additionally required the original
initial-table comparison and separate phase/campaign timeout classification.
Both fixes were independently re-reviewed before submission.

## Spec / owning GPU

Reviewer: `/root/prepare_diagnostic_spec_review`. **PASS for this diagnostic.**
All 2,285 archived source files match the pinned Git commit; generated prefixes,
original case/seed selection and `compute_90` options match. Six Python 3.12
controls reject forged/missing receipts, nonzero exits, incomplete campaigns and
non-phase timeouts, and verify descendant cleanup. No remaining finding.

## Standards / another lane

Reviewer: `/root/prepare_diagnostic_standards_review`. **PASS for this diagnostic.**
No documented-standard violation or material code-smell finding. The reviewer
tried incomplete output, forged phases, missing cases, non-phase timeouts,
nonzero exits and a TERM-resistant descendant; the controls rejected them or
killed the descendant. All six controls and shell syntax validation pass.
No protocol, claim, challenge, bound, committed column, verifier or reduction
order changes. Hardware behavior and complete qualification remain unverified.

## Pins and local validation

The complete [input manifest](e16-40k-diagnostic-pins.json) has SHA-256
`6d3e7d41914471fe830ad0ffc2705fcd7865f99e51eacf5bfd6d5e4e7b7b8dd6`.
Both reviewers verified all its hashes and the packaged worker/source identities.
The exact package builds with Rust 1.90.0, release/frozen, against the original
archive. Local controls reject absent CUDA and a mismatched generated case.
Remote Python 3.12.3 ran the six controls and verified all input hashes before
submission. The launcher disables requeue. Full repository and proof gates are
not supplied by this diagnostic review.

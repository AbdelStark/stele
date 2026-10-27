# Instance batching delivery review (RFC-0006 A2 / RFC-0012 A4)

Reviewer: codex-root, also the author; soundness-auditor, sumcheck-prover-engineer
and hash-owner passes, not independent audit. Approve mode 0; E3-02 stays open
for mode 1, its 10^4 coefficient checks, full rejection corpus and benchmark ledger.

I tried to break it by omitting a member contribution and drawing gamma before
Batch, and the controls NC-0202/0206 rejected it with RoundSumMismatch. These are
actual both-field instance controls, not complete two-mode catalog coverage.
The unused-input and omitted-BatchFinal extensions also reject at their exact checks.

Workflow 03 checklist:
- Public items: Batch/Claim/Reduction/RlcRecord implement A2 mode 0; A4 labels are closed.
- Challenges: full descriptor before gamma; Round before SC; all finals before continuation.
- Claims: each original tensor at its derived suffix; public adapter closes every one.
- Bindings: the four controls above run in the gate; catalog credit waits for mode 1.
- Ledger: one t/p^d RLC and one M D/p^d SC; 42 independent byte/record cases,
  including a real A1 continuation, and a gate mutation of the RLC numerator.
- Certificates: field identities only; no integer bound or full-profile claim. Q12 stays open.
- Padding/masks: virtual leading selector surrounds P; inactive sums are computed from data.
- Determinism: ordered instances/tables, fixed bytes, no new RNG/state injection.
- Parity: Rust/Python bytes in both fields; existing A1 corpus retained; no GPU change.
- Costs: original tables fold in place; no weight-pass change or measured speed claim.
- Verifier: no_std, checked shapes/allocations, alias consistency, explicit final obligations.
- Glossary: existing terms; successful reduction is not complete-statement acceptance.

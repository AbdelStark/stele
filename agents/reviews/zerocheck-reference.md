# E3-03 seeded reference review

Reviewer: codex-root, also the author. Same-author soundness-auditor and
sumcheck-prover-engineer passes; not independent audit. Scope: direct CPU
reference and mandatory seeded comparisons; production code is unchanged.

I tried to break it by changing one unused original slice final, and the control
ClaimMismatch rejected it (NC-0209). The new reference uses direct original-slice
MLE evaluation and exhaustive residual sums, not production hybrid construction
or tail-table folding. Fixed-node Lagrange denominators are nonzero; no random
quantity is inverted. Sharing canonical encoding, transcript and field/eq
primitives does not constitute an independent full implementation; the separate
Python bytes/decision corpus retains that complementary check.

Workflow 03 checklist:
- Public items: no library API change; test-only reference implements A3.
- Challenges/absorbs: Zero before j weights; optional ZeroSkip before u; each
  Round before r; all original finals in ZeroFinal before continuation.
- Claims/consumers: all seeded proofs pass actual verify_public; comparison
  checks the complete proof and reference/prover/verifier continuation.
- Bindings/controls: no new binding or NC credit; existing controls retained.
- Ledger: three SC phases unchanged; both gates require both named field tests.
- Certificates: no integer identity or field-faithfulness certificate added.
- Padding/masks: unchanged plan obligations; no new privacy claim.
- Determinism: fixed fixture seed and iteration order; every eligible shape
  appears among 1,000 cases per degree per field, 10,000 total.
- Parity: direct CPU versus dense CPU in both fields; GPU not changed.
- Costs: no measured improvement or fit; reference may support later comparison.
- Verifier: no_std code unchanged; allocations/assertions belong to small tests.
- Glossary: original slice claims retain their existing meaning.

Sign-off: approve reference coverage with complete cost/consumer/memory ledgers
still required by E3-03. Finite tests do not prove soundness or resolve Q12.

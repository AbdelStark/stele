# E3-03 interpolation prerequisite review

Reviewer: codex-root, also the author. Same-author soundness-auditor and
sumcheck-prover-engineer passes; not independent audit. Scope: interpolation
arithmetic and expanded research fixtures, not the A3 production consumer.

A3 permits 61 nodes. Products of their integer differences overflow i64;
accumulating denominators in K avoids overflow while preserving their value
modulo p. Every factor is nonzero because node differences are at most 60<p.
The helper rejects counts outside 1..=61 and reserves fallibly. Existing A1/A2
calls remain bounded by five nodes and produce the same field elements/bytes.
The new weights vector adds at most 61 field elements of temporary allocation;
no measured c_sc improvement or cost-model fit is claimed.

I tried to break it by changing a round evaluation, and the control
RoundSumMismatch rejected it. Existing production controls and byte/SC/RLC
corpora remain required gates. Direct tests cover both fields through degree 60,
node endpoints, and invalid counts; research fixtures now include all 130 honest
cases and the first challenge after ZeroFinal. Fixtures earn no NC credit.

Workflow 03 checklist:
- Public items: none; private arithmetic follows RFC-0006 A1/A3.
- Challenges/absorbs: no production schedule or label change.
- Claims/consumers: unchanged; all A1/A2 obligations remain.
- Bindings/controls: none added; existing NC-0200/0201/0205/0202/0206/0802 retained.
- Ledger: no new loss; current accounting gate must still pass.
- Certificates: field interpolation only; no integer witness identity added.
- Padding/masks: unchanged, no new commitment or privacy claim.
- Determinism: fixed node order and exact field operations.
- Parity: both-field interpolation checks and existing core byte corpora.
- Costs: bounded temporary allocation; no benchmark or speedup claim.
- Verifier: no_std, fallible allocation, bounded indices and nonzero denominators.
- Glossary: existing terminology, no new public abstraction.

Sign-off: approve this prerequisite with E3-03 production/parity/performance
requirements retained. The engine, labels and real new controls ship together.

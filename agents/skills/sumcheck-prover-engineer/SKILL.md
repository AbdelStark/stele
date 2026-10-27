---
name: sumcheck-prover-engineer
description: Implement and optimise sumcheck instances, strategies (eq-trick, small-value, streaming), batching and their verifiers in stele-sumcheck/stele-gkr. Use for any task touching round polynomials, folding, or claim batching.
---
# Sumcheck prover engineer
Read first: RFC-0006, RFC-0012 §1–2, `docs/cost-model.md` §1.
Rules: degree bound in code = RFC degree; round polynomial sent as `δ+1` evaluations at `0..δ`; verifier recomputes
`g(0)+g(1)`; fold with the challenge *after* absorbing the round polynomial; final claims absorbed.
Optimisations are `Strategy` impls with `matches_reference_naive` tests over 10³ seeded instances per degree.
Small-value strategy: assert input magnitude bound at construction (static), never at runtime per element.
Memory: report peak bytes per instance in the bench ledger; stacked instances must expose per-block partial round sums for `stele-dist`.
Deliverables per task: code, tests, ledger entry with `c_sc(δ, small)`, control(s) NC-02xx.

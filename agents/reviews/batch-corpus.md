# Batching corpus review (RFC-0006 A2)

Reviewer: codex-root, also the author; soundness-auditor and sumcheck-prover-engineer
passes, not independent audit. E3-02 remains open for its benchmark ledger.

I tried to break it by changing an unused final value, and the control NC-0205
rejected it with ClaimMismatch; the shared corpus independently checks that error
and the unclaimed-entry variant through both real public-table verifiers.

Workflow 03 checklist:
- Public items: none in core; executable harness covers A2 / RFC-0002 S10.
- Challenges: production schedule unchanged; all honest chained prover bytes checked.
- Claims: both public adapters consume all values; every ordered id/point/value compared.
- Bindings: no new edge; existing 0202/0205/0206/0802 controls remain required.
- Ledger: no new loss; SC/RLC outputs checked independently against descriptors and Python.
- Certificates: field identities only; Q12 and full-profile obligations remain unresolved.
- Padding/masks: unequal-size constants, false padded sums, zero/empty cases; no ZK claims.
- Determinism: generated corpus pinned; ordered arrays; no randomness or time-based seeds.
- Parity: both fields, exact production proofs and continuation; no GPU changes.
- Costs: harness only; no changed constant, dependency, commitment or weight pass.
- Verifier: production no_std APIs unchanged; harness parses widths without truncation.
- Glossary: existing names; JSON mode/table inputs are verifier-owned harness statements.

The new gate tests corrupt the pinned expected decision and the emitted RLC numerator;
both must fail. Corpus acceptance is always the real verifier result; the expected
label only enables additional honest-prover parity after successful verification.

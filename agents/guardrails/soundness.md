# Guardrail — soundness
- A challenge is drawn only by `Transcript::challenge(label)`; the label must be registered; the absorb order must match the RFC.
- Every sumcheck's degree bound in code equals the RFC's; a mismatch is a soundness bug even if tests pass.
- Final claimed values are absorbed before the next challenge (weak-FS).
- PCS column indices are derived after `u` (or its commitment) is absorbed.
- Multiplicities are committed before `α, β` are drawn; in treaty, both challenge pairs are drawn after that commitment.
- Any new public MLE (`A` in RFC-0006 §6) ships with its verifier-side evaluation and a test that the prover and verifier evaluations agree on 10⁴ random points.
- Bound certificates: never compute a bound from runtime data.
- Padding rows must be excluded by selectors in every lookup and masked in every zerocheck.
- When in doubt, write the attack as a control first; if it passes, you have found a bug, not a test problem.

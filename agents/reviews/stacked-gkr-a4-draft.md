# RFC-0006 A4 draft review

Reviewer: codex-root, also the author; rfc-author, gkr-reduction-author and
soundness-auditor passes on the research/escalation scope, not independent audit.
Decision: publish the counterexamples and Draft contract requirements. Do not
accept A4 or implement protocol behavior from it until its open requirements and
required reviews are complete. E3-06 is blocked; its original criteria remain.

Workflow 03 checklist:
- Public API: unchanged; stele-gkr retains its scaffold and closed gate guards.
- Challenges/absorbs: no implemented change. Draft requires a complete descriptor
  and exact schedule before acceptance; it assigns no new challenge implicitly.
- Claims/consumers: unchanged. Draft requires original tensor coordinates and real
  consumption, including authenticated selection-index and public-table sources.
- Bindings/controls: no production control credit. NC-0203 still needs an actual
  closed-statement wrong-layer control; the two counterexamples are algebra only.
- Ledger: no changed loss or certified profile. Complete summand degree and
  challenge accounting remain an acceptance prerequisite, including selectors.
- Certificates: no integer inference identity is introduced. CQIS certificates
  remain mandatory where an actual integer reduction is instantiated.
- Padding/masks: ambiguity is recorded, not silently resolved by a guessed selector.
- Determinism: fixed seed, MSB axes, exact modular operations; no timing-dependent
  behavior. 1,000 elimination orders agree with direct MLE evaluation.
- Parity: only research algebra; no production or GPU parity claim.
- Costs: c_sc/T_misc and redistribution terms identified; no benchmark or fitted
  constant changed. A message all-reduce is not claimed to fold input state.
- Verifier: no code, no_std or API change. Unsupported degrees must not silently
  exceed the existing engine's bound.
- Glossary: current terms retained; no new tensor commitment.

Adversarial finding: the wrong nonlinear layer-fold polynomial agrees at both
Boolean endpoints yet differs at node two (25 versus 17). This justifies the
specification gate; it is not an observed false acceptance by a production verifier.
No approval sentence claiming a production control was run is appropriate here.

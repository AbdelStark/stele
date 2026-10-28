# RFC-0006 A6 / RFC-0014 A1 draft review

Reviewer: codex-root, also the author; sumcheck-prover-engineer, rfc-author and
soundness-auditor passes. This is not an independent audit. Scope is the research
and escalation, not acceptance of the incomplete streaming contract.

- Public API: unchanged. No production strategy imports the research prototype.
  The two amendments remain Draft; E3-05 is blocked with all original criteria.
- Challenges: research uses the existing A1 Instance, Round/challenge and Final
  order. Each window emits ordinary A1 nodes; no additional challenge or label.
- Claims: every original input survives materialization, including unused inputs.
  The original public consumer checks the full point/final values; continuation
  comparisons include Final absorption. No source-supplied replacement consumer.
- Bindings: no new production binding/control credit. Ten directed research
  unused-tail mutations leave rounds unchanged and alter exactly one final value;
  all reject ClaimMismatch. Immutable-source enforcement remains a contract item.
- Ledger: no loss change; deterministic A1 equivalence uses m*delta/p^d unchanged.
  The conjectural complexity lower bound in the literature is not a security
  theorem or an unconditional impossibility claim. Q12 remains separate.
- Certificates: field algebra only; no new integer identity or CQIS certificate.
- Padding/masks: no inference selector or padded-tensor reduction is implemented.
  Candidate coordinates use the existing MSB order and unchanged input identities.
- Determinism: seeded field inputs, ordered windows/grids/visits, no timing choices.
- Parity: 60 research cases compare every A1 message, final, point and continuation
  in both fields. They share the existing field/transcript oracle. No Rust/GPU
  parity or complete implementation claim follows from this experiment.
- Costs: logical read counts are checked against actual recorded visits; source
  order is explicitly nonsequential. The grid/tail counterexample refutes a
  universal one-window budget only within this construction. The prototype keeps
  inputs, logs and temporary lists; it does not prove a memory bound. No measured
  cost-model constant or weight-pass count changes. Physical I/O and recomputation
  costs remain acceptance gates, including preservation of INV-7.
- Verifier: unchanged; no no_std, panic, length-validation or source dependency
  change. The production source error/abort contract remains unspecified.
- Glossary: existing claim/reduction/stage/weight-pass terms retained. No new cut.

I tried to break it by changing one unused final tail value after all rounds, and
the control in the research public consumer rejected it with ClaimMismatch.
This sentence describes research rejection only, not an implemented NC or approval
to accept either amendment. Publish the Draft requirements and reproducible study;
complete the source/schedule/memory contract before replacing a production scaffold.

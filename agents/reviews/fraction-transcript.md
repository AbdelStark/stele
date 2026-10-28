# Fraction transcript control review (E3-07a)

Reviewer: codex-root, also author. Same-author negative-control-author and
soundness-auditor passes, not independent audit. RFC-0008 A3 / RFC-0012 A9.

Workflow 03 checklist:
- Public items: separate control runners only; no production API changes.
- Challenges: Gamma moves before Fraction or Layer, or Fold moves before Final,
  only in adversarial replay using production Transcript and A1 serialization/prover.
  Exact-order replay must match the actual native proof before tampering.
- Claims: unchanged real public consumers close the original tree/selected-product
  sources and the following sumcheck's fixed original array.
- Bindings: NC-0411 changes exactly one next-layer round value; NC-0802 extends to
  exactly one following final derived after omitting tree/selected-product Final.
  Honest prover failures, acceptance and wrong rejections fail; no toy verifier.
- Ledger: no production challenge, label or numerator changes; both controls are
  mandatory in the real accounting gate. No FS theorem or profile credit.
- Certificates: no new integer identity or dynamic bound.
- Padding/masks: conditional ordinary/weighted trees, actual Boolean selector and
  unused source columns; no full lookup padding/private-consumer admission.
- Determinism/parity: both fields, all three early placements, both omitted-Final
  contexts; exact replay agreement and one-value differences asserted. GPU untouched.
- Cost: no runtime, c_lu, memory or weight-pass claim; primitive ledgers remain due.
- Verifier: unchanged no_std production implementation, no check-disabling flag,
  state import, injected RNG or alternate verifier.
- Glossary: existing transcript, claim, fraction, source and control terminology.

I tried to break it by drawing Gamma/Fold early and omitting tree/selected-product
Final; the unchanged verifiers rejected the one-value replacements with
RoundSumMismatch and FinalEvaluationMismatch. A gate regression rejects removal
of the named continuation test. E3-07a remains in progress with the expanded
shared decision corpus and complete primitive runtime/memory ledgers still due.

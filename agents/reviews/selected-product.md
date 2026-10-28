# Native selected-product review (E3-07a)

Reviewer: codex-root, also author. Same-author soundness-auditor,
GKR-reduction-author and sumcheck-prover-engineer passes, not independent audit.
RFC-0008 A3 / RFC-0012 A9 / RFC-0020 A4 govern this conditional reduction.

Workflow 03 checklist:
- Public items: SelectedProduct and LeafReduction; no full lookup acceptance API.
- Challenges: bind descriptor, source ids, alpha/beta, point and incoming values
  before A1. All A1 finals are absorbed. No new challenge family, RNG or replay.
- Claims: consume p=sigma_tilde(r), final Eq and final sigma exactly. Every original
  column is emitted at the same point, including beta=0 and inactive-selector cases.
- Bindings: NC-0408 extends to Eq under zero products; NC-0409 rejects an unused
  selector final and one unused upstream tree child; NC-0410 rejects an unused
  source final. All use ProverHook, actual prover and unchanged original consumer.
- Ledger: one leaf-phase SC record with tree identity, degree 3 and numerator 3m.
  The Leaf absorb adds no random loss; full lookup/source/PCS/ZK/FS remain separate.
- Certificates: pure field arithmetic, not a waiver of CQIS or characteristic bounds.
- Padding/masks: fixed Boolean selector, true Boolean selected product, no assumption
  that a product of separate MLE evaluations equals the MLE of their product.
- Determinism/parity: full Python/native proof bytes, claims, all record fields and
  continuation; 1000 seeded full-field cases per field, including scalar/beta=0 cases.
- Cost: dense Eq/selector/source copies and original public consumption; checked
  allocations and linear equality construction. No c_lu, fitted constant, peak
  memory or weight-pass claim; complete primitive ledgers remain required.
- Verifier: no_std, immutable borrowed context, all proof/source dimensions checked
  before absorption; malformed ids, points, non-Boolean selectors and shapes reject.
- Glossary: existing selector, source, fraction, claim and reduction terms.

I tried to break it by changing unused equality/selector/source finals and an
upstream unused child; the actual NC-0408..0410 controls rejected them at their
stated boundaries. A consumer-bypass gate regression must fail with TamperAccepted.
E3-07a remains in progress: transcript attack controls, expanded decisions and
primitive runtime/memory ledgers remain due. E3-07 private/full lookup is still blocked.

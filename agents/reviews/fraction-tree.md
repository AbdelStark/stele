# Native conditional fraction tree review (E3-07a)

Reviewer: codex-root, also author. Same-author soundness-auditor, GKR-reduction-author
and sumcheck-prover-engineer passes; not independent audit. RFC-0008 A3 / RFC-0012
A9 / RFC-0020 A4 govern this partial delivery. E3-07a remains in progress.

Workflow 03 checklist:
- Public items: conditional tree prover/verifier, original public consumer, scoped
  accounting and nonzero-denominator root equation. No lookup acceptance API.
- Challenges: descriptor/roots and current layer claims precede Gamma; all A1
  finals and exact Eq consumption precede Fold. Only production Transcript draws.
  The strategy observer records A1's actual folds without extra draws or replay.
- Claims: both original ids survive at one derived point, including unused values.
  The public adapter evaluates original arrays, never retained internal levels.
- Bindings: actual prover, one ProverHook value and unchanged consumer for
  NC-0406 root, NC-0407 unused child, NC-0408 Eq under zero products, both fields.
- Ledger: per-tree Gamma=m, Fold=m, A1 levels k have degree 3 and numerator 3k.
  Python/native corpus checks all records, proof bytes, claims and continuation.
- Certificates: field identities only; no CQIS/count-bound or profile admission.
- Padding/masks: generic pair arithmetic permits zero denominators; rational
  root checking rejects them. Selected-product/padding consumers remain required.
- Determinism/parity: both-field Python proofs and 1000 seeded full-field native
  cases per field, including zero unit coordinates/denominators and m=0. GPU untouched.
- Cost: 2N-1 retained pairs, separate borrowed source and five A1 input copies;
  linear equality construction, bounded proof/record state. No measured constant,
  c_lu or weight-pass claim. Full primitive and process-memory ledgers remain due.
- Verifier: no_std; validate complete shape before absorption; checked allocations.
  Original-array shape is checked before equality-table materialization.
- Glossary: existing tree, fraction, claim, source, reduction and consumer terms.

I tried to break it by changing a root, an unused child and an unused equality
final; fraction::rejects_fraction_tree_binding_tampers rejected each at its stated
boundary. Shared continuation detects absorb-order drift. Full challenge-order
controls, selected-product engine/NC-0409..0410, expanded decision corpus and
primitive ledgers remain E3-07a requirements; private lookup/PCS/ZK remain E3-07.

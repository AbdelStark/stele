# Q20 stacked ownership review

Reviewer: codex-root, also the author; rfc-author, gkr-reduction-author and
soundness-auditor. Not an independent audit. Decision: publish the candidate
ownership contract and research checks; keep A4 Draft and E3-06 blocked.

- Public items/RFC: only research functions and a Draft note addressing A4's
  elimination order, partial ownership and coordinate restoration. No core import.
- Challenges/absorbs: research points come from a fixed test seed. No production
  draw, label or absorb exists here; exact statement bytes/order remain required.
- Claims/consumers: every modeled input final equals its original MLE at the
  restored canonical point, including unused inputs. Actual claim consumers and
  source authentication are not implemented or discharged by this study.
- Bindings/controls: no production NC credit. Wrong-layer, source, coordinate and
  chained-final controls still need the real closed-statement verifier.
- Ledger: unchanged. Partitioning a Boolean suffix by fixed ownership preserves
  the complete degree-bounded polynomial; no new random loss is introduced.
  This identity does not prove Fiat-Shamir, composition or a certified profile.
- Certificates: no integer inference identity or dynamic overflow assertion.
- Padding/masks: original input padding is zero; constant terms demonstrate why
  the global summation cannot silently discard padded slots. Any required mask
  must be part of the exact coefficient/polynomial and its real consumer.
- Determinism: canonical bit positions and fixed traversal/order; representative
  ownership never depends on values or the round's non-Boolean evaluation node.
- Parity: direct original-table M31 evaluation checks every partial for both
  orders and the restored finals. Empty/no-input/constants and boundaries are
  included. This is not production QM31/OM31 or CPU/GPU parity.
- Cost model: current input coalescing and explicit partial storage move c_sc/T_misc.
  Logical owner-crossing counts are not network traffic or measured performance.
  No original weight reread, fitted constant or benchmark claim is authorized.
- Verifier: no production or no_std change. The full descriptor, exact error
  contract and authenticated source/consumer integration remain prerequisites.
- Glossary: no new cut, commitment, profile or source-authorization assumption.

I tried to break canonical claim restoration by using the draw-order point for
an original tensor; the direct original MLE differs in seeded layer-last cases.
This is a research mismatch, not rejection by a production verifier.

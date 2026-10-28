# Q20 weighted public-MLE review

Reviewer: codex-root, also the author; rfc-author, gkr-reduction-author and
soundness-auditor. Not an independent audit. Decision: publish the research
algebra and costs; retain RFC-0006 A4 as Draft and E3-06 blocked.

- Public items/RFC: candidate selected-axis evaluator under RFC-0006 A4 and
  formal/public-mle.md §7. Nothing under research is imported into a core crate.
- Challenges/absorbs: none. Research points come from a reproducible test seed;
  this changes neither the production transcript nor its registry.
- Claims/consumers: no emitted receipt or consumed original input claim. A supplied
  source remains synthetic research input; descriptor validation does not open it.
- Bindings/controls: no new production binding or NC credit. Wrong-layer/source/
  final-coordinate controls still require real closed-statement consumers.
- Ledger: no changed challenge/loss line or profile certification; Q12 remains.
- Certificates: exact field algebra only, no integer inference identity or bound.
- Padding/masks: all axis bounds and selectors enter Boolean weights before the
  sum. Shared axes remain inside the mask DP; disjoint axes factor independently.
  The direct-table oracle and separate-MLE counterexample test this distinction.
- Determinism: canonical axis order, deterministic integer indexing and test seed;
  no runtime-dependent accumulation or field operations involving floats.
- Parity: 10,000 seeded direct-table queries per kind per full field. The paths
  share field arithmetic but not coefficient algorithms. This is neither Rust
  differential testing nor CPU/SIMD/CUDA proof parity.
- Cost model: T_misc formulas include descriptor copying, O(m) weighted pairs,
  sparse-domain vectors and k multiplications per exact source entry. No benchmark
  constant, fitted coefficient, extra weight pass or full-process memory bound.
- Verifier: production is unchanged. The candidate reuses exact descriptor checks
  and validates query length and canonical limbs before evaluation. Production
  resource admission, errors and no_std interfaces remain acceptance work.
- Glossary: existing coefficient/axis/claim vocabulary; no authentication waiver.

I tried to break selector composition with non-Boolean full-K queries, shared
mask axes, padding and reversed axis choices; the independent Boolean-table
fold agrees, while multiplying separately extended mask/selector values differs.

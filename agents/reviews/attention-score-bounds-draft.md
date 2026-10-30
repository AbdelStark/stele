# Attention score bounds — same-author skill review

Scope: Draft RFC-0004 A3/A6 and RFC-0009 A2. Codex-root applies cqis-numerics,
rfc-author and soundness-auditor; not independent audit. Evidence:
[score study](../../research/cqis-bounds/ATTENTION-SCORE.md).

- Public items: static per-pair score record and per-layer templates under the
  Draft score formula. Accepted RFC-0022 and production APIs are unchanged.
- Challenges/absorbs: none; no FS order, degree, random challenge or loss change.
- Claims/consumers: no proof claims. Conditional source dot, scale products,
  nearest division and signed output are numerically composed with raw sums,
  block aggregation and normalization. Actual source/rotary/head/GQA/position,
  range, mask, maximum and function consumers remain required.
- Bindings/controls: DotRelation catches changed expected code/dot; SourceDigits
  catches changed actual dynamic scale; SignRelation catches sign/magnitude/gap.
  IntegerRelation catches output/product/division aliases even after complete
  local-column rebuilding. Certificate, Encoding, Range, Boundary and Relation
  catch metadata/serialization/range/carry mutations. No inference NC credit.
- Ledger: no lines change; required accounting gate must preserve coverage.
- Static bounds: every cap derives from configured widths, code/scale policies
  and units. Unsafe static score bounds reject even on zero actual data.
  Dot/sign fit M31 directly; wide scalar and signed-output equality use digits.
- Padding/masks: exact expected code width, no head/position tail allocation.
  Every supplied score is checked, including masked positions in model replay;
  actual source membership and masks remain unauthenticated obligations.
- Determinism: fixed roles, little-endian framing, nearest ties away, canonical
  dot-zero sign and ordinary integer zero when a negative dot rounds to zero.
- Parity: independent Fraction/NumPy and digit-convolution corpus plus model
  and checkpoint checks. Shared generic numerical primitives are disclosed;
  no native or GPU score parity claim, no fidelity or inference admission.
- Costs: O(W) source dot plus fixed column work; fixed per-layer records, no
  measured constant, benchmark claim, cut or additional weight pass. T_attn/c_x
  remains the relevant eventual production term.
- Verifier: production no_std untouched. Expected input/whole range/digit checks
  are research models, not succinct authenticated consumers or a complete set.
- Glossary/history: append-only Draft evidence and unchanged task criteria.
  All original baseline and block-variant checkpoint fields are preserved.

I tried to break it by replacing -2147385345 with +98302, a legal signed value
that differs by exactly p, and the control IntegerRelation rejected it after
all byte columns were rebuilt. Coherent product and division aliases also
rejected; the direct signed-output field equation would accept the first attack.

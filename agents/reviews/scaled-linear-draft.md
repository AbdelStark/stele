# Scaled-linear bounds — same-author skill review

Scope: Q26 / Draft RFC-0004 A3/A8/A9. Codex-root applies cqis-numerics,
rfc-author and soundness-auditor; not an independent audit. Evidence:
[closed schema study](../../research/cqis-bounds/SCALED-LINEAR.md).

- Public items: research static Spec/records, plaintext witness checker and model
  role compiler. No Accepted RFC-0022 schema is extended.
- Challenges/absorbs: none; no new randomness, FS or challenge order.
- Claims/consumers: no proof claims emitted. Dot/gather, learned mantissa, scale,
  whole ranges, source digits, maximum attainment and rounding need real consumers.
- Bindings/controls: mutations of every record field and role result, including
  coherent rebuilt columns, sign/output, boundary carries and modular aliases.
  No native binding or production NC id is admitted.
- Ledger: no line changes; accounting must remain unchanged.
- Static certificates: shapes, symmetric formats, exponent and unit/row policies
  determine bounds; whole signed sides require 2*Amax<p. Extreme shifts use
  justified zero/overflow branches. No observed-value bound is accepted.
- Padding/masks: no proof padding or new lookup/zerocheck; fixed role lists and
  zero-extended digits explicit. Constant branches retain both products.
- Determinism: exact integers and canonical branch/role/byte order; no host floats.
- Parity: 10000 Fraction/packed-column/NumPy cases and pinned checkpoint replay;
  shared helpers disclosed. Native CPU/SIMD/GPU parity remains required.
- Costs: bounded derivation and explicit limb work; no measured constant,
  benchmark, cut or proof weight pass. Full-model scaling remains open.
- Verifier: production no_std verifier unchanged; this is plaintext research.
  Candidate bytes require regeneration from separately expected metadata.
- Glossary/history: original criteria and Accepted RFC prefixes retained;
  links and glossary covered by repository gates.

I tried to break it by changing the weighted magnitude and rebuilding its local
columns, and the control IntegerRelation rejected it. False nonzero product in
zero_only rejected with ZeroOnly; an unsafe dot dimension rejected with FieldBound
even when all supplied numerical inputs were zero.

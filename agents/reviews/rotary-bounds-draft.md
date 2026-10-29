# Rotary application bounds — same-author skill review

Scope: Q26 / Draft RFC-0004 A3/A6/A7/A9. Codex-root applies cqis-numerics,
rfc-author and soundness-auditor; not independent audit. Evidence:
[rotary schema study](../../research/cqis-bounds/ROTARY.md).

- Public items: research Spec/record, plaintext relation checker and model roles;
  no Accepted RFC-0022 schema or production verifier changes.
- Challenges/absorbs: none; no randomness, degree loss or FS ordering change.
- Claims/consumers: no proof claims emitted. Q/K source ownership, canonical
  coefficient function/table, absolute position and whole ranges need actual
  consumers. The fixed envelope does not establish canonical source identity.
- Bindings/controls: static fields, coherent source/coefficient/layout substitutions,
  position, signed zero, field aliases, rounding and passthrough tampering reject.
  These are research controls without production NC-0106/0109 credit.
- Ledger: no line changes; accounting gate must preserve current coverage.
- Static bounds: fixed int16/Q14 formats and the analytic L1 envelope derive B;
  no coefficient extrema or runtime row values choose a certificate. Every whole
  signed side is below p/2. The extra unit in 23171 is necessary and exercised.
- Padding/masks: no proof padding, lookup or zerocheck added. Every real pair and
  unchanged channel is checked; r=0 retains all passthrough equalities.
- Determinism: exact integers, canonical field order and ordered head/pair roles.
- Parity: Fraction/NumPy, independent bound constants/framing, model roles and
  pinned checkpoint replay; shared helpers disclosed. Rust/GPU parity stays open.
- Costs: fixed derivation, O(h*w) witness/checker data/work; no measured constant,
  benchmark result, cut or weight-pass change. No byte limbs for this domain.
- Verifier: production no_std unchanged; research regeneration is not an
  authenticated plan parser, source consumer or complete certificate-set check.
- Glossary/history: Accepted prefixes and original task criteria preserved;
  links and glossary covered by repository gates.

I tried to break it by supplying the component-bounded pair (16384,16384) on
a zero row, and the control CoefficientEnvelope rejected it. A coherently rebuilt
source/coefficient/layout substitution rejected with Numerator; a modified
unchanged channel rejected with Passthrough. Numerator plus p rejected with Range.

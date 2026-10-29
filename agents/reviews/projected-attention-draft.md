# Projected attention: Draft composition review

Same authoring agent (codex-root), cqis-numerics / rfc-author / soundness-auditor
passes. This is not independent review, protocol acceptance or a model result.

- Public items: research Params/Cached, rotation, prepare/query and static bounds
  investigate RFC-0004 A6, RFC-0009 A2 and RFC-0017's GQA/rotation requirements.
- Challenges/absorbs: none; no transcript or error-budget change.
- Claims/consumers: none admitted. Projection, source scales, rotation/position,
  score conversion, GQA, masks and head assembly all need real proof consumers.
- Bindings/controls: numerical tests reject malformed scope, duplicate positions,
  unsupported score bounds and rotation overflow. A legal position substitution
  is intentionally accepted and changes the maximum: syntax is not source binding.
  No NC-0100/0101/0106/0109 or NC-0500..0506 credit follows. New admitted source
  and view bindings require catalogued one-value controls in the same change.
- Ledger: unchanged; existing accounting gate remains required.
- Static bounds: rotated int16 sources bound restored Q/K; the dyadic product is
  <2^62 and widened shifts <2^123. Static int32 admission applies to all scores.
  Sparse caches require a separate static position span; the old row-count-only
  block bound has an explicit counterexample. No supplied/observed field is trusted.
- Masks/padding: all scores remain well defined before masking. Empty real rows
  reject; padded query exclusion remains a full-forward/proof obligation.
- Determinism: fixed head order, absolute positions, fixed accumulation mode and
  signed ties; full/prefix/evicted-window results match the independent oracle.
  Final output conversion follows all wide heads; its rejection-order test passes.
- Parity: exact Fraction/NumPy numerical corpus only. No Rust/SIMD/GPU forward
  or proof parity, exp-generator independence or model fidelity claim.
- Costs: preparation/query/cache formulas and table/config comparison costs are
  explicit; no benchmark, weight-pass or cut change. c_a/c_x/T_misc need measurement.
- Verifier: unchanged no_std code; research object equality is not authentication.
- Glossary/spec: append-only RFC/agenda additions, same original task criteria;
  repository glossary/link/status checks required. A6/A2 remain Draft.

I tried to break it by duplicating a cached position, changing its configuration
and exceeding the static score bound, and the control rejected it with Positions,
CacheScope and ScoreBound respectively. The legal position substitution remains
accepted until source authentication exists; it is not a claimed proof rejection.

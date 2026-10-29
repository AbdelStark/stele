# Q26 RMSNorm arithmetic-bound research review

Reviewer: codex-root. Same-author cqis-numerics and soundness-auditor passes;
not independent audit. E5-03 retains its blocked status and original criteria.

- RFC/public items: research evidence for RFC-0021 §2.3 under Draft RFC-0004 A3.
  The new Rust example adapts the existing API; core numerical behavior is unchanged.
- Challenges/absorbs: none. Static column and signed-side faithfulness is deterministic.
- Claims/consumers: no cryptographic claim. Source, range, zero/sign, table,
  branch and shared-value consumers must enforce the modeled relations.
- Bindings/controls: no catalog credit. Tests alter certificates, signs, table
  values, bounded exponents, residues and shared facts. Coherent regenerated
  statistic/numerator/mantissa/remainder/product/quotient columns still reject.
- Ledger: no new random challenge, loss, profile or accounting line. The
  standard accounting gate remains required on this exact head.
- Bounds: all derive from d,F,G,E,en,ed. No witness-dependent tightening;
  maximum dimension's statistic includes incoming carries and both sides.
  The actual R<D and output remainder ranges are semantic checks, with
  certificate bounds covering the full exponent/shift domain independently.
- Padding/masks: no proof padding or mask change. Exact column roles/lengths,
  validated digit comparisons, canonical unused fields in the negative-shift branch.
- Determinism: fixed seed; exact integer/rational arithmetic, independent root
  bisection and packed-polynomial column oracle, pinned NumPy rounding reference.
- Parity: 11,004 full native intermediate/output-row decisions, including
  maximum dimension, zeros, both shift branches and 109 output overflows.
  No GPU code or proof parity claim; native certificate delivery remains open.
- Cost: c_a/c_lu would cover admitted limb/range work. No measured constant,
  benchmark ledger, committed tensor or inference weight-pass change.
- Verifier: unchanged. The allocating Python source/range checker and native
  numerical adapter are not a fallible no_std certificate/proof verifier.
- Glossary: existing certificate, sign, carry, range and column terminology.

I tried to break it by changing the normalization exponent and by regenerating
columns around a false numerator, and the control `rejects_malformed_norm`
rejected it with `IntegerRelation`. Lookup and source authentication remain
conditional obligations here; these local rejections are not NC-0105/0109.

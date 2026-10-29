# Q26 static limb-bound research review

Reviewer: codex-root. Same-author cqis-numerics and soundness-auditor passes;
not independent audit. E5-03 retains its original criteria and blocked status.

- RFC/public items: research-only functions under Draft RFC-0004 A3 and
  RFC-0003 A2; no new native public item or Accepted behavior.
- Challenges/absorbs: none. Integer column equivalence is deterministic.
- Claims/consumers: no emitted proof claim. Plaintext source/range checks model
  obligations that actual reduction, lookup and PCS consumers must still enforce.
- Bindings/controls: no new catalog edge or NC credit. Local tests reject all
  supplied certificate field changes, digit/carry changes, modulus-preserving
  additions of p, invalid boundary carries and source/decomposition changes.
- Ledger: no random challenge, loss, profile or accounting line changes.
  Standard accounting gate must still pass on this head.
- Bounds: derived solely from the expected static Spec. Both equality sides
  include carries; final carry is explicitly zero. M=257 with digit caps (255,1)
  exposes the missing whole-input range if 511 is admitted, even times zero.
  Arbitrary Specs are not an admitted schema and input values never tighten bounds.
- Padding/masks: no proof padding, lookup or zerocheck changes. Result columns
  and both boundary carries have exact lengths; extra fields/types reject.
- Determinism: fixed seed/order, exact integer arithmetic, explicit radix,
  independent packed-polynomial static oracle and pinned NumPy digit convolution.
- Parity: 10,000 static configurations and 10,000 actual input cases, plus
  supported endpoint/zero rows and wide maxima. No CPU/SIMD/CUDA proof claim;
  no GPU code touched and native certificate parity remains required.
- Cost: c_a/c_lu would account for admitted limb/range work; no measured constant,
  ledger entry, cut or weight-pass change in this research-only patch.
- Verifier: unchanged; this allocating Python checker is not a no_std verifier.
  Fallible native code, authenticated plan lengths and closed schemas remain open.
- Glossary: existing limb, carry, certificate and range terminology retained.

I tried to break it by adding p to one carry and by admitting 511 under a static
257 bound, and the control `rejects_malformed_limb_relations` rejected it with
`Range` and `InputRange`, respectively. These are local research rejections, not
production NC-0109. The lemma is suitable evidence for continuing Q26; full
certificate/quantiser acceptance, inference and private proving remain unfinished.

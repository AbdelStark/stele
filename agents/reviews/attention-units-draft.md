# Attention units: Draft numerical study review

Same authoring agent (codex-root), using cqis-numerics, rfc-author and
soundness-auditor skills; not an independent audit or protocol acceptance.

- Public items: research Config/Cache, preparation, row evaluation and bounds
  investigate RFC-0004 A6 / RFC-0009 A2. No native item implements Draft behavior.
- Challenges/absorbs: none; no transcript path or error term changes.
- Claims/consumers: none admitted. Value/scale, max/mask, exp, divisor, signed
  quotient/remainder and output conversions all need actual proof consumers.
- Bindings/controls: research mutations diagnose lost scales/shifts, compacted
  blocks and wrong units. The legal scale substitution intentionally succeeds,
  demonstrating why syntax is not authentication. NC-0100/0101/0109 and
  NC-0500..0506 remain unimplemented by this study; new source binding requires
  a catalogued control in its admitting change.
- Ledger: unchanged; accounting gate checks the existing registry and lines.
- Bounds: static shape/parameter formulas; exhaustive static-scale bound check.
  No RFC-0022 record or field-faithful reduction is inferred from Python width.
- Masks/padding: masked keys give zero; a real all-masked row rejects. This row
  API does not admit padded query rows; full forward must enforce their zeros.
- Determinism: explicit index order, lowest maximum, fixed absolute blocks;
  no timing-dependent mode or reduction ordering. Memoization affects no result.
- Parity: 10,000 independent exact/NumPy decisions, 24 block-boundary cases and
  16 prefix comparisons;
  no native/SIMD/CUDA attention digest or full-forward parity credit.
- Costs: c_a/c_x/T_misc gain scale/restored-unit work when implemented; no
  measured constant or benchmark claim. No weight-pass or cut change.
- Verifier: unchanged no_std code; this bounded research API is not a verifier.
- Glossary: repository lint applies; Accepted RFC bodies remain byte-identical.

I tried to break it by changing cached units, using a nonzero code at zero scale,
and selecting an insufficient block shift, and the control rejected it with
CacheScope, ZeroScale and BlockBound respectively. The accepted legal scale
substitution still needs source authentication; it is not a claimed rejection.

Disposition: retain both amendments as Draft. Complete score/RoPE/head/config
semantics, native implementation, full schemas/consumers and fidelity are required.

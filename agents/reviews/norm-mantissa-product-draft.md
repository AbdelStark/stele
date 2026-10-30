# RMSNorm mantissa product — same-author review

Codex-root applies cqis-numerics, gkr-reduction-author, rfc-author and
soundness-auditor. This is not independent audit. [Evidence](../../research/cqis-bounds/NORM-MANTISSA-PRODUCT.md).

- Public items: RFC-0021 §2.3 / RFC-0022 §2.3 mantissa interval and closed
  normal_product role, under Draft RFC-0004 A3. This bounded role permits D=0;
  configured positive D and the normalized interval require actual composition.
- Challenges: parent draws none. Verified range/product roots and states
  precede the inherited polynomial rho and three A1s, with all instance/round/
  final frames retained. Complete norm bytes, five roots and two verified
  states seed the final parent transcript; no outside challenge or retry.
- Claims: actual offset bytes are fully ranged before affine M derivation and
  independent M-root binding. Actual right planes reconstruct the full D16
  root; left planes equal verified M bytes. Both original/product power claims,
  whole-input/packing, output/carry and zero boundary consumers remain complete.
- Bindings: all source/root/field controls passed. A genuine bare product
  accepts M=16383 or changed M at D=0, but the actual parent source join rejects.
  Wrapped offset slack fails its terminal consumer; MD+p fails the real product.
  Actual configured-divisor-to-product composition passed and rejects substitution.
- Ledger: A3 total9b+18g+38, four lookup dimensions2,b+2,g+3,g+3, separate
  product identity C-1 and A1 reduction4b. Nonlookup draws16+4b+8g ZeroWeight,
  17+6b+8g Sumcheck. All20 main/intermediate-width proofs passed with exact
  accounts/draws. Accounting gate remains pending; no production profile certified.
- Bounds: actual offset<=49151 gives16384<=M<=65535 with static2*65535<p.
  Its canonical field output is checked before encoding; this guard supplements
  the actual range, not its proof. Product whole D bound is exactly Dmax;
  integer MD follows only after actual range/carry/product acceptance.
- Padding: every full16-slot D root survives reconstruction from4/8/16 planes.
  All8/16/32 MD output slots and zero boundary carries remain. No prefix-only
  comparison or truncating field lift replaces those source bindings.
- Determinism: complete canonical norm bytes, fixed plane/role/invocation order,
  exact integer arithmetic and independent NumPy products/byte convolutions.
  The canonical-output guard changes no valid source value or transcript state.
- Parity: native CPU/SIMD/CUDA unchanged. Main full field/repetition cases and
  actual140-bit maximum products passed; this remains revealing research.
- Costs: O(B) affine/source views plus every c_a/c_sc/c_lu/T_misc inherited
  consumer. No measured constant, benchmark claim or extra weight pass.
- Verifier: native no_std unchanged. Expected schema/namespace precede bounded
  payloads. Focused malformed affine inputs now reject before root encoding;
  actual range-first verification remains. Producer helpers confer no acceptance.
- Glossary/history: append-only Draft/accounting evidence and original blocked
  acceptance criteria. No new Accepted role, public-MLE kind, native NC or cut.

I tried to break it by using a genuinely valid subminimum-mantissa product at
D=0 with unchanged MD=0, and the control Product:SourceJoin rejected it.

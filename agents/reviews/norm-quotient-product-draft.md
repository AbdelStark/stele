# Quotient-product review

Codex-root applies cqis-numerics, gkr-reduction-author, rfc-author and
soundness-auditor. This is a same-author review, not independent audit.
[Scope and evidence](../../research/cqis-bounds/NORM-QUOTIENT-PRODUCT.md).

- Public items: Draft RFC-0004 A3 research for RFC-0022 §§2.1,2.3,5's
  quotient_product role. No Accepted role, cut or profile change.
- Challenges: full expected norm bytes, three external roots, every auxiliary
  root and every verified range state precede parent weights/rounds/finals.
  Exact divisor/output reconstruction adds no challenge. Dynamic proof families
  depend only on static certificate caps; their ids remain reserved when absent.
- Claims: all seven original derived views have independent consumers at
  emitted points. A divisor view hidden by zero quotient and an algebraically
  preserving carry-final pair both rejected at their original consumers.
- Bindings: actual source mutations, fresh false low/high products, field
  aliases and changed carry families rejected. Independently valid halves
  encoding Zmax+1 rejected at the product relation; their ranges alone do not
  prove the whole-result bound. A valid substituted divisor also rejected its
  expected root when a zero quotient preserved the output.
- Ledger: let X=1+bd+bl+h*bh+sum(bg). Total A3 numerator is
  (21+9h+9g)*a+7X+18g+3c; each nonlookup count is
  (9+4h+4g)*a+3X+8g+c. Separate lookup dimensions are a+2, bd+1,
  a+bl+1, optional a+bh+1, and a+bg+3 per active carry family. Initial honest
  proofs, the full16-proof matrix and all four P8 proofs passed exact receipts;
  both matrix hashes are frozen. The maximum and accounting gate remain
  pending; no native profile is certified by these formulas.
- Bounds: expected closed quotient_product caps only. Actual whole q<=32768
  and offset B-1<=Bmax-1 give positive bounded B. Split result ranges supply
  canonical digit caps; faithful columns and zero endpoints then imply qd=qB
  and its whole bound. Maximum side98047 is below p/2. No observed maxima.
- Padding: padded q/result rows and every carry endpoint/unused plane remain
  zero. Fresh false-cap proofs rejected padded carries, the terminal carry,
  unused high carry and offset overflow. Root controls rejected padded sources.
  Output bytes beyond the parent column domain are exact public zeros derived
  from range widths/caps. Unexpected proof families rejected at shape checking.
- Determinism: fixed reserved role ids, ordered active ranges and canonical
  function bytes. The10000-case corpus passed with frozen hash. Dict order in
  supplied auxiliary roots cannot alter verification order. No challenge retry.
- Parity: native CPU/SIMD/CUDA unchanged. NumPy byte convolution and wide exact
  products are research differential evidence. Actual signed-Y magnitude and
  fully verified factor bytes composed; the factor's B slice is taken only
  after verifying its complete64-slot source. Complete normalization remains
  separate from this factor/product composition.
- Costs: O(NP), P<=16, producer/views plus complete inherited range/hash and
  independent MLE consumers in c_a/c_sc/c_lu/T_misc. Each range stays within
  131072 bytes; the external result root has262144 canonical-u32 slots at full
  N. No per-row proof loop, benchmark, fitted constant or extra weight pass.
- Verifier: native no_std unchanged. Trusted metadata/capacity precedes
  payload access; exact proof keys, root counts, range lengths and canonical
  parent fields are checked. Verification reconstructs scalar B from actual
  bytes and derives views; it never recomputes whole q*B to grant acceptance.
- Glossary/history: append-only Draft/accounting evidence. Selected branches,
  bias/division equality, strict remainder, signed output and full native/model/
  private inference remain open. CI integration and repository gates pending.

I tried to break it by encoding Zmax+1 with independently valid low/high
range proofs, and the control ProductColumns:RoundSumMismatch rejected it
at the actual multiplication consumer.

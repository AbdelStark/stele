# RMSNorm output factors — same-author review

Codex-root applies cqis-numerics, gkr-reduction-author, rfc-author and
soundness-auditor. This is not independent audit. [Evidence](../../research/cqis-bounds/NORM-OUTPUT-FACTORS.md).

- Public items: RFC-0021 §2.3 wide output shift and RFC-0022 §2.3 static
  factors, under Draft RFC-0004 A3. Final signed output remains additional.
- Challenges: complete expected norm bytes, five roots and the fully verified
  paired A/D state precede the parent A3. All inherited source/range/selection/
  product challenge and final framing remain. Parent draws12 weights/rounds;
  no supplied shift/table, outside challenge or retry.
- Claims: parent reads the same actual64 indicator words from the verified
  child. Its three claims consume the actual indicator/factor/public views at
  the emitted points. No extra indicator or unconsumed public value is accepted.
- Bindings: changed flags, all factor regions, high padding and B+p proofs
  fail the actual relation. A genuine proof against a one-cell-corrupted public
  grid satisfies every Boolean equation but fails its actual public consumer.
  Composition-preserving altered finals reject. A valid different exponent
  proof with identical N,A,D at N=0 fails the pinned offset root. All controls
  passed without verifier or expected-reason repair.
- Ledger: added A3 numerator36, total199+9b+18g; selection6, product C-1
  and A1 loss4b remain separate. Four inherited lookup identities/reductions
  stay. Full nonlookup draws75+4b+8g and82+6b+8g; exact assertions run in
  the proof matrix. Full matrix/public checks and accounting gate pending.
- Bounds: complete expected parameters derive e in[-16,90]. Unique valid
  indicator and equality to public bytes force both branch flags and B/h/L,
  with static2^90/2^89/2^16 bounds. No whole-factor M31 equality substitutes.
- Padding: all64 factor slots,31 invalid indicator indices and all inherited
  N/A/D slots remain. Inactive branch factors are fully bound, not skipped.
- Determinism: fixed plane/index/child order and canonical norm bytes. Exact
  integer generation and10000 NumPy product cases passed; no floating point.
- Parity: native CPU/SIMD/CUDA unchanged. Revealing full fields/repetitions
  and10000 public points per field remain running; no native/private admission.
- Costs: one fixed4096-cell A3 plus one complete paired consumer and public/
  source views in c_a/c_sc/c_lu/T_misc. No measured constant, benchmark or
  extra weight pass. A whole-norm composer can use this paired child once.
- Verifier: native no_std unchanged. Expected metadata precedes bounded shapes;
  canonical fields/roots/finals checked. Producer factors never grant acceptance.
- Glossary/history: append-only Draft/accounting evidence; original blocked
  criteria remain. No Accepted role, native NC, public-MLE kind or cut credit.

I tried to break it by proving changed factor bytes against a one-cell-corrupted
public grid satisfying every Boolean relation, and the control
Factors:ClaimMismatch rejected it at the actual public-value consumer.

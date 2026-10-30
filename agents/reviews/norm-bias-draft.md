# Biased-sum review

Codex-root applies cqis-numerics, gkr-reduction-author, rfc-author and
soundness-auditor. This is a same-author review, not independent audit.
[Scope and evidence](../../research/cqis-bounds/NORM-BIAS.md).

- Public items: Draft RFC-0004 A3 research for RFC-0022 §§2.1,2.3,5's bias
  role. No Accepted role, cut or profile change.
- Challenges: complete expected norm bytes, three external roots, every
  auxiliary root and verified range state precede parent weights/rounds/finals.
  Scalar reconstruction and the expected row mask add no challenge. Active
  ranges come only from static caps, with fixed reserved ids.
- Claims: all five original views have independent consumers at the emitted
  points. A preserving t+1/h-1 final substitution rejected at ClaimMismatch.
- Bindings: actual source mutations rejected at their root checks. Fresh
  false low/high sums, U+p and changed carry families rejected at the sum
  relation. Independently valid halves representing Zmax+1 also rejected
  there; the half ranges alone do not establish the whole output bound.
- Ledger: with X=3+bh+bl+H*bu, A3 numerator is
  (20+9H+9g)*a+7X+18g+2c and each nonlookup count is
  (9+4H+4g)*a+3X+8g+c. Lookup dimensions are a+4, bh+1, a+bl+1,
  optional a+bu+1 and g copies of a+3, each retaining its separate identity
  and reduction. Initial honest proofs passed exact receipts. The complete
  matrix, maximum and accounting gate remain pending.
- Bounds: whole t<=2^44 and h<=hmax are consumed. The expected closed bias
  certificate supplies Boolean carry caps and sides<=511<p/2. Faithful
  addition then establishes the whole U bound. No observed maxima are used.
- Padding: only the expected real-row count masks scalar h. Padded t/U/carry
  values and terminal/unused carries remain zero. Ragged nonzero-bias proofs
  passed. Padded source mutations, false-cap padded/terminal carries, bias
  overflow and changed high extensions rejected at their stated consumers.
  No supplied mask or certificate is accepted.
- Determinism: fixed role ids and canonical function bytes; verification
  orders auxiliary roots by expected roles. The10000-case corpus hash is
  frozen. No challenge retry or data-dependent role selection.
- Parity: native CPU/SIMD/CUDA unchanged. NumPy byte addition and exact wide
  sums supply research differential evidence. The actual product source and
  a complete verified factor source composed; h came from its actual
  slice18:34. A valid substituted h rejected the pinned factor root.
  Complete normalized-interval composition remains separate.
- Costs: O(NP), P<=16, producer/views plus complete range/hash and independent
  MLE consumers in c_a/c_sc/c_lu/T_misc. Each range stays within131072 bytes.
  The maximum output root has262144 canonical-u32 slots. No benchmark,
  fitted constant, per-row proof loop or extra weight pass is claimed.
- Verifier: native no_std unchanged. Trusted metadata determines lengths
  before payload access; exact proof families, roots, round/final shapes and
  canonical parent fields are checked. Verification derives byte views and
  never recomputes whole t+h to grant acceptance.
- Glossary/history: append-only Draft/accounting evidence. Division equality,
  strict remainder, configured branches, signed output and native/model/private
  inference remain open. CI integration and repository gates are pending.

I tried to break it by encoding Zmax+1 with independently valid low/high
range proofs, and the control SumColumns:RoundSumMismatch rejected it
at the actual addition consumer.

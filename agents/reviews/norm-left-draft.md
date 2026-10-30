# Left-factor review

Codex-root applies cqis-numerics, gkr-reduction-author, rfc-author and
soundness-auditor. This is a same-author review, not independent audit.
[Scope and evidence](../../research/cqis-bounds/NORM-LEFT.md).

- Public items: Draft RFC-0004 A3 research for RFC-0022 §§2.1,2.3,5's
  left role. No Accepted role, cut or profile change.
- Challenges: complete expected norm bytes, three external roots, every
  auxiliary root and every verified range state precede parent weights/
  rounds/finals. Actual positive-factor reconstruction adds no challenge.
  Active families derive only from static caps and retain reserved ids.
- Claims: all nine original views have independent consumers at their
  emitted points. Each factor-byte final was changed separately at zero
  product; every change rejected at ClaimMismatch. A preserving Cin/q
  final substitution also rejected at its original consumer.
- Bindings: actual source mutations rejected at root checks. Fresh false q,
  product+p and carry changes rejected at multiplication. At L65536, a
  supplied t=2^44 with q=0 rejected even though both source ranges were
  valid. A valid factor substitution at t=q=0 rejected its expected root.
- Ledger: total A3 numerator is(21+9g)*a+37+7bl+18g+7*sum(bg);
  nonlookup draws per label are(9+4g)*a+15+3bl+8g+3*sum(bg).
  Lookup dimensions are a+4, a+2, bl+1 and a+bg+3 per active family;
  each keeps its separate identity and reduction. Initial honest proofs
  passed exact receipts, including no carries and one/two-byte carries.
  The complete matrix, both full-row proofs and accounting gate remain pending.
- Bounds: whole t<=2^44, q<=32768 and offset L-1<=Lmax-1 are consumed.
  Closed left-role caps give maximum side130815<p/2. Whole positive L
  and zero carry endpoints justify integer lifting. All17 static Lmax
  transitions passed geometry and carry checks; no observed bound is used.
- Padding: padded t/q/carries and closed terminal/unused carries stay zero.
  The q view includes all six high zero-byte planes. False-cap padded and
  terminal carries, padded sources, q overflow and high factor extensions
  rejected. Offset overflows changing byte width rejected at OpeningShape.
  The dimension-zero offset-cap control rejected at FinalEvaluationMismatch;
  its initial expected round-check label was corrected without changing
  verifier code. The boundary suite then passed.
- Determinism: fixed role ids and canonical function bytes; verification
  uses expected auxiliary-root order. The10000-case NumPy corpus is frozen.
  No challenge retry or witness-dependent family selection.
- Parity: native CPU/SIMD/CUDA unchanged. NumPy int64 multiplication and
  independent byte convolution include products beyond the output range;
  complete proof controls reject false bounded q. Actual reciprocal-product,
  signed-Y magnitude and one fully verified factor bundle composed on the
  same roots. L came from its actual eight-byte slice34:42. Complete
  normalized-interval and model ownership remain separate obligations.
- Costs: O(8N) producer/views plus complete range/hash and independent MLE
  consumers in c_a/c_sc/c_lu/T_misc. Each range fits131072 bytes and lookup
  dimension18. No benchmark, fitted constant, per-row proof loop or extra
  weight pass is claimed.
- Verifier: native no_std unchanged. Trusted metadata determines capacity
  before payload access. Exact proof families, roots, range lengths and
  canonical parent fields are checked. Acceptance consumes byte columns;
  it never computes whole t*L to authorize q.
- Glossary/history: append-only Draft/accounting evidence. Selected e<0,
  unused qd/r zeros, the right branch, signed output, native/model/private
  inference and original task criteria remain open. Gates and CI are pending.

I tried to break it by changing a factor-byte final while t=q=0 preserved
the product, and the control LeftColumns:ClaimMismatch rejected it at
the original factor consumer.

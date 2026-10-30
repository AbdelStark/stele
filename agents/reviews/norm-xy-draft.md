# RMSNorm magnitude product — same-author review

Codex-root applies cqis-numerics, gkr-reduction-author, rfc-author and
soundness-auditor. This is not independent audit. [Evidence](../../research/cqis-bounds/NORM-XY.md).

- Public items: RFC-0021 §2.3 and RFC-0022 §2.3 closed xy role, under Draft
  RFC-0004 A3. Canonical product sign, xy*J and output branches remain separate.
- Challenges: expected norm function bytes, six roots and four verified child
  states precede the parent weights/rounds/finals. All signed/range/lookup
  framing remains. Only inherited Transcript labels are used; no retry.
- Claims: actual verified magnitude, output and carry arrays construct all
  seven parent views, consumed at their emitted points. Originals are retained
  under zero factors. Source signs remain fully verified by signed children.
- Bindings: stale raw/magnitude/output/carry and fresh changed bounded output/
  carry controls passed. A loose-cap proof rejected at SourceCopy:ClaimMismatch
  because cap metadata changes the range transcript. The focused control now
  keeps expected metadata and supplies false-cap witness bytes, exercising the
  actual cap relation directly; both strict carry and output alias reject at
  CapRelation:RoundSumMismatch. All controls and same-X statistic composition
  passed. Separate real terminal, padded carry and padded output controls each
  rejected at their actual cap consumers.
- Ledger: total A3 numerator107a+108; six lookup dimensions a+2 and two a+3
  retain separate identities/reductions. Full nonlookup draws45a+44 of each
  label; seven parent claims. Exact runtime account assertions are running.
- Bounds: only the closed expected xy role derives carry caps(0,254,255,64,0).
  Full signed magnitudes<=32768 and xy<=2^30 imply high-byte caps. Both column
  sides<=65535,2*65535<p. Exact terminal zero is enforced by the carry range.
- Padding: signed and xy ranges force padded rows zero; explicit carry caps
  are zero there. Every byte column and original remains, including padding.
  Range lookups retain the complete canonical byte table and zero extension.
- Determinism: fixed role, child, column and row order; full norm bytes and
  exact integer arithmetic.10000 NumPy cases passed with a frozen digest.
- Parity: native CPU/SIMD/CUDA unchanged. Revealing field/repetition and full
  capacity matrices remain running; no native/private inference admission.
- Costs: O(N) witness/views/folded A3 producer plus complete inherited ranges
  and full-opening consumers in c_a/c_lu/c_sc/T_misc. No measured constant,
  benchmark, scalar proof loop per element or extra model weight pass.
- Verifier: native no_std unchanged. Expected schema bounds every dimension;
  full field/root/shape validation precedes use. Producers confer no authority.
  Internal ids and views occupy disjoint offsets in the reserved parent span.
- Glossary/history: append-only Draft/accounting evidence. Original blocked
  criteria and full16384 domain remain; no capacity, Accepted role or cut change.

I tried to break it by substituting a different bounded output product,
and the control ProductColumns:RoundSumMismatch rejected it.

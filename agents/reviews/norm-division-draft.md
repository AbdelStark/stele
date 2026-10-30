# Output-division review

Codex-root applies cqis-numerics, gkr-reduction-author, rfc-author and
soundness-auditor. This is a same-author review, not independent audit.
[Scope and evidence](../../research/cqis-bounds/NORM-DIVISION.md).

- Public items: Draft RFC-0004 A3 research for RFC-0022 §§2.1,2.3,5's
  output equality and strict remainder. No Accepted cut or profile change.
- Challenges: complete expected metadata, seven external roots, every range
  root and every verified child state precede parent weights/rounds/finals.
  Both complete child verifiers run; no supplied receipt is accepted. The
  expected row mask and reconstruction of actual B add no challenge.
- Claims: all ten parent original views are consumed independently at their
  emitted points. Preserving qd/U and r/gap final substitutions rejected
  at their original claims. All inherited consumers remain mandatory.
- Bindings: fresh false equality, carry changes and source mutations rejected.
  A valid biased-sum child and remainder range encoding r=B preserved
  equality but rejected at StrictRemainder. A freshly assembled false
  quotient-product child rejected inside its multiplication consumer before
  parent equality. An r+p/gap-p forgery preserved strict remainder but
  rejected at Equality. No field-residue equality substitutes for digits.
- Ledger: inherit both complete child accounts. New A3 numerator is
  (22+18H+9g)*a+14*(bl+H*bh)+18g+16; each new nonlookup count is
  (10+8H+4g)*a+6*(bl+H*bh)+8g+8. Each remainder/gap half and carry family
  retains its separate lookup identity and reduction. The proof matrix,
  maximum and accounting gate remain pending; initial honest proofs passed
  exact counts, and the complete matrix remains required.
- Bounds: exact whole r/gap<=Bmax-1 follows from the power-of-two-minus-one
  split caps. All75 shift transitions passed. Equality carry caps derive
  from the expected closed division role; strict carry caps start at one
  and propagate only static byte maxima. Actual bytes<=255 and Boolean
  carries bound both sides by511<p/2. This local certificate does not
  assert unconsumed tighter last-digit caps. Equality itself derives U's
  whole bound from the actual bounded qd and r.
- Padding: expected real rows mask B and the strict initial one. Source,
  result and carry padding remain zero. Fresh false-cap proofs rejected
  padded carries and both terminal carries; padded range sources and changed
  high remainder roots rejected. All16 columns retain high zero obligations.
- Determinism: fixed child identities and reserved range roles; expected
  order controls root/state absorption. Static caps alone choose active
  families. The10000-case NumPy corpus has a frozen hash. No challenge retry.
- Parity: native CPU/SIMD/CUDA unchanged. NumPy byte addition and exact wide
  division provide independent research witness checks. The actual B/h
  composition test verifies one complete factor bundle before using either
  slice; it passed, including zero-quotient divisor substitution rejection.
  Normalized-interval and physical model
  ownership remain separate obligations.
- Costs: O(16N) producer/views plus both complete children and new ranges,
  hash and independent MLE consumers in c_a/c_sc/c_lu/T_misc. Every range
  stays within131072 bytes and lookup dimension18. No benchmark, fitted
  constant, per-row proof loop or additional weight pass is claimed.
- Verifier: native no_std unchanged. Validated expected metadata determines
  capacity and ids before payload access. Exact keys, roots, range lengths
  and canonical parent fields are checked. Whole division is used only by
  the witness/test oracle; acceptance uses complete children and byte proofs.
- Glossary/history: append-only Draft/accounting evidence. Configured
  branches, left shift, signed output, native/model/private inference and
  original task criteria remain open. Gates and CI integration are pending.

I tried to break it by setting r=B while preserving qd+r=t+h, and the
control StrictRemainder:RoundSumMismatch rejected it at the independent
strict-remainder consumer.

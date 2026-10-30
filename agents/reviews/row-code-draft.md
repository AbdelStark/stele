# Dynamic row codes — same-author review

Codex-root applies cqis-numerics, gkr-reduction-author, rfc-author and
soundness-auditor. This is not independent audit. [Evidence](../../research/cqis-bounds/ROW-CODE.md).

- Public items: RFC-0004 §5.5 / Draft A3/A8, unchanged RFC-0006 A1/A3 and
  range_8. Actual scale and signed output with bounded division/zero relations;
  no native reduction, physical packed root, production cut or private proof.
- Challenges/absorbs: ten roots and nine fully verified child states precede
  seven parent A3 invocations. All Finals are absorbed, including scalar flags.
  Zero dimensions retain Instance/Final/records; no new label, retry or inverse.
- Claims/consumers: all22 finals use actual source/view values at their emitted
  points. Output magnitude and quotient bind the same root. Packing, masking,
  broadcasts and carry views derive from verified arrays; no supplied view map.
- Bindings/controls: one-value raw/scale/output/magnitude and auxiliary mutations
  reject. Equation-preserving final changes and inactive factors still reject
  ClaimMismatch. Oversized half-tie remainder, zero-scale free output, wrong sign
  and valid but inconsistent flag/predecessor/quotient children have complete
  controls. Every original production NC requirement remains separate.
  Canonical signed int8 -128 is rejected by the actual quotient cap127 consumer.
- Ledger: retain19 independently repeated lookup identities/reductions. Own A3
  adds12a+3c; total A3 is171a+87b+12c+25 with inherited A1 a separate. Exact
  tests replay every lookup dimension, draw, record and claim count. No reduction
  is squared; binding, FS/H and private composition remain additional.
- Static bounds: closed row metadata derives P=4 and Nrows*P<=4096 before
  payloads. Actual Q<=127 and T=C+3 in[0,258] give sides<=66813; smaller scalar
  bounds also satisfy2*bound<p. Strict remainder gives unique rounding for S>0;
  nonnegative gaps force R=Q=0 at S0. No whole gated-word alias assumption.
- Padding/masks: actual input/output/range consumers force original padding0.
  Scale/nonzero views are masked on padding. Carry padding is3, forced by masked
  columns and public T0=TP=3. All high planes, terminal and scalar claims remain.
- Determinism: fixed child/id/plane order and explicit little-endian context.
  Integer corpus and complete field/repetition proofs cover endpoints, ties,
  zero and negative rounding to zero. All resource dimensions are static.
- Parity: native CPU/SIMD/GPU unchanged. Exact integer corpus and small naive A3
  parity are research evidence; shared engines do not constitute independent audit.
- Costs: O(Nrows*P) witness/views/folded parent producer plus every nested
  range/lookup/hash consumer in c_a/c_sc/c_lu/T_misc. Reference full openings are
  not a measured performance result. No benchmark constant or extra weight pass.
- Verifier: production no_std unchanged. Expected schemas derive first; lengths,
  roots and strict field limbs are checked. Arithmetic assembly helpers cannot
  bypass full verification, even when constructed with false child statements.
- Glossary/history: append-only Draft/accounting evidence; original task status
  and criteria remain blocked/open. No analytic public MLE is added: new views
  use complete authenticated words. Static mode, model-owned routing, native
  stacking and private PCS/ZK remain necessary.

I tried to break it by using Q0/R=2*S at a negative half tie while preserving
every other parent relation, and the control RemainderBound:RoundSumMismatch
rejected it. A nonzero code at scale0 satisfies division/sign but the control
ZeroCode:FinalEvaluationMismatch rejected it.

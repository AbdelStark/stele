# Biased attention numerator review in progress

Codex-root applies cqis-numerics, gkr-reduction-author and soundness-auditor.
This is a same-author review, not an independent audit. The
[scope](../../research/cqis-bounds/ATTENTION-BIASED-NUMERATOR.md) preceded tests
and implementation. Tests first rejected the missing module. Corpus and
proof suites are running; this is not a completed sign-off.

- Public items: Draft RFC-0004 A3/A6 and RFC-0009 A2. Expected normalization
  metadata fixes W=2U+D and all three whole bounds. Both channel tensors and
  the shared scalar retain sixteen external byte planes.
- Challenges: complete child transcripts remain unchanged. Full schema,
  roles, field/repetition bytes, every external/internal root and verified
  child state precede the parent A3. It draws a+4 per ZeroWeight/Sumcheck
  label, with no new label or A1.
- Claims: five actual originals consume U, the real-channel D broadcast,
  carry-in, W and carry-out at the emitted points. Every inherited range,
  lookup and packing original remains mandatory before those views are built.
- Bindings: controls target every root, false input/output/carry values,
  all five compensated originals, wrong D padding, genuine ranged W-p,
  whole caps, endpoints and high planes. Complete scaled-numerator and
  positive-denominator sources must compose and reject valid replacements.
- Ledger: GU+GW+5 independent lookup identities retain repeated identities
  and unsquared reductions. The scope's exact range/A3 and draw formulas
  include parent loss 2(a+4), all scalar work and all three group families.
  Runtime receipts and the repository accounting gate remain under validation.
- Bounds: static Umax/Dmax/Wmax<2^128 precede views. Both sides of each
  integer column are at most 767<p/2; final carry is zero. No observed input
  value sets a bound or authorizes verification.
- Padding: each G=2 half has exactly N/2 caps, explicitly zero on unused
  channels. Source/output joins retain plane-major order and all sixteen
  planes. The shared D view is zero on padded channels. Complete carry ranges
  cap padded and final entries at zero; initial carry is the expected zero.
- Determinism: fixed expected groups, child order, namespaces and byte order.
  No float, retry or witness-selected configuration. Independent integer
  sums, byte roots and column carries remain under validation.
- Parity: native CPU/SIMD/CUDA are unchanged. Capacity checks include 8193
  and 16384 channels. Full proofs must cover GU/GW=1/1,1/2,2/2 at width
  16384, retaining all original consumers and exact accounting.
- Costs: linear byte/broadcast/carry views and complete range/A3 consumers
  contribute to c_a/c_sc/c_lu/T_misc. Every child respects the existing range
  capacity. No benchmark, fitted constant, new cut or weight pass is claimed.
- Verifier: native no_std is unchanged. Expected metadata fixes lengths;
  strict proof keys and canonical field values are checked. The verifier
  consumes byte views and complete proofs, not plaintext whole sums.
- Glossary/history: Draft/accounting additions are append-only. Original
  statuses and criteria stay blocked. Positive source provenance, quotient
  product, strict remainder, signed output, full ownership, native/private
  inference, fidelity and independent review remain required.

The observed-attack conclusion remains pending the controls. All full-width
proofs and required repository gates must also complete.

The primary suite passed. I tried to break it by changing each original final
claim while compensating another to preserve the column equation, and
Bias:ClaimMismatch rejected all five attacks. Complete changed input/output
and carry children rejected at the parent equation. Corpus, boundary/source
composition suites, matrix and full-width proofs remain pending.

Boundary controls subsequently passed, including the genuine ranged W-p
alias and denominator broadcast on padded channels. Both rejected at
Bias:RoundSumMismatch; whole caps, endpoints and external high planes also
retained their consumers. Remaining source proofs, corpus, matrix and
full-width validation are pending.

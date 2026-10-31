# Canonical accumulated block sign review in progress

Codex-root applies cqis-numerics, gkr-reduction-author and soundness-auditor.
This is a same-author review, not an independent audit. The
[scope](../../research/cqis-bounds/ATTENTION-BLOCK-TOTAL-SIGN.md) preceded tests
and implementation. The first run rejected the missing module. All 10000 corpus
cases, controls and both source compositions passed. Matrix and full proof
validation continue. Repository gates will run
once after the preceding block-sum gates. This is not a completed sign-off.

- Public items: Draft RFC-0004 A3/A6 and RFC-0009 A2. Expected schema and
  absolute block ids bind the offset, magnitude and canonical sign roles.
  This stage consumes an actual aggregate root; upstream ownership remains
  a separate obligation.
- Challenges: all complete range transcripts remain. Expected schema, blocks,
  roles, field and repetition metadata, three external roots, four internal
  roots and four verified child states precede parent ZeroWeight challenges.
  Two A3 Instance/Round/Final schedules use existing labels. Dimension zero
  draws no parent challenge and still consumes every original.
- Claims: actual whole U, b, M and Gmask are consumed by the degree-two sign
  relation. Actual M, g and b are consumed by the degree-one canonical-zero
  relation. Repeated M/b identities retain independent emitted points. The
  verifier evaluates each original at the point carried by its claim.
- Bindings: controls target all roots and ranges, bounded false magnitude,
  negative zero, relaxed-cap modulus aliases, metadata replay, every original
  view, malformed fields and proof shapes. Source composition checks complete
  block-sum proofs and valid changed aggregates. Negative raw signs at rounded
  zero remain bound by the upstream proof even when the aggregate is unchanged.
- Ledger: four independently repeated lookup identities and unsquared lookup
  reductions remain. Range/A3 numerator is 41a+7(bo+2bm), including parent 5a.
  Parent draws are 2a per label; full totals are 18a+3(bo+2bm) per label.
  Tests compare all six parent records, seven claim ids and draw counts.
  Initial receipts and draws matched. Repository accounting verification is pending.
- Bounds: metadata determines qmax, G and every range cap. Static
  2*max(4G,G+1)<p makes both equalities faithful, including G=0. Complete
  range verification precedes every whole lift. Relaxed-cap alias witnesses
  deliberately violate those ranges; they are not presented as valid ranged
  integers.
- Padding: all four ranges require zero padding. Gmask is nonzero only on
  real channels. External U/M roots preserve all eight planes independently
  of compact range widths. The sign root retains one full padded plane.
- Determinism: fixed range, root and relation order; unique sorted expected
  block ids; fixed namespace and schema encoding. No floating point or retry.
  The independent corpus digest is frozen; both-field proof validation continues.
- Parity: native CPU/SIMD/CUDA are unchanged. NumPy supplies independent
  differences, signs, whole predecessors and byte roots. The maximum proof
  covers 16384 channels with 1024 block ids as metadata; it does not prove
  the upstream block/channel grid or full model ownership.
- Costs: four complete ranges and two A3s contribute to c_a/c_sc/c_lu/T_misc.
  Whole views require linear work over verified bytes. No measured constant,
  benchmark result, new cut or extra weight pass is claimed.
- Verifier: native no_std is unchanged. Expected metadata fixes lengths,
  exact proof keys and canonical fields are required, and all children are
  verified. The verifier does not recompute abs or sign to accept a proof.
- Glossary/history: Draft and accounting entries are append-only. Original
  task statuses and criteria stay blocked. Global probability aggregation,
  normalization units, source ownership, native/private inference, fidelity,
  GPU work and independent audit remain required.

The first implementation run passed the total account equality but rejected
a test expecting two parent records. A3 emits three records per relation,
including its zero-cost skip record. The assertion now checks all six records
and all seven original ids; verifier behavior did not change.

I tried to break it by setting the sign to one at zero magnitude, and the
control CanonicalZero:RoundSumMismatch rejected it. Dimension zero rejected
the same attack at CanonicalZero:FinalEvaluationMismatch. Every compensated
original-final attack rejected at its ClaimMismatch consumer.

The independent corpus passed 329725 channels and 6660 zero-bound cases.
Both complete block-sum source compositions passed, including valid changed
aggregate rejection and upstream sign binding at rounded zero. Matrix,
full-size proof and repository gates remain pending.

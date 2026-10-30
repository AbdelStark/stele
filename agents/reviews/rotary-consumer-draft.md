# Canonical rotary consumer review in progress

Codex-root applies cqis-numerics, gkr-reduction-author, rfc-author and
soundness-auditor. This is a same-author review, not independent audit.
[Scope](../../research/cqis-bounds/ROTARY-CONSUMER.md). Tests-first rejected
the missing module. All primary/public/original/boundary controls passed.
The corrected10000-case corpus passed. Matrices, maximum and gates remain
under validation;
this is not a completed sign-off.

- Public items: Draft RFC-0004 A3/A6/A7. Expected descriptor and absolute
  position determine the canonical Q14 coefficient row. Both layouts, partial
  rotation and full passthrough retain complete arithmetic consumers.
- Challenges: inherited signed/range transcripts remain. Expected shape,
  units, descriptor, position, eight roots and six verified child states
  precede four parent A3s in fixed order. Existing ZeroWeight and
  Instance/Round/Final schedules retain canonical parent field tuples.
- Claims: all sixteen parent originals retain actual-point consumers,
  including public coefficients, padded constants and values hidden by zero.
  Input/output signed bytes, q and every whole range retain their consumers.
- Bindings: tests-first covers six external/two auxiliary roots, valid source
  and output substitutions, coherent r=16384, canonical negative zero, whole
  bounds, M31 aliases, padding, position/layout/units and all original finals.
  Primary roots, valid source/output replacements and coherent r=16384
  rejected at their named consumers. All original finals, public coefficient
  padding, metadata replays, whole bounds, aliases and signed overflow also
  rejected. Full passthrough retained its actual rounding consumer.
- Ledger: ten separate lookup identities and unsquared reductions remain.
  Parent phase losses total10a; full range/A3 loss132a+105 and nonlookup draw
  totals56a+43 per label are in accounting. Receipt checks and the accounting
  gate require successful execution.
- Bounds: the fixed coefficient envelope23171 gives |N|<=759267328. Complete
  M/g ranges, signed sources and strict remainder put all equation sides below
  p/2. No bound is derived from observed coefficient or input extrema. There
  is no wide field residue or committed numerator substituting for this proof.
- Padding: expected row count masks public coefficients and bias. Paired source
  views use only actual signed inputs; signed/range children retain padded-zero
  obligations. Passthrough uses public(16384,0) and skips no child or original.
- Determinism: exact integer-certified coefficient generation and fixed pairing,
  child and plane order. The immutable cache retains at most16 rows, keyed by
  exact descriptor bytes and validated integer position. Unsupported or unresolved generation rejects.
- Parity: no native CPU/SIMD/CUDA change. Independent Arb coefficient checks,
  NumPy/Fraction row calculations passed10000 cases, including239 expected
  overflows. All92 canonical coefficient rows matched Arb. The first coverage
  assertion exposed a sampling quarter coupled to identity rotation; the
  corrected independent position schedule passed. Both fields/repetitions
  and16384 rows remain under validation. No native/GPU parity is claimed.
- Costs: O(heads*width) views/ranges and four A3s in c_a/c_sc/c_lu; canonical
  generation and full public MLE evaluation remain T_misc reference costs.
  No measured constant, new cut or additional weight pass is claimed.
- Verifier: native no_std unchanged. Strict separately expected metadata,
  roots, proof keys and parent fields. Supplied coefficients, certificates,
  positions or receipts confer no acceptance authority.
- Glossary/history: append-only Draft/accounting evidence. Native generation,
  registry/passport admission, model/private inference, other required variants,
  fidelity and original task criteria remain open. Independent review is required.

I tried to break it by setting r=16384 and reducing q while retaining the exact
whole division and a valid signed output source, and the control
Remainder:CapRelation:RoundSumMismatch rejected it.

# Scaled attention numerator review in progress

Codex-root applies cqis-numerics, gkr-reduction-author and soundness-auditor.
This is a same-author review, not an independent audit. The
[scope](../../research/cqis-bounds/ATTENTION-NUMERATOR.md) preceded tests and
implementation. Tests first rejected the missing module. Corpus and proof
suites are running; this is not a completed sign-off.

- Public items: Draft RFC-0004 A3/A6 and RFC-0009 A2. The full normalization
  schema fixes the magnitude cap and power-of-two shift. Eight source and
  sixteen output byte planes preserve the full configured domain.
- Challenges: complete child transcripts are retained. Expected schema,
  source roles, field/repetition bytes, all external/internal roots and
  verified child states precede the parent A3. It draws a+4 challenges per
  ZeroWeight/Sumcheck label, with no new label or A1.
- Claims: four actual originals consume shifted source, carry-in, output and
  carry-out at the exact emitted points. Complete inherited source, cap,
  lookup and carry claims remain mandatory before constructing these views.
- Bindings: tests attack every root and child, false source/output/carry,
  all four compensated originals, changed metadata, genuine ranged U-p,
  whole caps, padding, endpoints and high planes. Actual raw/block canonical
  magnitude sources must compose, including valid substitute rejection.
- Ledger: 5+G independent lookups retain repeated identities and unsquared
  reductions. Range/A3 numerator is 56a+7(bm+bu)+80 for G=1, or
  65a+7bm+14bu+62 for G=2. Nonlookup draws per label are
  25a+36+3(bm+bu), or 29a+28+3bm+6bu. Runtime receipts and the repository
  accounting gate must confirm the formulas.
- Bounds: static Tmax<2^64 and Tmax<<shift<2^128 precede byte views. Each
  column side is at most 32767<p/2. Complete source bounds force omitted
  high bits to zero, even when shift reaches 92 with a zero static bound.
- Padding: real carries are capped by c-1, padded channels by zero and final
  carries by zero. Complete source/output ranges retain padded zeros. Output
  group joins repack every channel in plane-major order with all sixteen
  external planes. No zero value or bound skips a consumer.
- Determinism: fixed schema-derived groups, range order, namespaces and byte
  order. Integer arithmetic only. Corpus and both-field digests remain under
  validation; there is no challenge retry or witness-selected layout.
- Parity: native CPU/SIMD/CUDA are unchanged. Independent NumPy shifts and
  byte roots check the oracle. Two complete 16384-channel proofs are required,
  one with two output groups and one with identity shift.
- Costs: complete ranges and linear byte/carry views contribute to
  c_a/c_sc/c_lu/T_misc. Fixed groups retain the existing range capacity.
  No measured constant, benchmark, new cut or extra weight pass is claimed.
- Verifier: native no_std is unchanged. Expected metadata determines every
  length, strict proof shape and canonical field value. Actual child/A3
  verification admits the output; plaintext whole multiplication does not.
- Glossary/history: Draft/accounting entries are append-only. Original
  statuses and criteria stay blocked. Signed division/rounding, source
  ownership, global attainment, native/private inference, fidelity and
  independent review remain required.

The observed-attack conclusion remains pending the controls. Required local
repository gates and the full-size proof queue must also complete.

The first control run rejected metadata replay at Shift:ClaimMismatch. The
arithmetic was unchanged, so its linear zero relation remained valid; the
changed transcript point was caught by the actual original consumer. The
test had expected RoundSumMismatch. Only the expected diagnostic changed.
All preceding root, false-value and compensated-original controls passed.
The original failed-run log is retained; the failed suite must complete.

The corrected primary suite passed, including malformed field and authority
controls. I tried to break it by changing each original final claim while
compensating another to preserve the column equation; Shift:ClaimMismatch
rejected all four attacks. Complete changed source/output/carry children also
rejected at the parent equation. Corpus, boundary/composition suites, matrix,
full-width proofs and required repository gates remain pending.

Static review found the ragged G=2 padding error before the corpus reached
its capacity cases. The 8193-channel focused regression rejected at Capacity
because the second child had only one cap. Both half-domains now carry explicit
zero caps and zero values on unused channels. This restores the intended
supported domain and preserves the stated account; no limit is raised.
Existing G=1 proof inputs and fully occupied G=2 layouts are unchanged.
The focused capacity checks and corrected corpus remain under validation.

The focused capacity checks subsequently passed for 8193 and 16384 channels.
All boundary controls and both actual canonical-magnitude source compositions
passed. Valid changed sources rejected at Magnitude:CommitmentMismatch.
Matrix, corrected corpus, full-width proofs and repository gates remain pending.

The corrected 10000-case corpus and both capacity cases passed over 354302
channels, including 3352 zero-bound cases and all shifts 0..92. Its digest
is frozen. The original ragged-capacity failure remains recorded. Matrix,
full-width proofs, repository gates and independent review remain pending.

The original corrected proof runner completed all 16 matrix proofs with exact
receipts, draws and original claims across both fields/repetition counts.
Its observed digest is frozen. Full-width proofs, repository gates and
independent review remain pending; no completed work was restarted.

CI integration passed all 11 inventory/CLI/aggregate tests. Five normal
modes and both full-width group-family proofs are mandatory; inherited jobs
and native steps are preserved. Hosted results and original local gate/full
proof queues remain pending. This does not replace independent review.

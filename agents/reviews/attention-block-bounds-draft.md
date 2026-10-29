# Attention block bounds — same-author skill review

Scope: Draft RFC-0004 A3/A6 and RFC-0009 A2. Codex-root applies cqis-numerics,
rfc-author and soundness-auditor; not independent audit. Evidence:
[block study](../../research/cqis-bounds/ATTENTION-BLOCKS.md).

- Public items: conditional block rounding/aggregation records, plaintext checks
  and configured-block model templates; Accepted RFC-0022 remains unchanged.
- Challenges/absorbs: none; no FS order, random challenge or degree loss change.
- Claims/consumers: no proof claims emitted. Numerical tests compose raw sums,
  rounded aggregates and normalization. Actual source/mask/position/scale/head,
  function and range consumers remain required for the complete claim graph.
- Bindings/controls: IntegerRelation catches canonical-source and zero-to-32
  rounding aliases; SumRelation catches a changed aggregate. Blocks/Witness,
  SourceDigits, OutputRelation, Range and Boundary catch their named mutations.
  No NC-0100/0101/0109/0500..0506 credit is claimed.
- Ledger: no lines change; accounting gate must preserve existing coverage.
- Static bounds: formats, absolute span and configured drop derive every cap;
  a short/zero actual row cannot relax the full-block drop requirement. Rounded
  totals fit directly in M31; wide raw sums and divisor aggregates use columns.
- Padding/masks: only expected occupied blocks are stored, retaining absolute
  IDs and all-masked rows. Missing/extra rows reject. Complete membership and
  masks are still source obligations; no free compaction or padding is admitted.
- Determinism: fixed role order, explicit nearest ties away and canonical zero
  source sign; nonzero negative sources may correctly round to integer zero.
- Parity: exact/NumPy corpus and model/checkpoint composition; shared numerical
  primitives disclosed. Native/GPU parity and inference admission remain open.
- Costs: fixed records and O(k*W) actual-block work/data; no unused-tail allocation,
  measured constant, benchmark claim, new cut or proof weight-pass change.
- Verifier: production no_std unchanged; research whole ranges/digit checks are
  not succinct authenticated consumers or complete certificate-set validation.
- Glossary/history: Accepted prefixes and original criteria preserved. The pinned
  block-mode variant is explicitly a different numerical configuration, not the
  baseline identity, a claimed generated continuation or fidelity approval.

I tried to break it by changing the rounded output from zero to 32 while making
the biased division wrap by exactly p, and the control IntegerRelation rejected
it after all columns were rebuilt. Omitting an occupied zero block rejected
with Witness even though it would leave the aggregate numerical value unchanged.

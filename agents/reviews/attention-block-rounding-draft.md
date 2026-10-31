# Attention block-rounding review in progress

Codex-root applies cqis-numerics, gkr-reduction-author and soundness-auditor.
This is a same-author review, not an independent audit. The
[scope](../../research/cqis-bounds/ATTENTION-BLOCK-ROUNDING.md) preceded tests
and code. Tests first rejected the missing module. All 10000 corpus cases,
controls and actual source composition passed. Matrix and three full geometries
continue in their original process. Repository gates are queued once. This is
not a completed sign-off.

- Public items: Draft RFC-0004 A3/A6 and RFC-0009 A2. Expected block schema
  fixes magnitude cap, shift, bias and quotient/remainder caps. Absolute block
  ids and source roles are expected metadata, never proof-supplied authority.
- Challenges: five complete range schedules remain. Full schema, field and
  repetition metadata, block ids, every external/internal root and all verified
  child states precede the two parent A3s. Existing ZeroWeight and sumcheck
  labels retain their Instance/Round/Final schedule.
- Claims: all eight originals retain actual-point consumers. The quotient
  product view comes from verified bytes even when q is statically zero.
  Public bias, padded masks and initial/terminal carries remain obligations.
- Bindings: tests attack each block/output root and range, bounded M+p,
  coherent r=D, omitted bias, changed carries and compensated originals.
  Metadata replay, valid block substitution, high bytes and malformed shapes
  rejected. Complete canonical-sign proofs passed ragged per-block joins; a
  valid replacement rejected its pinned source root.
- Ledger: five independently repeated lookup identities and unsquared
  reductions remain. Total range/A3 loss is49a+7(bm+bq+br)+42 over the field;
  the parent contributes4a+6. The test compares actual receipts and draws for
  both fields/repetition counts. Repository accounting remains pending.
- Bounds: static block policy gives qmax<=32767. Hmax+bias and qmax*D must
  each be below2^64 before eight columns are used. Natural carries have the
  static envelope [-129,2]; shifted values are ranged [0,131]. Nonnegative
  column sides are at most66431<p/2. No observed maximum replaces a bound.
- Padding: the dense M/q/r ranges use one final padded domain. Each source
  root gathers actual verified M bytes and adds only the channel padding of
  that block. All dense tail and carry slots have zero caps. External q/r
  roots retain two/eight planes, including q with a one-byte zero-cap range.
- Determinism: sorted unique expected blocks, fixed root/range/A3 order and
  static namespaces. No floating point, retry or payload-dependent order.
  The corpus digest is frozen; proof matrix and full-domain runs continue.
- Parity: native CPU/SIMD/CUDA are unchanged. Fraction and NumPy oracles test
  exact rounding, external byte layouts and independent prefix carries.
  Full 128x128, 1024x16 and 1x16384 geometries remain required evidence.
- Costs: linear dense byte views and per-block root joins, two batched A3s
  and five complete range/hash consumers in c_a/c_sc/c_lu/T_misc. These are
  static operation counts, not measured benchmarks; no weight pass changes.
- Verifier: native no_std is unchanged. Expected dimensions precede payloads;
  exact proof shapes, complete children and canonical fields are checked.
  Root joins use verified bytes. No verifier-side division, producer receipt
  or supplied projection grants acceptance.
- Glossary/history: append-only Draft/accounting additions. Original task
  statuses and criteria remain blocked. Signed block output, aggregation,
  restored normalization units, complete source ownership, native/private
  proof, fidelity and independent audit remain required.

I tried to break it by setting r=D while reducing q so every byte column
remained equal, and Remainder:CapRelation:RoundSumMismatch rejected it.
Compensating each original final also rejected at its ClaimMismatch consumer.

All 16 matrix proofs passed with exact receipts and draw counts. Their
transcript digest is frozen. The original three full geometries and gate
queue remain active; this evidence does not complete the review.

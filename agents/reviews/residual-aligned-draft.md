# Residual aligned-source review in progress

Codex-root applies cqis-numerics, gkr-reduction-author, rfc-author and
soundness-auditor. This is a same-author review, not independent audit.
[Scope](../../research/cqis-bounds/RESIDUAL-ALIGNED.md). Tests-first failed at
the missing module. The10000-case corpus and primary adversarial controls passed.
Boundary controls and all16 main proof cases passed. The no-carry matrix,
maximum and gates remain under validation; this is not a completed sign-off.

- Public items: Draft RFC-0004 A3/A8 research only. Expected residual schema
  fixes fractions and source roles. Only the aligned offset is proved.
- Challenges: complete child transcripts remain. Expected schema/role bytes,
  three external roots, all auxiliary roots and verified child states precede
  the parent A3. Its ZeroWeight and Instance/Round/Final schedule is unchanged.
- Claims: five original views retain independent consumers at emitted points.
  Verified raw signed bytes become offset bytes by the exact top-bit map;
  expected shifts supply coefficients. No whole aligned integer is recomputed
  by verification, and no zero source suppresses a child consumer.
- Bindings: controls cover every external root, valid same-magnitude signed
  substitutions, in-range O+p, actual carries, padding and compensated finals.
  Primary controls rejected at the named source, column and original consumers.
  Terminal/padding controls also rejected at the actual cap consumers.
  The no-carry matrix additionally tests compensated finals for both public
  zero carry views and output, preserving the final algebraic equality.
- Ledger: six signed lookup units plus output and nonzero carry groups;
  every repeated identity and unsquared reduction is retained. Parent degree
  is one over8N. Closed total and draw formulas are in the appended accounting
  entry. Main matrix receipts matched the closed loss/draw totals; the
  no-carry matrix and accounting gate remain required.
- Bounds: whole output cap65535*(A+B) and every carry cap come solely from
  expected fractions and static byte limits. Each column side is at most65535.
  Closed carry bounds, including terminal zero, give exact integer equality.
- Padding: the sign-bit offset applies only to real rows. Both signed sources,
  output and carry families retain their actual padded-zero range obligations.
  All eight output planes enter the root, including high extension zeros.
- Determinism: fixed role, range and column order; explicit metadata bytes,
  expected capacity and disjoint child spans. No timing-dependent selection.
- Parity: native CPU/SIMD/CUDA unchanged. Independent NumPy int64 alignment and
  byte/carry grids passed10000 cases and3383720 cells; the digest is frozen.
  All16 main cases passed both fields and repetition counts. The no-carry
  matrix and complete16384-row proof remain under validation.
- Costs: O(N) byte views and one batched A3 plus all complete child range/hash
  consumers in c_a/c_sc/c_lu/T_misc. No measured constant or extra weight pass.
- Verifier: native no_std unchanged. Exact proof keys, separately expected
  schema/roots and canonical parent fields; no supplied receipt or certificate
  grants acceptance. The research capacity is explicit, with no weakened task.
- Glossary/history: append-only Draft/accounting evidence. Canonical numerator
  sign, one-round residual output, the original2^20 domain, native/model/private
  inference and fidelity remain required. The remaining validation
  stays required; production control coverage is unchanged.

I tried to break it by substituting an independently ranged O+p while retaining
the original signed sources and carries, and the control
AlignedColumns:RoundSumMismatch rejected it.

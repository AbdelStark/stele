# Positive attention denominator review in progress

Codex-root applies cqis-numerics, gkr-reduction-author and soundness-auditor.
This is a same-author review, not an independent audit. The
[scope](../../research/cqis-bounds/ATTENTION-DENOMINATOR.md) preceded tests and
implementation. Tests first rejected the missing module. All 10000 corpus
cases and primary controls passed. Composition, matrix and boundary proofs
are running. Required repository
gates are queued once. This is not a completed sign-off.

- Public items: Draft RFC-0004 A3/A6 and RFC-0009 A2. The expected full
  normalization schema fixes Q, zmax and the unit factor in both modes. The
  output is sixteen bytes, preserving the exact-mode D=2^64 boundary.
- Challenges: the wrapper draws none. Complete gap and limb-product
  transcripts remain unchanged. Schema, roles, field/repetition bytes, both
  external roots, five internal roots and three verified child states bind
  the returned state. Equivalent arithmetic metadata can reuse valid child
  proofs; callers must bind the distinct returned composition state.
- Claims: both products retain their actual left/right operands and public
  powers at the emitted points. Every inherited packing/range claim is
  consumed. Exact byte joins connect gap, Q, both ones, actual Z and factor F.
- Bindings: controls target every root and join, including a changed one
  hidden by zero gap. Forged arithmetic views and compensated public powers
  attack all eight product original consumers. Separate controls attack
  below-Q/zero Z, genuine ranged Z-p/D-p aliases, gap caps and full high bytes.
  Complete global-sum source composition and valid substitutes are required.
- Ledger: seven lookup identities and their unsquared reductions remain
  independent. Range/A3 numerator is 7bg+9(bp+bd)+18(gp+gd)+73; the two product
  identity losses remain separate, with A1 reduction 2+4(bp+bd). Nonlookup
  draws are 3bg+4(bp+bd)+8(gp+gd)+31 ZeroWeight and
  3bg+6(bp+bd)+8(gp+gd)+34 Sumcheck. Exact receipts and the repository
  accounting gate remain under validation; initial receipts and draws matched.
- Bounds: complete 0<=g<=zmax-Q and faithful Z=g+Q columns establish both
  divisor bounds. The second static limb certificate proves D=Z*F without
  lifting Z or D into one M31 value. Every bound comes from expected metadata.
- Padding: actual gap and Z bytes are zero-extended into static operand
  layouts. Every constant byte is checked. Source bytes above a compact
  denominator operand must be zero. Full eight/sixteen-byte external roots,
  complete carry endpoints and output padding remain consumed.
- Determinism: fixed role order, namespaces and exact schema bytes. No float,
  retry or witness-selected mode. Independent integer products, byte roots,
  column convolutions and both-field proof digests remain under validation.
- Parity: native CPU/SIMD/CUDA are unchanged. The full-metadata exact proof
  must reach D=2^64, and the block boundary must reach D=2^48. Both retain
  width 16384 and length 1048576 metadata; these scalar proofs do not claim
  ownership of the upstream key/channel grid.
- Costs: a scalar wide range and two existing complete limb products with
  constant-size byte joins contribute to c_a/c_sc/c_lu/T_misc. No measured
  constant, benchmark, new cut or additional weight pass is claimed.
- Verifier: native no_std is unchanged. Expected metadata fixes all lengths;
  exact child shapes and canonical fields are mandatory. Actual proof
  verification, rather than plaintext whole-product recomputation, admits D.
- Glossary/history: Draft/accounting additions are append-only. Original
  statuses and acceptance criteria stay blocked. Numerator scaling, signed
  division/rounding, global attainment, source ownership, native/private
  model inference, fidelity and independent review remain required.

I tried to break it by replacing one with zero on the zero gap operand,
and the control Positive:SourceJoin rejected it. Each product's forged
left/right view rejected at SourceClaimMismatch, and compensated public
powers rejected at PowerClaimMismatch. The independent corpus digest is
frozen; remaining boundary/composition proofs and gates are still pending.

Boundary and source-composition suites subsequently passed. I tried to break
it with fully output-ranged Z-p and D-p values; the controls rejected at
Positive:Product:RoundSumMismatch and Denominator:Product:FinalEvaluationMismatch.
A complete global probability sum composed on its actual root. Valid changed
and zero source sums could not replace the admitted divisor. The matrix,
full-metadata boundary proofs and repository gates remain pending.

All 16 matrix cases and both full-metadata scalar boundary proofs subsequently
passed, with exact receipts, draws and original claims. Their digests are
frozen. The exact proof preserves D=2^64; the block proof preserves D=2^48.
Both retain length 1048576 and width 16384 metadata. The original runner
completed successfully. Repository gates and independent review remain pending;
this evidence does not claim upstream key/channel ownership.

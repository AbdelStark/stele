# Doubled attention denominator review in progress

Codex-root applies cqis-numerics, gkr-reduction-author and soundness-auditor.
This is a same-author review, not an independent audit. The
[scope](../../research/cqis-bounds/ATTENTION-DOUBLED-DENOMINATOR.md) preceded
tests and implementation. Tests first rejected the missing module. Corpus
and proof suites are running; this is not a completed sign-off.

- Public items: Draft RFC-0004 A3/A6 and RFC-0009 A2. The consumer binds
  sixteen-byte D and 2D with the exact coefficient two. The complete expected
  normalization schema preserves Dmax=2^64 and doubled maximum 2^65.
- Challenges: the wrapper draws none. All complete child transcripts retain
  their root/state absorbs and challenges. Expected schema and roles bind
  both external/internal roots and the verified product state in the returned
  composition state. Equivalent arithmetic may reuse a child proof, but
  callers must bind the distinct returned state.
- Claims: both actual operand claims and both public powers are consumed at
  their emitted points. All input whole ranges, packing, output/carry ranges
  and original claims remain mandatory. Every right byte equals coefficient two.
- Bindings: tests target both external roots, zero-hidden factor changes,
  false operand views, compensated public powers, genuine output-ranged 2D-p,
  source overflow, endpoints, padding and high planes. Complete positive
  denominator composition must reject valid changed or zero substitutes.
- Ledger: three independent lookup dimensions b+2,g+3,g+3 retain repeated
  identities and unsquared reductions. Range/A3 numerator is 9b+18g+31,
  product identity k-1 and A1 reduction 4b. Nonlookup draws are 4b+8g+13
  ZeroWeight and 6b+8g+14 Sumcheck. Exact receipts and the repository
  accounting gate remain under validation.
- Bounds: expected metadata fixes the whole D cap and every limb column.
  Static certificates make each column faithful below p/2. D and 2D are
  never lifted into single M31 values. No observed value sets a bound.
- Padding: compact operand/output arrays are zero-extended to all sixteen
  external planes. Every high right operand byte is exactly zero. Complete
  output padding and initial/final carry consumers remain present.
- Determinism: fixed roles, namespaces and canonical schema bytes. Integer
  arithmetic only, with no retry or witness-selected layout. Independent
  integer doubles, byte roots and column convolutions remain under validation.
- Parity: native CPU/SIMD/CUDA are unchanged. Both full-metadata scalar proofs
  retain length 1048576 and width 16384, reaching exact 2D=2^65 and block
  2D=2^49. They do not establish ownership of upstream key/channel grids.
- Costs: one existing complete scalar limb product and constant-size byte
  joins contribute to c_a/c_sc/c_lu/T_misc. No benchmark, measured constant,
  new cut or additional weight pass is claimed.
- Verifier: native no_std is unchanged. Expected metadata fixes every length;
  exact child shapes and canonical fields remain mandatory. Complete product
  verification admits the output, rather than plaintext whole multiplication.
- Glossary/history: Draft/accounting additions are append-only. Original
  statuses and criteria stay blocked. Positivity requires the actual upstream
  proof; biased numerator, quotient product, strict remainder, signed output,
  full ownership, native/private inference and fidelity remain required.

The observed-attack conclusion remains pending the controls. Required
repository gates and independent review must also complete.

The initial run passed receipt, external-root and zero-hidden factor controls.
An altered input digit rejected at Double:Input:LimbPacking:ClaimMismatch: the
replayed linear proof still had zero rounds, but its original source claim
no longer matched. The test expected a round failure. Only that expected
diagnostic changed; the original log is retained and verifier behavior is
unchanged. The failed control suite must complete.

The corrected primary suite passed. I tried to break it by changing the
coefficient two to zero while D was zero, and Double:Factor rejected it.
Both forged actual operand views rejected at SourceClaimMismatch; compensated
public powers rejected at PowerClaimMismatch. The complete independent corpus
passed and its digest is frozen. Remaining proof suites and gates are pending.

Boundary and actual positive-source composition suites subsequently passed.
The genuinely output-ranged 2D-p value rejected at Double:Product:FinalEvaluationMismatch.
Both valid changed and standalone zero source substitutions rejected.
All 16 matrix cases matched exact receipts, draws and original claims; their
digest is frozen. Full-metadata boundaries and repository gates remain pending.

# Canonical attention sign review in progress

Codex-root applies cqis-numerics, gkr-reduction-author and soundness-auditor.
This is a same-author review, not an independent audit. The
[scope](../../research/cqis-bounds/ATTENTION-SIGN.md) preceded tests and code.
The tests-first run rejected the missing module. All 10000 corpus cases,
controls and actual source composition passed. The proof matrix and full-domain
proof are running; required repository gates are queued once. This is not a
completed sign-off.

- Public items: Draft RFC-0004 A3/A6 and RFC-0009 A2 research. The expected
  schema determines O, H and M caps. Actual scalar H is a verified source.
  This proves a conditional signed sum, without upstream ownership admission.
- Challenges: seven complete range transcripts retain their own schedules.
  Expected schema/roles, four external roots, seven auxiliary roots and all
  verified child states precede the three parent A3s. Terminal carry, signed
  columns and canonical zero use the existing ZeroWeight and sumcheck labels.
- Claims: all twelve parent originals are consumed at their emitted points.
  The actual H bytes broadcast only to real channels. A zero-hidden sign,
  initial/terminal carries and the public mask remain checked originals.
- Bindings: controls rejected mutations of every external root and range, bounded
  M+p, negative zero, both carry families and all originals with compensated
  final values. Valid replacement O/H sources preserve the difference but
  rejected the pinned roots. Complete weighted/probability/base child proofs
  passed actual joins; valid alternate children rejected their pinned roots.
- Ledger: seven separate repeated lookup identities and unsquared reductions.
  The appended account includes the scalar H range separately. Tests compare
  exact A3 numerators and draw totals with receipts for both fields and both
  repetition counts. The repository accounting gate is pending.
- Bounds: signed carries lie in [-2,2]; shifted carries have range [0,4].
  Exact endpoints and nonnegative column sides at most 1534 establish integer
  equality. The actual magnitude-byte sum is at most 2040; predecessor plus
  sign is at most 2041. These bounds are static and below p/2.
- Padding: expected channel count fixes every mask. O/M/sign/predecessor and
  carry padding are ranged zeros. The scalar base range has its own shape;
  it is never padded as a channel vector. External O/H/M roots retain all
  eight byte planes even when the compact range has fewer bytes.
- Determinism: fixed range, root and A3 order; exact schema bytes; disjoint
  local namespaces. No runtime cap, retry or timing-dependent reduction order.
- Parity: native CPU/SIMD/CUDA are unchanged. All 10000 independent NumPy cases
  and prefix-derived carry checks passed. The full 16384-channel proof
  does not establish a complete million-key source composition.
- Costs: linear byte views, three batched A3s and seven complete range/hash
  consumers contribute to c_a/c_sc/c_lu/T_misc. These are static counts, not
  measured performance. No additional pass over weights is introduced.
- Verifier: native no_std is unchanged. The verifier checks expected metadata,
  complete children, exact proof shapes and canonical parent fields. Supplied
  states or certificates grant no authority. It does not subtract wide O/H
  integers or compute an absolute value to grant acceptance.
- Glossary/history: Draft/accounting additions are append-only. Original
  task criteria remain blocked. Rounding, normalization, ownership, native/
  private inference, fidelity and independent review remain required.

I tried to break it by setting the sign of zero magnitude to one while
retaining valid ranges and signed columns, and CanonicalZero:RoundSumMismatch
rejected it. Compensating the actual H and O final claims also rejected at
SignColumns:ClaimMismatch.

The complete 16-proof matrix passed in both fields and repetition counts.
Its transcript digest is frozen, and all receipts/draw totals matched. The
original full-size proof and gate queue continue without a restart.

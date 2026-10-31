# Global attention offset base review in progress

Codex-root applies cqis-numerics, gkr-reduction-author and soundness-auditor.
This is a same-author review, not an independent audit. The
[scope](../../research/cqis-bounds/ATTENTION-GLOBAL-BASE.md) preceded tests
and implementation. Tests first rejected the missing module. The evidence
and repository gates must complete before any sign-off.

- Public items: Draft RFC-0004 A3/A6 and RFC-0009 A2. Exact-mode H=S*Z uses
  the full expected normalization schema and eight-byte external Z/H roots.
  Block normalization has no such base and rejects this consumer's schema.
- Challenges: none in the wrapper. Complete child transcripts preserve their
  root/state absorbs. Full schema, roles, external/internal roots and verified
  product state bind the returned context state. Equivalent arithmetic may
  reuse the child, but its distinct context state must be bound by the caller.
- Claims: both actual operand claims and both public powers are consumed at
  the emitted points. Complete whole ranges, packing and output/carry ranges
  remain mandatory. Every actual right byte must equal the expected S byte.
- Bindings: controls target both roots, zero-hidden factor substitutions,
  high factor bytes, false actual operands, compensated public powers,
  genuine output-ranged H-p/H+p, whole Z overflow and source composition.
  Each control asserts its rejection reason; observed results remain pending.
- Ledger: independent lookup dimensions b+2,g+3,g+3 preserve repeated
  identities and unsquared reductions. Range/A3 numerator is 9b+18g+31,
  product identity k-1 and A1 reduction 4b. Nonlookup draws are 4b+8g+13
  ZeroWeight and 6b+8g+14 Sumcheck. Runtime receipts and the repository
  accounting gate must match; the wrapper has no loss or draw.
- Bounds: static expected Zmax=L*2^E<=2^34 and Hmax=Zmax*S<2^50 fix the
  limb certificate. Whole input caps differ for Z and S and both are checked.
  Every byte column is faithful below p/2. No observed value chooses a bound.
- Padding: compact operands/output extend to all eight external planes.
  Every high S byte is exactly zero. Output padding and initial/final carry
  constraints remain in the complete child proof, including at zero input.
- Determinism: fixed namespaces and canonical expected schema bytes; integer
  arithmetic only. Corpus products and byte roots have an independent NumPy
  oracle. No retries or witness-selected layouts occur in the verifier.
- Parity: native CPU/SIMD/CUDA are unchanged. Full-metadata scalar proofs use
  length 1048576 and width 16384; they do not prove full-row ownership or
  performance. Both challenge fields and repetition counts require validation.
- Costs: one complete scalar limb product and constant-size byte joins affect
  c_a/c_sc/c_lu/T_misc. No measured constant, benchmark, new cut or additional
  weight pass is claimed. Existing local-base consumers remain unchanged.
- Verifier: native no_std is unchanged. Expected metadata fixes each length;
  exact child shapes and canonical fields remain mandatory. Complete product
  verification admits the relation; plaintext multiplication only builds roots
  and witnesses for the producer/test oracle.
- Glossary/history: Draft/account additions are append-only. Original task
  status and criteria stay blocked. Positive Z and exact source ownership
  require upstream proofs; complete normalization, configured conversion,
  native/private inference, fidelity and independent audit remain required.

The observed-attack conclusion is pending the controls. This review does not
grant native coverage or approve an RFC amendment.

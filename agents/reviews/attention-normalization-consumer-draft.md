# Conditional attention normalization review in progress

Codex-root applies cqis-numerics, gkr-reduction-author and soundness-auditor.
This is a same-author review, not an independent audit. The
[scope](../../research/cqis-bounds/ATTENTION-NORMALIZATION-CONSUMER.md)
preceded namespace checks, tests and implementation. Tests first rejected the
missing module; the complete evidence and repository gates remain required.

- Public items: Draft RFC-0004 A3/A6 and RFC-0009 A2. Six complete children
  in exact mode and five in block mode bind signed int16 normalization on
  expected O/Z roots. Exact global H=S*Z also joins the canonical raw sign.
- Challenges: the wrapper draws none. Expected schema/roles, all expected
  roots and every verified child state bind the final context. All child
  transcripts retain their existing absorbs and challenges. Equivalent valid
  arithmetic metadata must produce a distinct context state.
- Claims: every child verifies independently. All actual/public originals,
  complete range consumers and strict-division claims remain mandatory.
  The same expected root is passed to every child sharing that source.
- Bindings: tests alter every expected root and replace every child with a
  separately valid proof preserving Y=0. Producer root joins are checked,
  but verifier admission never calls that assembler or trusts a receipt.
  Missing/extra children, mode swaps and invalid block H roles must reject.
- Ledger: no wrapper loss. Every child lookup identity and unsquared
  reduction remains separate. Range/A3 and A1 numerators are summed. Four
  polynomial identities remain in exact mode, three in block mode. Each
  child receipt, aggregate and empty wrapper draw set require validation.
- Bounds: full expected metadata derives every child certificate and fixes
  all widths/groups. No source value selects a bound. Static faithful byte
  relations and whole ranges remain in the children. Producer division is
  separate from verifier admission; int16 output overflow is not clipped.
- Padding: complete byte planes and each child's padding checks remain.
  Block membership metadata is the full configured sequence of block ids.
  Block mode has no H payload/root and requires a canonical zero role sentinel.
- Determinism: fixed child order, role order and canonical schema encoding.
  Integer producer arithmetic only. The independent corpus compares NumPy
  signed rounding and all byte roots, including ties and negative-input zero.
- Parity: native CPU/SIMD/CUDA are unchanged. Both challenge fields and
  repetition counts require complete proofs. Full 16384-channel exact and
  block proofs are queued behind existing prerequisite proofs, not restarted.
- Costs: the wrapper adds fixed-count root routing and context hashing to
  the complete child costs in c_a/c_sc/c_lu/T_misc. No benchmark, measured
  constant, new cut or additional weight pass is claimed.
- Verifier: native no_std is unchanged. Expected metadata fixes every child
  shape. Exact proof keys and root widths are checked before admission. A
  child proof cannot select another mode or supply its own specification.
- Glossary/history: Draft/account additions are append-only. Original task
  status and criteria remain blocked. Full O/Z source ownership, configured
  output conversion, model/cache/decode ownership, native/private PCS/ZK/FS,
  GPU scale, fidelity and independent audit remain required.

The observed-attack conclusion is pending actual controls. This review does
not grant production coverage or approve an RFC amendment.

Focused context-encoding controls passed for both modes, fields and repetition
counts: changing any one opaque child state, the schema or an output role
changes the final context; missing states and extra roots reject. These tests
ran separately because the original proof runner was already loaded. Future
boundary runs include them. Actual proof-substitution controls and the corpus
continue in their original processes; no admission result is inferred from
the context test alone.

The first proof suite reached a test-fixture failure: its valid replacement
control used Z=66 under the static maximum 65. The producer correctly rejected
Divisor before that proposed alternate proof existed. The baseline fixture now
uses Z=33, so both Z and Z+1 are admissible and the intended verifier binding
can be exercised. No verifier behavior changed. The failed log is retained;
only the waiting full-proof driver was stopped before any full proof started.
The independent corpus and gate queue continue without a restart. The corrected
proof suite must pass before an observed-attack conclusion.

The independent corpus subsequently passed all 10000 random cases plus four
capacity and one tie case. All 197531 checked channels matched NumPy integer
normalization and full external byte roots; overflow rejection and signed
zero behavior matched. Its digest is frozen. The corrected proof suite has
passed the exact-mode substitution controls and is still running; complete
block-mode, matrix, full-size and repository gate evidence remains pending.

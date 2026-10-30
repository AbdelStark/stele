# Capped scalar range consumers — same-author review

Codex-root applies cqis-numerics, gkr-reduction-author, rfc-author and
soundness-auditor. This is not independent audit. Scope: Draft RFC-0004 A3 /
RFC-0008 A2 / RFC-0012 A8, reusing Accepted RFC-0006 A3 and RFC-0021 range_8.
Evidence: [range consumer study](../../research/cqis-bounds/CAPPED-RANGE.md).

- Public items: bounded expected Spec, honest witness generation, arithmetic
  producer and revealing verifier. No native private protocol or plan admission.
- Challenges/absorbs: unchanged Q31 lookup first. The following A3 context binds
  expected caps/source/table, source/byte/carry roots and completed lookup state.
  Four k=0 relations absorb their descriptor and every final in order. There are
  4a+4 weights and 4a+4 tail draws; no skip draw or newly registered label.
- Claims/consumers: all twelve A3 claims are evaluated at their derived points
  against full root-bound originals or deterministic views. Q31 consumes two
  additional claims per repetition, including the same byte root and mu roots.
  Coherent changed finals preserve a scalar relation but fail original consumption.
- Bindings/controls: one-value opening changes reject CommitmentMismatch; changed
  source reconstruction rejects its relation. Wrapped x+p and nonboolean-carry
  attacks fail TerminalCarry and CarryBoolean respectively. Out-of-table bytes
  fail the actual lookup equation. No production NC credit is claimed.
- Ledger: conditional Q31 identity/reduction terms are retained; four A3 relations
  add (9a+10)/|K|. The accounting document records each degree/dimension and actual
  draw count. Binding and FS/H are unresolved; repetitions do not square A3 loss.
- Static faithfulness: caps are verifier-owned canonical M31 values. Once byte
  membership and carry Booleanity hold, both column sides are <=511 and 2*511<p.
  The endpoint proves W+S=cap<p. Source reconstruction is field embedding followed
  by uniqueness of canonical representatives, not unchecked wide integer arithmetic.
- Padding/masks: pad caps with zero and select every byte, including padded rows.
  Zero cap plus all relations enforces zero source words/bytes/carries. The lookup
  grouping is one flat plane-major unit of 8N<=32768<p positions, with no
  preliminary Unit draws; this is not an inferred model layout.
- Determinism: closed ids, fixed plane order, expected caps/table and A3 schedule.
  Both fields/repetition counts agree on exact states, claims and records. The
  folded producer matches the naive oracle on the selected small fixtures.
- Parity: research Python only; no native inference, GPU, private PCS or ZK claim.
  Existing Merkle, lookup, zerocheck and table generators are shared and disclosed.
- Costs: dense field tables, folds, exact original consumption and complete
  revealing payloads in c_a/c_lu/T_misc. No benchmark, RSS guarantee, fitted
  constant, production cut or inference weight-pass change.
- Verifier: production no_std untouched. Expected capacities precede vector work;
  supplied proof shapes/canonical fields/roots are checked. Python object proofs
  are not a native bounded wire parser. Arithmetic producers never bypass verify.
- Glossary/history: append-only Draft evidence and research accounting. Original
  criteria remain blocked. Native range dominance, wide/signed source contracts,
  actual inference consumers and joint private masking remain open.

I tried to break it by using a source decomposition equal to x+p and a wrapped
complement that satisfied every byte column and carry-bit equation, and the
control TerminalCarry:FinalEvaluationMismatch rejected it. Field-valued nonbits
with zero terminal carry instead failed CarryBoolean:RoundSumMismatch.

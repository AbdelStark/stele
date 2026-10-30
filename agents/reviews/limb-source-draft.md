# Limb input source consumers — same-author review

Codex-root applies cqis-numerics, gkr-reduction-author, rfc-author and
soundness-auditor. This is not independent audit. Scope: Draft RFC-0004 A3,
RFC-0008 A2 and RFC-0012 A8; Accepted A3/range_8 primitives are unchanged.
Evidence: [limb source study](../../research/cqis-bounds/LIMB-SOURCE.md).

- Public items: static schema/layout derivation, exact source adapter, arithmetic
  composition and revealing verifier. No production protocol/cut admission.
- Challenges/absorbs: optional nibble range, whole range, packing in fixed order.
  Nested Q31/A3 schedules remain complete. Expected schema/source, original/word
  roots and all completed nested states precede packing weights and tail draws;
  every final is absorbed. No new registered label or challenge retry.
- Claims/consumers: every nested range claim reaches its actual original/public
  consumer. Packing consumes two byte or three nibble/word claims at their actual
  points against the independently bound source and the same verified word root.
  Low/high are deterministic even/odd plane views, not separately trusted inputs.
- Bindings/controls: changed source/word openings reject commitment checks;
  changed finals reject arithmetic or actual ClaimMismatch. Fresh wrong originals
  reject packing; 511 under 257 rejects the whole terminal carry. A digit16 that
  packs to a valid byte rejects the independent nibble endpoint. Padded/high
  source positions, expected caps, malformed shapes, ids and capacities reject.
  These research checks receive no native NC credit.
- Ledger: byte/nibble A3 totals are 11a+11+9b / 20a+18b+29 over |K|. Each
  complete Q31 identity and reduction term is retained separately. Weight/tail
  draws total 5a+4b+5 / 9a+8b+13 each; no Unit or skip draws. Tests compare
  child/packing counts, identities, records and totals. No reduction loss is
  squared. Binding, FS/H, private composition and joint ZK remain additional.
- Static faithfulness: expected limbs.Spec supplies every cap and layout; its
  static certificate is recomputed. Nibble ranges make packing sides <=255.
  Byte equality uses canonical representative uniqueness. Whole-word range uses
  the existing faithful byte columns and integer telescoping, not one wide field.
  Nonnegative digits and the whole maximum imply each certificate coordinate
  cap min(radix-1, floor(limit/radix^j)); multiplication/output/carries stay open.
- Padding/masks: count determines two separate N-row families. All padded rows
  and high planes remain original source coordinates; zero whole caps and
  canonical nonnegative digits force zeros. No model validity selector is inferred.
- Determinism: exact ids, source layout, nested order and schema framing; frozen
  corpus/proof states and reference A3 objects check both fields/repetitions.
- Parity: research Python only, sharing the disclosed field/lookup/Merkle/A3
  engines. No native inference, independent prover or GPU parity claim.
- Costs: O(BN) additional packing/consumption and the complete nested ranges;
  static capacities precede payload work. Symbolic c_a/c_lu/T_misc only, without
  a measured speedup, fitted constant, extra cut or inference weight pass.
- Verifier: production no_std untouched. Exact proof shapes, source identities
  and canonical field values are checked; object proofs are not a native bounded
  wire parser. Actual range/packing consumers replace plaintext range assertions.
- Glossary/history: append-only Draft evidence/accounting and original criteria
  preserved. Multiplication, result/carry, signed/model source and private PCS/ZK
  obligations remain explicit; input-range evidence does not complete inference.

I tried to break it by using a canonical operand of 511 under maximum 257,
and the control WholeWord:TerminalCarry:RoundSumMismatch rejected it. A nibble16
that packed to an otherwise valid byte instead failed its actual nibble-range
terminal consumer. Coordinated packing finals failed original ClaimMismatch.

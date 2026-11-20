# Review — E18-03: Contraction virtual columns engine core & NC-1307/NC-1338

- **Task:** `E18-03` (Lane P, development tier, RFC-0027 §2)
- **Scope audited:** Engine core (`4f1053a1..e7b37da7`) — `ResolvedColumns::for_segment` for `Def::Contraction`, Step 2.4 single- and multi-claim (`RFC-0006 A2` mode 1) contraction reductions, `VIRTUAL_BATCH`/`VIRTUAL_CONTRACTION` disjoint instance IDs, `Metrics` partial-eval counters, RFC-0012 A19 ledger lines, `NC-1307` and direct/adaptive `NC-1338`, RFC-0028 §8 note.
- **Reviewer:** Independent `soundness-auditor` (`81d553dc-dfed-48c8-a940-9f63a01086f7`)
- **Verdict:** **APPROVE** (after resolving F1 and F2 from first audit pass `1fb9313b`)

## Resolution of First-Pass Findings

- **F1 (Resolved — INV-1 Spec First):** Added the `E18-03 implementation note` in `docs/rfcs/RFC-0028-relation-ir-v2.md` §8 fixing per-column reduction order (strictly decreasing `ColumnId`), wire layout `[optional RFC-0006 A2 mode-1 claim batch] || [contraction sumcheck]`, disjoint instance IDs `VIRTUAL_BATCH | col_id` and `VIRTUAL_CONTRACTION | col_id`, unsplit sumcheck whenever `free <= MAX_VARS`, `summed <= MAX_VARS`, and `shared + summed <= MAX_VARS` (even when `free + summed > MAX_VARS`), `Error::Unsupported` when `shared + summed > MAX_VARS`, and direct block reduction for pre-split `Ref::FIXED_0/1` contractions.
- **F2 (Resolved — Test Coverage):** Added multi-claim `claim_batch` round-0 tamper (`RoundSumMismatch`), two-segment carried `Linear -> Contraction -> Linear` Step 2.4 -> Step 2.5 previous-segment stack opening test, and `shared + summed = 31 > MAX_VARS` -> `Error::Unsupported` test in `crates/stele-reductions/src/relation_tests.rs`.

## Workflow 03 Adversarial Statement

Attempted to break `E18-03` (`4f1053a1..e7b37da7`) via single-claim vs multi-claim `Def::Contraction` reductions (including `free == 0`/`summed == 0`, shared free bits, self-operands, and `Ref::FIXED_0/1` row-blocked slices), forged `eq` final evaluations preserving `eq · lhs · rhs` (`EqMismatch`), instance-ID collisions with `ZEROCHECK`/`MATMUL`/`BATCH`/`TUPLE`/lookup IDs, `shared + summed > MAX_VARS` admission (`Error::Unsupported`), cross-segment carried `Linear -> Contraction -> Linear` Step 2.4 -> Step 2.5 openings, out-of-width `i64`/`i128` materialization overflow (`Error::Capacity`) and poisoned `Values` slots, `NC-1307` round-0 tampers on both batch and contraction sumchecks (`RoundSumMismatch`), direct and adaptive single-/multi-claim `NC-1338` forgeries (`RoundSumMismatch` / `FinalEvaluationMismatch`), noncanonical limbs (`NoncanonicalField`), and truncated sections (`ProofShape`). Every attack is rejected cleanly and deterministically by `verify_segmented` with exact RFC-0012 A19 ledger lines, no new transcript labels, bit-identical non-virtual proofs, and no security level or profile promotion claimed.

*(Module-conversion addendum and L1/L2a before/after ledgers will be appended after rebasing onto `main`.)*

# Review — E18-02: Linear virtual columns engine core & NC-1337..1338

- **Task:** `E18-02` (Lane P, development tier, RFC-0027 §2)
- **Scope audited:** Engine core (`a0830708..78e0e151`) — `ResolvedColumns`, Step 2.4 `Def::Linear` claim reduction, RFC-0026 A28 `absorb_virtual_members` & `absorb_linear_evals`, `NC-1337..1338`, RFC-0028 §8 note.
- **Reviewer:** Independent `soundness-auditor` (`81d553dc-dfed-48c8-a940-9f63a01086f7`)
- **Verdict:** **APPROVE** (after resolving F1, F2, F3 from first audit pass `632a4545`)

## Resolution of First-Pass Findings

- **F1 (Resolved):** `docs/rfcs/RFC-0028-relation-ir-v2.md` §8 reconciles `LinearMismatch` (direct `NC-1337`/`NC-1338`) and downstream discharge (`PublicMismatch`, `Sumcheck`, `Pcs`) for adaptive `Def::Linear` `NC-1338` against `RoundSumMismatch`/`FinalEvaluationMismatch` for `Pointwise`/`Contraction` (E18-03/E18-04). `tests/negative-controls/src/development.rs::run_virtual_linear(1338)` and `relation_tests.rs` execute both direct (`LinearMismatch`) and adaptive (`PublicMismatch` + witness `Sumcheck(RoundSumMismatch)`) `NC-1338`, plus `NoncanonicalField` limb rejection and white-box transcript-binding tests (`absorb_virtual_members` no-op parity on non-virtual checks + challenge sensitivity; `absorb_linear_evals` binding).
- **F2 (Resolved):** `ResolvedColumns::for_segment` uses checked `i128`/`i64` arithmetic with a deterministic sequential fallback returning `Err(Error::Capacity)` on overflow (no `as i64` wrap). `ResolvedColumns::get` structurally refuses to fall back to `Values` for any `Kind::Virtual(_)` column (`Err(Error::Missing(id))`). Regression tests cover overflow, poisoned `Values` slots ignored, broadcast `Ref`, constant-only `Def::Linear` on `log_len == 0`, and invalid forge targets.
- **F3 (Resolved):** `identities_for` hoists `relation.column_segments()` once; `prove_segmented_impl` counts `Kind::Weight` reads from `ResolvedColumns::for_segment` in `col_reads` (INV-7) and validates `forge_virtual` inputs up front.

## Workflow 03 Adversarial Statement

Attempted to break `E18-02` (`78e0e151`) via non-multilinear `Def::Linear` references (fixed bits, repeated domain bits, permutations, broadcasts, empty terms, `log_len == 0`), out-of-order and cross-segment virtual column claims (segment `s` reading segment `s - 1` virtuals and vice versa, claims on carried `s - 1` witnesses opened in Step 2.5, unclaimed virtual columns), weak Fiat–Shamir on virtual lookup members and `Linear` operand evaluations, noncanonical field limbs and truncated/dropped reduction sections, out-of-width `i128`/`i64` overflow and poisoned `Values` slots in `ResolvedColumns`, and both direct and adaptive `NC-1337`/`NC-1338` virtual forgeries. Every attack is rejected cleanly and deterministically by the actual `verify_segmented` verifier, pre-A28 non-virtual proofs remain bit-identical, and no security level or profile promotion is claimed.

*(Module-conversion addendum will be appended once `E18-02` is rebased onto `main` after `E22-03` + `E18-06` + `E18-01` merge and module conversions + L1 before/after ledgers are audited.)*

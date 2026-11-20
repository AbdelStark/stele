# Review — E18-04: Pointwise virtual columns engine core & NC-1339..1340

- **Task:** `E18-04` (Lane P, development tier, RFC-0027 §2)
- **Scope audited:** Engine core (`e7b37da7..46c9f8d1`) — `ResolvedColumns::for_segment` for `Def::Pointwise`, shared `pointwise_instance`, Step 2.4 single- and multi-claim (`RFC-0006 A2` mode 1) `eq`-weighted RFC-0006 A1 sumchecks (`degree <= 4`, `EqMismatch` check, `VIRTUAL_POINTWISE` disjoint instance ID), RFC-0012 A19 ledger lines, `NC-1339` and `NC-1340` executed through `verify_segmented` (`84/126 bindings; 156/252 controls`), RFC-0028 §8 note.
- **Reviewer:** Independent `soundness-auditor` (`81d553dc-dfed-48c8-a940-9f63a01086f7`)
- **Verdict:** **APPROVE**

## Summary of Audit Verification

- **`Def::Pointwise` MLE identity & degree bounds:** Verified `pointwise_instance` deduplication of factor `Ref`s by full `(column, vars)` equality, MSB-first `eq_table`/`eq_evaluate` coordinate alignment with `Dense::fold`, `EqMismatch` check on `sp.final_values[0]`, `1 <= degree <= 4` sumcheck shape, static `HALF_MODULUS` bound enforcement, and `claims.push` routing.
- **Reduction order, transcript & accounting:** Verified disjoint `VIRTUAL_POINTWISE = (1 << 62) | (6 << 48)`, unclaimed column omission, RFC-0006 A2 mode 1 batching (`Line::Rlc` + `Line::Sc`) + `eq`-weighted sumcheck (`Line::Sc`, `m · degree / |K|`), zero new transcript labels, bit-identical non-virtual proofs, and INV-1 RFC-0028 §8 note.
- **Overflow, isolation & negative controls:** Verified checked `i128`/`i64` materialization (`Error::Capacity`), structural `Values` refusal in `ResolvedColumns::get`, INV-7 `col_reads` accounting, `controls`-only forge gating, `#![forbid(unsafe_code)]`, `#![no_std]`, and actual-verifier execution of `NC-1339` (`Fraction(RootMismatch)`) and `NC-1340` (`StatementMismatch(Invalid::Bound)`).

## Workflow 03 Adversarial Statement

Attempted to break `E18-04` (`e7b37da7..46c9f8d1`) via degree-1..3 `Def::Pointwise` definitions (sumcheck degrees 2..4 with `eq`, repeated factors, constant-only `log_len == 0`, broadcast `Ref`s, sign-magnitude `(1 - 2σ)x`), forged `eq` final evaluations scaled inversely with a factor to pass sumcheck (`EqMismatch`), multi-claim `claim_batch` round-0 tampers (`RoundSumMismatch`), unclaimed columns and truncated/noncanonical reduction sections (`ProofShape` / `NoncanonicalField`), direct and adaptive `NC-1338` virtual forgeries (`RoundSumMismatch` / `FinalEvaluationMismatch`), out-of-width 3-factor `i128`/`i64` overflow (`Error::Capacity`) and poisoned `Values` slots, `NC-1339` committed `y + 1` with virtual rounding remainder range lookup (`Fraction(RootMismatch)`), and `NC-1340` advice-as-virtual with field inverse `2^27` mod `p` (`StatementMismatch(Invalid::Bound)`). Every attack is rejected cleanly and deterministically by `verify_segmented` with exact RFC-0012 A19 ledger lines, no new transcript labels, bit-identical non-virtual proofs, and no security level or profile promotion claimed.

*(Module-conversion addendum will be appended after rebasing onto `main`.)*

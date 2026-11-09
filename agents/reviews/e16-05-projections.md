# E16-05 output-uniqueness lemmas (row conversion, projection)

**Scope.** RFC-0026 §5.2 obligation for §5 rows 3–4, task E16-05:
`stele_reductions::development::{row, projection}`. Same-author pass; an
independent soundness-auditor pass is requested on the PR.

Conventions: every statement is over Z. Every column lies in its declared width:
range discipline holds, and a matmul output is held by its matmul under RFC-0026
§3.6 as amended. Every identity is wrap-free under the bound rule, which
`Relation::validate` checks. `μ` is a public mask that is 1 exactly on real
(row, lane) or (row, channel) entries.

## Chain lemma (shared)

A chain declares `E_k + c_(k-1) − 256·c_k = 0` for `k = 0..N−1`, with `c_(−1) = 0`
and no `c_(N−1)`. Multiply position `k` by `256^k` and sum: the carries telescope,
so the chain holds iff `Σ_k 256^k E_k = 0` and each `c_k = (E_k + c_(k−1))/256`.
The carries are therefore functions of the terms. A carry split as
`lo + 2^16·hi` is auxiliary.

## Row conversion (RFC-0025 §2.2 dynamic/static; RFC-0004 A15 grouped)

**Lemma R.** Take an int16 input column `x`, with any values on padding. Every
assignment that satisfies the row-conversion relations has the same codes `c`
and the same scales `s`. On real entries they equal `Quantiser::convert_wide`'s
codes and scales. On padding, `c = 0`, and `s = 0` for a dynamic group made only
of padding. When the executor rejects a row (static `|q| > 127`), the relations
cannot be satisfied.

*Proof.*
1. **Sign/abs.** From `μx = a − 2σa`, `σ ∈ {0,1}` and `a ≥ 0`: on real entries
   `a = |x|`; on padding `a = 0`.
2. **Attained maximum** (dynamic, per group).
   - `h` is Boolean and the matmul gives `Σ_group h = 1`, so exactly one lane `j`
     has `h_j = 1`.
   - `h·gap = 0` gives `gap_j = 0`. With `gap = M − a`, `M = a_j`.
   - `gap ≥ 0` on every lane gives `M ≥ a_i`. So `M = max_group a`, the
     executor's maximum: padded lanes have `a = 0`, and `a ≥ 0`.
3. **Ceiling.** `127s − M ∈ [0,126]` (lookup) gives `s = ceil(M/127)`, the
   executor's scale. A static policy fixes `s` as a public column.
4. **Zero-row branch** (dynamic). `z ∈ {0,1}` and `z·M = 0`.
   - If `M > 0`, then `z = 0`.
   - If `M = 0`, then `s = 0`, and `spare = s + z − 1 − ρ ≥ 0` with `ρ ≥ 0` forces
     `z = 1`.
   - So `z = [M = 0]`, and the divisor `D = s + z ≥ 1` always.
5. **Division.** `a = q0·D + ρ` with `0 ≤ ρ ≤ D − 1` is Euclidean division, so
   `q0` and `ρ` are unique.
6. **Half bit.** Let `w = (2β−1)(2ρ−D) − (1−β) ≥ 0`.
   - `β = 1` gives `w = 2ρ − D`; `β = 0` gives `w = D − 2ρ − 1`. Exactly one is
     nonnegative, so `β = [2ρ ≥ D]`.
   - Then `q = q0 + β = floor((2a + D)/(2D))`, the executor's half-away magnitude.
     When `s = 0`, `a = 0`, so `q = 0`, as `z·q = 0` also states.
7. **Range.** `q ∈ [0,127]` by range, so an executor overflow is unsatisfiable.
8. **Code.** `c = (1 − 2σ)·q`. `σ` is free only when `x = 0`, and then `q = 0`.
   So `c` is unique and equals the executor's signed code. On padding, `a = 0`,
   so `q = 0` and `c = 0`.

The auxiliary columns `σ` (at `x = 0`), `h` (ties) and the carries are not
unique. No output depends on them. ∎

## Projection (RFC-0025 §2.2/2.5, family 1, no bias)

**Lemma P.** Take codes `c` (signed 8, zero on padded lanes; Lemma R provides
this), scales `s` (per row, below `2^bits(S)`, or per group for A15), the
committed weights `W`, public mantissas `m_j` and the plan shift `l`. Every
satisfying assignment has the same output `Y`, and:
- on real entries, `Y = R(V·m_j·u·2^l)`, rounded half away from zero, where
  `V = Σ_i c_i·W_ji` and `u = s` (per-row input), or `V = Σ_i s_k(i)·c_i·W_ji` and
  `u = 1` (grouped input);
- on padding, `Y = 0`;
- the relations are unsatisfiable exactly when that value leaves int16 (the
  executor's `Range`).

*Proof.*
1. **Sums.**
   - Per-row input: the matmul gives `C_0 = Σ_i c_i W_ji = V`.
   - Grouped input: `c·s = b0 + 256·b1`, with `b0 ∈ [0,255]` and `b1` ranged,
     fixes the digits. The two matmuls give `C_0 + 256·C_1 = Σ_i (c_i s_k(i)) W_ji = V`.
   - Codes on padded lanes are zero, so padded weight columns never enter `V`.
2. **Sign chain.** By the chain lemma, `V = (1 − 2τ)·Σ_k 256^k v_k`, with bytes
   `v_k` and enough bytes for the declared maximum of `|V|`. If `V ≠ 0`, then `τ`
   and `|V| = Σ 256^k v_k` are unique. If `V = 0`, then `|V| = 0` and `τ` is free.
3. **Scale bytes.** `s = Σ_c 256^c s_c`, with byte ranges and a top limb of
   `bits(S) − 8(n−1)` bits. These bytes are unique. So `P = |V|·m_j·u` is fixed:
   `m_j` is two public bytes, and `m = 0` on padded channels.
4. **Rounding chain, `l < 0`, `K = −l`.**
   - The chain gives `P + 2^(K−1) = Ymag·2^K + ρ`, with `ρ ∈ [0, 2^K)`: byte
     limbs plus a top limb of `K − 8(⌈K/8⌉ − 1)` bits.
   - So `Ymag = floor((P + 2^(K−1))/2^K) = R(P/2^K)`, which is unique.
   - If `K > bits(Pmax) + 1`, every admissible `P < 2^(K−1)`, so `R = 0`. The
     relation `Ymag = 0` replaces the chain.
5. **Rounding chain, `l ≥ 0`.**
   - The chain gives `Ymag' = P·256^⌊l/8⌋`.
   - The output identity scales by `2^(l mod 8)`, so `|Y| = P·2^l` exactly.
6. **Output.**
   - `Y = μ·(1 − 2τ)·2^(l≥0 ? l mod 8 : 0)·Ymag`. This is `sign(V)·R(|V|·m·u·2^l)`,
     the executor's `scaled_sum` value. When `V = 0` the free `τ` multiplies
     `Ymag = 0`.
   - The signed-16 range on `Y` matches the executor's int16 rejection, including
     `+32768`.
   - On padding, `μ = 0` gives `Y = 0`.

The auxiliary columns `τ` (at `V = 0`) and the carries are not unique. No output
depends on them. ∎

## Near-miss tests (RFC-0026 §5.2)

`crates/stele-reductions/src/development/tests.rs` re-derives every auxiliary
column from the tampered output, using the module's own `assign`. This is the
strongest auxiliary assignment available. Each case:

| Output | Tests |
|---|---|
| codes | `rejects_code_off_by_one` (±1, every policy); `rejects_code_other_rounding_direction` (ties 1.5 → 1 and −1.5 → −1, floor vs half-away) |
| scale | `rejects_scale_off_by_one_with_consistent_codes`, with codes recomputed under the wrong scale; `rejects_ceiling_near_miss_at_multiples_of_127` (M = 381 → 3 not 4; M = 382 → 4 not 3, rejected by the ceiling lookup) |
| zero row | `rejects_zero_row_branch_near_misses`: zero row with s = 1; z cleared; z set on a nonzero row; nonzero code with z = 1 |
| Y | `rejects_projection_output_off_by_one_and_other_rounding` (±1 and toward-zero, every policy); `rejects_projection_tie_rounded_toward_zero` (±1.5); `accepts_extreme_shifts_and_rejects_their_near_misses` (l = −200, l = 300) |
| padding | `rejects_nonzero_padding`, plus garbage on a padded input lane being ignored |

## Known limits (rejected with `Unsupported`, never accepted unsoundly)

- Gated rows over `2^30` and grouped gated scale folds belong to E16-08.
- A15 digit rows at `d = 16384` exceed the 30-bit width of the matmul output.
- A projection domain `t + log o + log d > 30` needs the plan-fixed row-block
  split. A row-block matmul must read a fixed slice of the code column, which the
  current `Ref` (an injective variable map) cannot express.

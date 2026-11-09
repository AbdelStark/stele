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
     When `s = 0`, `a = 0`, so `q = 0`. The RFC-0026 pattern's `z·q = 0` is
     therefore implied, and the module does not declare it (the review of #307
     found it and `z·M = 0` backing each other up).
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
5. **Rounding chain, `l ≥ 0`.** A plan shift above 16 is clamped to 16: every
   `P ≥ 1` then leaves int16 either way, and `P = 0` stays 0.
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

The tests forge each wrong output the way an attacker would. The witness is a
`Step` dataflow (`row::Step`, `projection::Step`): every step solves its own
defining relation from earlier values. A test lies at one step, then completes
every later step from the lie, so all other relations are satisfied wherever they
can be. The checker must still reject.

| Output | Tests |
|---|---|
| codes | `rejects_code_near_misses`: `q ± 1` with the code completed; `β` flipped (the other rounding direction, including the ties 1.5 and −1.5); the code ±1; every policy and every real lane |
| scale | `rejects_scale_near_misses`: `s ± 1` with every later step (codes included) recomputed; the ceiling at `M = 381 = 127·3` (3, not 4) and `M = 382` (4, not 3), rejected by the slack lookup |
| zero row | `rejects_zero_row_branch_near_misses`: a zero row with `s = 1`; `z` cleared; `z` set on a nonzero row; a nonzero code on a zero row |
| Y | `rejects_projection_output_near_misses`: `\|Y\| ± 1` with the remainder limbs and `Y` completed; `Y ± 1`; the ±1.5 ties rounded toward zero |
| padding | `rejects_nonzero_padding`, plus garbage on a padded input lane being ignored |

## Mutation survey (review of PR #307)

`stele_ir::relation::check_except(relation, values, skip)` is a test aid. It runs
the full `validate`, then evaluates every constraint except the named ones.

For every constraint the modules declare, `survey_row_conversion_constraints` and
`survey_projection_constraints` delete that constraint alone. They then search
for a forged, in-range witness that `check` rejects and `check_except(.., [name])`
accepts. The candidates are:
- a lie at any step, by an offset or a borrow between limbs, completed
  downstream;
- the same lie with one later step kept honest (the deleted constraint's own
  column);
- carries re-solved around a deleted chain position;
- attacker completions that change two columns at once:
  - `|Y| ± 1` absorbed by one remainder limb;
  - `τ` flipped, with `|V|` carried by one byte;
- inputs the executor rejects (a static row whose code would be ±128, a code that
  overflows the int16 output), completed honestly.

A constraint is **killed** when the accepted forgery changes an output (codes,
scale, `Y`) or is accepted on an input the executor rejects. Otherwise it must
carry a written reason, and the test fails on any unexplained survivor.

The cases are:
- rows `[300,−7,150,0,3,−150]`, a zero row, `[381,1,−382,254,−127,128]`,
  `[509,−500,…]` and the int16 extremes, under dynamic, grouped `g = 2` and
  static `s = 5` (with an overflowing input);
- projections under dynamic, grouped and static policies at their tightest
  right shift; `l = −200` (vanishing); `l = 9`; and exact ties `P = 2^(K−1)`
  with 2 and 4 lanes, both per-row and grouped.

Result: 71 constraints in total.
- 43 are killed.
- 15 chain-carry ranges are redundant over Z. Each is fixed by its position
  identities; the range exists for the bound rule mod p.
- 13 are redundant or output-neutral, with the reasons below.
- Pairs that back each other up are listed explicitly:
  - `L0/row/magnitude/range` and `L0/row/floor/range` each imply the other's lower
    bound;
  - the RFC pattern's `z·q = 0` was dropped because the division and the half bit
    imply it.

| constraint | result |
|---|---|
| `L0/q/byte/0/range` | killed: sign[0] flipped, \|V\| carried by byte 0 |
| `L0/q/byte/1/range` | killed: Sign[0][0] +1 |
| `L0/q/byte/2/range` | killed: Sign[0][0] +1 |
| `L0/q/byte/3/range` | killed: Sign[0][0] +1 |
| `L0/q/digit/0/range` | auxiliary only (Digits[0][0] borrow); output-neutral: the fold fixes b0 + 256 b1 = q*s, and V = C_0 + 256 C_1 = sum (b0 + 256 b1) w depends only on that sum; the ranges bound the matmul outputs for the bound rule mod p |
| `L0/q/digit/1/range` | redundant: output-neutral: the fold fixes b0 + 256 b1 = q*s, and V = C_0 + 256 C_1 = sum (b0 + 256 b1) w depends only on that sum; the ranges bound the matmul outputs for the bound rule mod p |
| `L0/q/fold` | killed: Digits[0][0] +1 |
| `L0/q/magnitude/range` | redundant: implied: the rounding chain gives Ymag = floor((P + 2^(K-1))/2^K) >= 0 (or Ymag' = P*256^(l/8) >= 0) exactly, and \|Y\| = f*Ymag <= 32768 by the output range |
| `L0/q/output` | killed: Output[0][0] +1 |
| `L0/q/output/range` | killed: input code[12] = 127, which the executor rejects |
| `L0/q/remainder/0/range` | killed: Magnitude[0] -1, remainder limb 0 absorbs it |
| `L0/q/remainder/1/range` | killed: Magnitude[0] -1, remainder limb 1 absorbs it |
| `L0/q/remainder/2/range` | killed: Magnitude[0][0] +1 |
| `L0/q/round/0` | killed: Magnitude[0][0] -1, Remainder kept |
| `L0/q/round/1` | killed: Magnitude[0][0] +1, Remainder kept |
| `L0/q/round/2` | killed: Magnitude[0][0] +1, Remainder kept |
| `L0/q/round/3` | killed: Magnitude[0][0] +1, Remainder kept |
| `L0/q/round/4` | killed: Magnitude[0][0] +256, Remainder kept |
| `L0/q/scale` | killed: ScaleBytes[0][0] +1 |
| `L0/q/scale/0/range` | auxiliary only (ScaleBytes[0][1] borrow); scale byte range: s = sum 256^c s_c is fixed by the scale identity; only the byte representation moves, never the product sum |
| `L0/q/scale/1/range` | redundant: scale byte range: s = sum 256^c s_c is fixed by the scale identity; only the byte representation moves, never the product sum |
| `L0/q/sign/0` | killed: Bytes[0][4] +1 |
| `L0/q/sign/1` | killed: Bytes[1][0] +1 |
| `L0/q/sign/2` | killed: Bytes[2][0] +1 |
| `L0/q/sign/3` | killed: Bytes[3][1] +1 |
| `L0/q/sign/range` | killed: Sign[0][4] -1 |
| `L0/q/sum/0` | killed: Sums[0][0] +255 |
| `L0/q/sum/1` | killed: Sums[1][0] +1 |
| `L0/q/vanishing` | killed: Magnitude[0][0] +1 |
| `L0/q/weight/range` | redundant: committed model data, never prover-chosen (RFC-0026 §2.2); kept for the bound rule |
| `L0/row/attained` | killed: Maximum[0] +127, Hit kept |
| `L0/row/attained/one-hot` | killed: Maximum[0] +127 |
| `L0/row/ceiling` | killed: Scale[0] +1, Slack kept |
| `L0/row/code` | killed: Code[0] +1 |
| `L0/row/codes/range` | redundant: implied: c = (1 - 2 sigma) q with sigma in {0,1} and q in [0,127] |
| `L0/row/division` | killed: Remainder[0] +2 |
| `L0/row/floor/range` | redundant: implied: q0 = q - beta <= 127 (quotient range) and q0 > -1 (a >= 0, rho < D) |
| `L0/row/gap` | killed: Maximum[0] +127, Gap kept |
| `L0/row/gap/range` | killed: Maximum[2] -1 |
| `L0/row/half` | killed: Half[0] +1, HalfGap kept |
| `L0/row/half/range` | killed: Half[0] -1 |
| `L0/row/half_gap/range` | killed: Half[0] +1 |
| `L0/row/hit/range` | redundant: implied for M: sum h = 1 forces a lane with h != 0, where h*gap = 0 makes M attained, whatever integers h holds |
| `L0/row/magnitude/range` | redundant: implied: a = q0*D + rho with q0 >= 0, D >= 1, rho >= 0 (floor, spare, remainder) |
| `L0/row/maximum/range` | redundant: implied: M = a_j at a lane with h_j != 0 (attained, one-hot) and a <= 32768 |
| `L0/row/quotient` | killed: Quotient[0] +1 |
| `L0/row/quotient/range` | killed: input x = -638, which the executor rejects |
| `L0/row/remainder/range` | killed: Floor[0] +1 |
| `L0/row/scale/range` | redundant: implied: 127 s = M + slack <= 32768 + 126 (ceiling, slack lookup, maximum) |
| `L0/row/sign` | killed: Magnitude[0] +2 |
| `L0/row/sign/range` | killed: Sign[2] -1 |
| `L0/row/slack/range` | killed: Scale[0] +1 |
| `L0/row/spare` | killed: Zero[1] -1, Spare kept |
| `L0/row/spare/range` | killed: Zero[1] -1 |
| `L0/row/zero` | killed: Zero[0] +1 |
| `L0/row/zero/range` | auxiliary only (Zero[1] +1); output-neutral: z matters only where M = 0, where a = 0 gives q = 0 for every divisor s + z >= 1 |
| chain carry ranges (15: `L0/q/sign/carry*`, `L0/q/round/carry*`) | redundant: each carry is fixed by its position identities (chain lemma); the range keeps every position wrap-free mod p (bound rule), which the integer checker cannot exercise |

## Known limits (rejected with `Unsupported`, never accepted unsoundly)

Each limit has an owner in `agents/tasks/graph.yaml`.

- **Gated row conversion (RFC-0004 A8).** Owned by E16-08 (PR #305), which reads
  this module's `RowOutput`. That includes grouped gated folds, which the
  projection rejects with `Unsupported::Policy`.
- **Projection domains over 30 bits** (`log T + log o + log d > 30`). These need
  the plan-fixed row-block split (per-block outputs plus a mask identity, as #308
  does). Owned by E16-10. `Projection::new` returns `Unsupported::Domain`.
- **A15 digit rows at padded `d = 16384`.** The worst case `2^14·256·128` exceeds
  the 30-bit width of the matmul output; three digit rows are needed. Owned by
  E16-10.

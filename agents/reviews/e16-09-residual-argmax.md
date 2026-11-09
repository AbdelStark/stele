# E16-09 residual add, model boundary and greedy argmax: output-uniqueness lemmas and review notes

**Scope.** `stele_reductions::residual::Residual` (RFC-0026 §5 row 11) and
`stele_reductions::argmax::Argmax` (row 13) and `stele_reductions::finish::Finish`
(row 12 with row 13), §5.2 obligations, on branch `task/E16-09-residual-head-argmax`.
Same-author notes; the proof engine (E16-02) is out of scope.

## Residual add (row 11)

`out = R((X·2^(c−fx) + Y·2^(c−fy))/2^(c−fo))`, `c = max(fx, fy, fo)`, fractions in
`[0, 30]`, int16 inputs and output, `R` half away from zero (RFC-0025 §2.2;
`numerics::scaled_sum` with divisor 1). Wide (RFC-0004 A14) streams are outside
RFC-0026 §1.3 and are not declared.

**Normal form.** One of `c−fx`, `c−fy`, `c−fo` is 0. Let `F` be the input with the
smaller shift `m`, `G` the other one, `e` the difference, `k = c − fo`. Then
`N = 2^m·(F + G·2^e)` and `m > 0` only when `k = 0`, so
`out = 2^m·R((F + G·2^e)/2^k)`. `N` reaches 46 bits; it is never held whole.

**Narrow copy.** When a single identity would hold `G·2^e'` with
`2^15·2^e'` too large for §3.6, it holds a witness `G'` with the identity `G' = G`
(bound `2^16`) and the range `signed(w)`: `w = clamp(17 − e, 1, 16)` when `k = 0`,
`w = clamp(31 − e', 1, 16)` when `k > 0`. Every assignment of the other relations
bounds `|G·2^e'|` below `2^16` (`k = 0`: `G·2^e = S − F`, `|S|, |F| <= 2^15`) or
below `2^30` (`k > 0`: `G·2^e' = (out − β)·2^k2 + L − F_h − κ` with
`|out − β| <= 2^15 + 1`, `k2 <= 14`), so `G ∈ signed(w)` whenever any satisfying
assignment exists. A narrow copy never rejects an executor value that is in range.

### Relations

| Case | Identities |
|---|---|
| `k = 0` | `numerator S = F + 2^e·G'`; `scale out = 2^m·S` when `m > 0` (`S` is `out` when `m = 0`, `S ∈ signed(max(1, 16−m))`) |
| `k > 0`, stage 1 (`s = k − 14 > 0`) | `first F = 2^s·F_h + F_l`; when `e < s`: `second G = 2^(s−e)·G_h + G_l`, `carry_sum F_l + 2^e·G_l = 2^s·κ + ρ`; `sticky_zero ρ − st·ρ = 0`; `sticky_gap ζ = st·ρ − st` (`ρ` is `F_l` when `e >= s`) |
| `k > 0`, stage 2 | `numerator T − 2^k2·(out − β) − L = 0` with `T = F_h + (2^(e−s)·G' or G_h + κ)` (`T = F + 2^e·G'` when `s = 0`); `round tie = (2β−1)(2L + st − 2^k2 − ν) − (1−β)`; `sign tc = out − β + 2^16·ν` |
| all | `copy G' = G` when declared; `pad mask·out = 0` when lanes are padded |

Every witness has one range with its declared width: `out` signed 16; `F_h`
signed `max(1, 16−s)`; `F_l`, `ρ`, `ζ` unsigned `s`; `G_h` signed `max(1, 16−j)`,
`G_l` unsigned `j` (`j = s − e`); `κ`, `st`, `β`, `ν` unsigned 1; `L` unsigned `k2`;
`tc` unsigned 16; `tie` unsigned `k2 + 1`. `s <= 16`, `k2 <= 14`, so every range is
at most 16 bits. `accepts_static_validity_every_fraction_triple` validates all
`31^3` fraction triples.

### Lemma (output uniqueness)

*For inputs `X`, `Y` in signed 16 (padding 0), every assignment satisfying the
relations has `out = R(N/2^(c−fo))` on every real entry and `out = 0` on padding. If
that value is outside int16 (the executor returns `Range`), no assignment exists.*

Proof. All relations hold over Z (§3.6: bounds below `p`, every column disciplined).

- `k = 0`: `S = F + G·2^e` and `out = 2^m·S = N`; `R(N/1) = N`.
- `k > 0`, stage 1 (`s > 0`): `F = 2^s·F_h + F_l` with `F_l ∈ [0, 2^s)` is Euclidean
  division, so `F_h, F_l` are unique; likewise `G_h, G_l`. Then
  `F_l + 2^e·G_l ∈ [0, 2^(s+1))`, so `κ ∈ {0,1}` and `ρ ∈ [0, 2^s)` are unique, and
  `N = T·2^s + ρ`: `T = floor(N/2^s)`, `ρ = N mod 2^s`. `sticky_zero` forces `st = 1` when
  `ρ > 0`; `sticky_gap` gives `ζ = −st >= 0` when `ρ = 0`, so `st = 0`. So `st = [ρ ≠ 0]`.
  With `s = 0`: `T = N`, `st = 0`.
- Stage 2: `T = (out − β)·D2 + L`, `L ∈ [0, D2)` is Euclidean, so `H := out − β =
  floor(T/D2) = floor(N/2^k)` and `L` are unique. `H ∈ [−2^15 − 1, 2^15)` and
  `tc = H + 2^16·ν ∈ [0, 2^16)` force `ν = [H < 0]`. `tie >= 0` forces
  `β = [2L + st >= D2 + ν]`.
- Rounding: `N mod 2^k = L·2^s + ρ`. If `L > D2/2` both sides of
  `β = [N mod 2^k >= 2^(k−1) + ν]` are 1; if `L < D2/2` both are 0; if `L = D2/2`
  both reduce to `ρ >= ν`, that is `st >= ν`. With `D = 2^k`, `N/D = H + (N mod D)/D`:
  for `H >= 0` (`N >= 0`) `R` rounds up exactly when the remainder is at least `D/2`;
  for `H < 0` it rounds toward `H + 1` exactly when the remainder exceeds `D/2`
  (ties go away from zero, to `H`). Both are `β = [N mod D >= D/2 + ν]`, so
  `out = H + β = R(N/D)`, the executor's value, and `out` is unique.
- `out ∈ signed 16` by its range, so an overflowing executor value has no assignment.
- Padding (padded lanes and, when `T` is not a power of two, padded token rows):
  inputs 0 give `out = 0`, and `pad` pins it independently of the inputs.

Every auxiliary column is determined above, so the whole assignment is unique.

## Model boundary (row 12)

`Finish` declares no relation. In plan order it declares E16-04's `RmsNorm` on
`R_L` (scope `G/norm`), E16-05's `RowConversion` on the norm output (`G/row`) under
the Model's final policy, E16-05's `Projection` on that row (`G/head`, shift
`e − f + fl`, unbiased; its own head source, or the embedding column when tied), and
`Argmax` on the head output. **Lemma:** for `R_L` in signed 16, the outputs are unique
and equal `Executor::finish`'s, by the RmsNorm lemma (E16-04), lemmas R and P (E16-05)
and the argmax lemma below, composed along RFC-0026 §5.1; the deletion surveys of
those modules cover every constraint `Finish` declares. Tests: every power-of-two
family-1 fixture's boundary from `Executor::capture` passes; any other claimed id
on any row, and one moved logit, are rejected; T = 64, d = 512, V = 256 validates.
`Finish::new` rejects a token count that is not a power of two or differs from the
norm or head row count. A tied head reads the E16-04 `Embedding` module's `E` source
(V×d, untransposed) and declares no weight; validate and check pass on a fixture
with executor-equivalent tied logits.

## Greedy argmax (row 13)

Plan data: `T` tokens, checked `[r, e)`, `y` exactly when `e = T`, vocabulary `V`.
`Argmax::new` rejects a malformed range, a missing or extra `y`, and any checked token
`c_i >= V` (a padded id is never a statement). Columns on the logits layout `(i, v)`,
`v` padded to `2^nv`:

| Column | Kind | Width | Discipline |
|---|---|---|---|
| `L` logits (head output) | witness, upstream | signed 16 | upstream |
| `O` onehot, `lt` below | public `T×2^nv` | unsigned 1 | — |
| `row` (checked rows), `real` (`v < V`), `ones` | public | unsigned 1 | — |
| `sel` selected (T) | witness | signed 16 | range |
| `sel_b` blocks (`T×2^nb`, only when `nv > 15`) | witness | signed 16 | range |
| `Mg` margin (`T×2^nv`) | witness | unsigned 16 | range |

`chk[i,v] = row[i]·real[v]` is the RFC's public `chk`, held as two broadcast factors
so no third `T×V` public column exists.

Relations:

1. **M select** `sel_b[i,b] = Σ_{v_low} O[i,b,v_low]·L[i,b,v_low]` over `2^vb`,
   `vb = min(nv, 15)` summed ids. Bound `2^15 + 2^15·2^15 < p`. With `nv <= 15` the
   output is `sel` directly.
2. **M block_sum** (`nv > 15`) `sel[i] = Σ_b sel_b[i,b]·1`, `nb = nv − 15 <= 15`.
3. **I greedy** `Mg − row·real·sel + row·real·L + lt = 0`. Bound `2^16 + 2^16 + 1`.
4. **R** on `sel`, `sel_b`, `Mg`.

### Lemma

*For `L` in signed 16, the relations are satisfiable iff for every checked `i`, `c_i`
is the least real id attaining `max_{v<V} L[i,v]`; then `sel`, `sel_b`, `Mg` are
unique.*

Proof. Matmuls are exact over Z (bounds below `p`, ranged operands and outputs).
`O[i,·]` is the one-hot of `c_i` on a checked row and 0 elsewhere, so
`sel_b[i,b] = L[i,c_i]` for the block of `c_i` and 0 otherwise, and
`sel_i = L[i,c_i]` (0 on unchecked rows). `greedy` fixes `Mg` uniquely. On an
unchecked row or padded id `chk = lt = 0`, so `Mg = 0`. On a checked row and real `v`,
`Mg = sel_i − L[i,v] − [v < c_i] ∈ [−65536, 65535]`, and the range demands `Mg >= 0`:
for `v >= c_i` that is `L[i,v] <= L[i,c_i]`, for `v < c_i` it is `L[i,v] < L[i,c_i]`.
Together: `L[i,c_i]` is the row maximum and no smaller id attains it. Conversely the
greedy choice gives `Mg ∈ [0, 65535]`. Padded logits never enter: `chk = 0` there and
`c_i < V`.

## Near-miss, deletion survey and executor evidence

- **Executor capture.** `matches_executor_capture_fixtures` (both modules) runs
  `Executor::capture` on every successful family-1 version-1 case of the stele-cqis
  `model-execution` fixtures. Every residual add of every layer (inputs, fractions
  and quotients from `Block::mid` / `Block::residual`) passes `check`, its outputs
  chain into the next cut, and quotient ±1 with the strongest re-solved rounding
  columns is rejected. The head's logits (`Head::logits`) with the recorded
  `Head::argmax` pass on the full checked range; every other id on every row is
  rejected.
- **Near misses.** Residual: output ±1 on every shape branch for each `(β, ν)`;
  the other rounding direction at exact ties (one- and two-stage); a sticky-bit lie
  just past a negative tie; nonzero padding. Argmax: a non-maximal token, a later
  index among ties, a padded id (statement rejected), a nonzero margin on an
  unchecked row; an unchecked row's token is free.
- **Deletion survey** (`rejects_each_constraint_removed`). Attack witnesses are
  built as an attacker would: start from the honest assignment, move the targeted
  values inside their widths, and complete every other relation from the values as
  they then stand (`respond`, and for ranges a search over in-identity alternatives:
  Euclidean splits moved by whole multiples, carry/sticky/gap from their identities,
  every `(H, β, ν)` near the honest one with `L`, `out`, `tc`, `tie` from theirs).
  For each constraint name the test requires a witness that `check` rejects and that
  breaks that constraint alone (so `check_except([name])` accepts it), or a stated
  reason it is redundant over Z, with no survivor left unexplained; a constraint
  listed redundant must never break alone. Uses `stele_ir::relation::check_except`. Residual scenarios:
  `(12,8,9)` one stage; `(0,30,14)` two stages, narrow copy, swapped inputs;
  `(30,28,13)` split `G`; `(8,8,12)` exact with `m > 0`; `(0,16,30)` exact with a
  1-bit narrow copy; `(16,0,0)` two stages at ties; `(23,0,5)` the Llama fixture's
  first add; plus one overflowing executor entry per shape. Argmax at `V = 8` and
  `V = 40000` (blocks).

| Constraint | Kind | Witness breaking it alone, or reason it is redundant over Z |
|---|---|---|
| residual `numerator` | I | `out + 1`, `tc + 1` (`k > 0`); `S + 1`, `out + 2^m` or `out + 1` (`k = 0`) |
| residual `round` | I | `β` flipped, `out` moved with it, `tie = 0` |
| residual `sign` | I | `ν` flipped, `β`/`tie` completed, `tc` kept |
| residual `scale` | I | `out + 1`, `S` kept |
| residual `copy` | I | `G ± 1` with `G'` kept; `G' ± 1` with stage 2 completed |
| residual `first` | I | `F_h ± 1`, stage 2 completed |
| residual `second` | I | `G_h ± 1`, stage 2 completed |
| residual `carry_sum` | I | `κ` flipped, stage 2 completed |
| residual `sticky_zero` | I | `st = 0` with `ρ > 0`, `ζ = 0`, stage 2 completed |
| residual `sticky_gap` | I | `st = 1` with `ρ = 0`, `ζ = 0`, stage 2 completed |
| residual `pad` | I | nonzero input on a padding lane, every column completed, `out ≠ 0` |
| residual `out` | R | an overflowing executor entry (`2^15 <= |out| < 2^16`), all identities hold. Redundant when `k = 0, m > 0` (`out = 2^m·S`, `S ∈ signed(16−m)`) and in shapes where no int16 input overflows (every other relation forces the executor value) |
| residual `low`, `half`, `twos`, `tie` | R | search witness (e.g. `β = 2` with `out = H + 2`; `ν = 1` with `H >= 0`) |
| residual `first_low`, `second_low`, `rest`, `sticky`, `gap` | R | search witness (`F_l + 2^s`; `ρ = 2^s` with `ζ = 2^s − 1`; `st = −1` at `ρ = 0`; `st = 1`, `ζ = −1`) |
| residual `negative` | R | redundant: `ν = (tc − out + β)/2^16` with `tc ∈ u16`, `out ∈ s16`, `β ∈ u1` |
| residual `narrow` | R | redundant: outside `signed(w)`, `|G'·2^e'| >= 2^30` (`2^16` when `k = 0`) puts `out`, `tc` or `S` out of range |
| residual `scaled` | R | redundant: `out = 2^m·S`, `out ∈ s16` |
| residual `first_high`, `second_high` | R | redundant: the input is int16 and the low part is ranged |
| residual `carry` | R | redundant: `2^s·κ = F_l + 2^e·G_l − ρ ∈ (−2^s, 2^(s+1))` |
| argmax `greedy` | I | false claim with every margin clamped into `[0, 65535]` |
| argmax `select` | M | false claim, `sel` and its block raised to the row maximum, margins completed |
| argmax `block_sum` | M | false claim, `sel` raised, `sel_b` kept |
| argmax `margin` | R | false claim with the honest-formula margin (`−1` at the earlier maximum) |
| argmax `selected`, `blocks` | R | redundant: a one-hot row times int16 logits is one logit or 0 |

Every redundant range is still required: it disciplines its column (RFC-0026 §3.6
item 3), which is what makes the bound rule of each identity reading it hold in M31.
Over Z alone it is implied; in the field a column outside its width could wrap.

A source-level deletion campaign (each identity, matmul and range removed in
`declare` in turn, then the module's tests run) is recorded in the PR body.

## Widen-by-one-bit pass (in `rejects_each_constraint_removed`)
Each module range is widened by one bit:
- a signed width `w` becomes `signed(w+1)`;
- an unsigned width `u(w)` is tried as both `u(w+1)` and `signed(w+1)`.

A 17-bit `Range` is not valid (RFC-0026 §3.4), so the widened range is evaluated over Z. The pass uses `check_except` to skip that range, then checks the column against the wider width. It searches the same in-identity alternatives as the deletion survey.

Each (range, widening) must have one of:
- a witness that the true relation rejects, the widened one accepts, and that changes `out` at its entry (for `out`, an executor overflow) or makes a false argmax claim pass;
- a written reason it is safe. A reason must never coexist with a found witness in any shape.

| Range | Widening | Witness, or why it is safe |
|---|---|---|
| residual `out` | s17 | an overflowing executor entry |
| residual `low` (L) | u+1, s+1 | witness (`L ± D2` with `H ∓ 1`, rounding moved) |
| residual `half` (β) | u2, s2 | witness (`β = 2` or `−1`, `out` moved) |
| residual `twos` | u17, s17 | witness (`ν` against the sign at an exact tie) |
| residual `tie` | s+1 | witness (negative `tie`, other rounding direction) |
| residual `tie` | u+1 | safe: only the sign of `tie` matters; with `L, st, ν, β` in range `tie <= D2 < 2^(k2+1)` |
| residual `negative` (ν) | u2, s2 | safe: `tc = out − β + 2^16·ν ∈ [0, 2^16)` with `|out − β| <= 2^15 + 1` forces `ν ∈ {0, 1}` |
| residual `first_low` | u+1 | witness: `F_l = 2^s`, `F_h − 1`, `st = 1` at an exact positive tie with `ρ = 0` (scenario `(16,2,0)`, `X = 0, Y = 2`): `out` 1 → 0 |
| residual `first_low` | s+1 | safe: when `F_l` is `ρ`, `st = 1` and `gap = F_l − 1 < 0`; otherwise `κ − 1` absorbs `−2^s` and `T` is unchanged |
| residual `rest` (ρ) | u+1 | witness: `ρ = 2^s`, `κ − 1`, `st = 1` at an exact positive tie (scenario `(30,28,13)`, `X = 32764, Y = 8193`) |
| residual `rest` | s+1 | safe: `ρ < 0` forces `st = 1`, then `gap = ρ − 1 < 0` |
| residual `sticky` | s2 | witness: `st = −1` at an exact positive tie with `ρ = 0`: `out` rounds toward zero |
| residual `sticky` | u2 | safe: `st >= 2` forces `ρ = 0`, then `gap = −st < 0` |
| residual `gap` | s+1 | witness: `st = 1`, `gap = −1` with `ρ = 0` at an exact negative tie: `out` rounds toward zero |
| residual `gap` | u+1 | safe: in range, `gap = st·(ρ − 1) <= 2^s − 2` |
| residual `second_low` | u+1, s+1 | safe: moving `2^j` between `G_h` and `G_l` moves `±2^s` through `carry_sum`; `κ` absorbs it, so `T = F_h + G_h + κ` is unchanged, or `ρ` leaves its range |
| residual `carry` (κ) | u2, s2 | safe: `F_l + 2^e·G_l ∈ [0, 2^(s+1))` with `ρ ∈ [0, 2^s)` leaves only `κ ∈ {0, 1}` |
| residual `first_high`, `second_high` | s+1 | safe: `F_h = floor(F/2^s)` for `F ∈ s16` and `F_l ∈ u(s)`, already inside `signed(16 − s)` |
| residual `narrow` | s+1 | safe over Z: the copy forces `G' = G`; outside `signed(w)`, `|G·2^e'| >= 2^30` (`2^16` if `k = 0`) puts `out`, `tc` or `S` out of range. The width exists for the §3.6 bound |
| residual `scaled` | s+1 | safe: `out = 2^m·S`, `out ∈ s16` |
| argmax `margin` | s17 | witness: a false claim (`Mg = −1` at the earlier maximum) is accepted |
| argmax `margin` | u17 | safe: `Mg <= 65535` for int16 logits; only `Mg >= 0` carries the check |
| argmax `selected`, `blocks` | s17 | safe: an exact matmul of a one-hot row and int16 logits is one logit or 0 |

## Open items

- The head matmul past `MAX_VARS` (`log T + log V + log d > 30`) is E16-10/E16-11's.

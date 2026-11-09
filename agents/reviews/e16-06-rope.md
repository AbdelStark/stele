# E16-06 RoPE module: output-uniqueness lemma and review notes

**Scope.** `stele_reductions::rope::Rope` (RFC-0026 §5 row 5, §5.2), on branch
`task/E16-06-rope`. Same-author notes; the proof engine (E16-02) is out of scope.

## Relation

One instance per rotated tensor (Q with `h` heads, K with `g` groups) of one layer.
All columns use the output layout `(t, head, i)`, each dimension padded to a power of
two, row index in the high bits; `n` is the total bit count and `d = log dh`.

| Column | Kind | Width | Discipline |
|---|---|---|---|
| `x` (input, E16-05 output) | witness, upstream | signed 16 | upstream |
| `out` (`Q'`/`K'`) | witness | signed 16 | range |
| `partner` `P` | witness | signed 16 | range |
| `low` `L` | witness | unsigned 14 | range |
| `half` `β`, `negative` `ν` | witness | unsigned 1 | range |
| `twos` `tc` | witness | unsigned 16 | range |
| `tie` `w` | witness | unsigned 14 | range |
| `perm` over `(i, i')` | public | unsigned 1 | — |
| `own_hi`, `partner_hi` | public | signed 15 | — |
| `own_one`, `partner_one` | public | unsigned 1 | — |

Public data, all from plan data only: `Rotation::coefficient(t, j)` for `t < T`,
`j < r/2`. For a pair `(left, right)` (layout 0: `(2j, 2j+1)`, layout 1: `(j, j+r/2)`)
the own coefficient is `c` on both sides; the partner coefficient is `−s` at `left`
and `s` at `right`. Unrotated channels `r <= i < dh` have own `2^14`, partner `0`.
Padding entries (`t >= T`, `head >= h`, `i >= dh`) have both coefficients `0`. Each
coefficient `v ∈ [−2^14, 2^14]` is split as `v = hi + one`, `hi = min(v, 2^14 − 1)`.
`perm[i][i'] = 1` exactly when `i < r` and `i'` is the partner channel of `i`.

Relations:

1. **M** `P(t,h,i) = Σ_{i'} x(t,h,i')·perm(i,i')`. Bound `2^15 + 2^d·2^15 < p`.
2. **I numerator** `x·own_hi + x·own_one + P·partner_hi + P·partner_one
   − 2^14·out + 2^14·β − L = 0`. Bound `3·2^29 + 2^16 + 2^15 − 1 < p`.
3. **I half** `w = (2β−1)(L − 2^13 − ν) − (1−β)`. Bound below `2^17`.
4. **I sign** `tc = out − β + 2^16·ν`. Bound below `2^18`.
5. **R** on every witness column with its declared width.

## Lemma (output uniqueness)

*For any `x` with entries in signed 16, every assignment satisfying relations 1–5
has `out(t,h,i) = R(N/2^14)` with `N = x(t,h,i)·a + x(t,h,p(i))·b` (the executor's
numerator), and `out = 0` on padding. In particular `out` is unique and equals
`Executor::rotate` wherever the executor does not return `Range`; where it does,
no assignment exists.*

Proof.

- By §3.6 every relation holds over Z, because all bounds above are below `p` and
  every column lies in its declared width.
- (1) `perm` is a 0/1 matrix with at most one 1 per row, so `P(t,h,i)` is the
  partner entry `x(t,h,p(i))` for `i < r` and 0 otherwise. `P` is unique.
- (2) Since `hi + one = v`, the first four terms sum to `N`, where `N = 0` on
  padding. So `N = H·2^14 + L` with `H := out − β`. With `0 <= L < 2^14` this is
  Euclidean division, so `H = floor(N/2^14)` and `L = N mod 2^14` are unique.
- (4) `out ∈ [−2^15, 2^15)` and `β ∈ {0,1}` give `H ∈ [−2^15 − 1, 2^15)`.
  `tc = H + 2^16·ν ∈ [0, 2^16)` then forces `ν = 1` exactly when `H < 0`.
- (3) `w >= 0` (range) means: if `β = 1` then `L >= 2^13 + ν`; if `β = 0` then
  `L <= 2^13 + ν − 1`. Exactly one `β` satisfies this: `β = [L >= 2^13 + ν]`.
- Rounding. If `N >= 0`, then `H >= 0`, `ν = 0` and
  `out = H + [L >= 2^13] = floor((N + 2^13)/2^14)`, which is round half away from
  zero. If `N < 0`, then `H < 0` and `ν = 1`. Write `|N| = (−H − 1)·2^14 + (2^14 − L)`
  when `L > 0`. Then `R(N/2^14) = −floor((|N| + 2^13)/2^14) = H + [L > 2^13]`,
  and for `L = 0`, `R = H`. Both equal `H + [L >= 2^13 + 1]`.
- So `out = R(N/2^14)`, and the `out` range rejects exactly the executor's `Range`
  overflow (`wide` in `execution.rs`). On padding `N = 0` gives `out = 0`.
- Auxiliary columns `H, L, ν, β, tc, w, P` are all unique too.

The rounding identity was also checked exhaustively in Python for
`N ∈ [−5·2^14, 5·2^14]`, over every `(out, β, ν)` with `out ∈ [−8, 8]`: exactly one
`out` survives, and it is `R(N/2^14)`.

## Interfaces (RFC-0026 §5.1)

- Input: the E16-05 projection output for Q (or K), int16, shape `(T, h, dh)` with
  each dimension padded to a power of two (equal to `(T, h·dh)` when `h` and `dh`
  are powers of two). Its producer pins padding to 0. The module's honest `P`
  assumes that; its soundness does not.
- Output: `RopeColumns::output`, int16, same layout, consumed by E16-07. Position
  `t` is row `t`, the absolute position in the prefill window.
- Group: `L{ℓ}/rope/{n}`, shared by Q and K when their lengths agree.

## RFC-0026 A1 (row 5 kinds)

Row 5 listed kinds `I, R, P`; RFC-0026 A1 amends it to `I, R, M, P`. This module also uses one **M** per tensor (the
`partner` gather against a public permutation) and commits `partner`. A pointwise
identity cannot read the paired channel. A `Ref` cannot fix or negate a bit, so
reading `i XOR 2^k` needs an extra domain bit, and even then only works for
`r/2` a power of two in split layout. The permutation matmul covers every layout,
rotary width and head width that the `Model` admits. It adds one sumcheck over
`d` bits per tensor and no new error kind: the M line of §6 already exists.

## Tests

- `matches_reference_*`: random rows (`|x| < 2^13`), extreme rows (int16 endpoints,
  including executor overflow, where `assign` fails), Llama-3.1-8B fixture rotation
  over 32 heads and 8 groups. Shapes cover full, partial, odd head count and
  non-power-of-two head width, both layouts, base/linear/llama3 and no rotation.
  The output matches the executor-equivalent reference, and `check` accepts.
- `near_misses` builds, for a tampered output, the strongest in-range assignments:
  every `β, ν ∈ {0, 1, 2}`; `L` either solving the numerator or kept honest; and
  `L`, `tc`, `tie` at their formula values clamped into their ranges. Each fails
  exactly the constraint whose value had to be clamped.
  `rejects_output_off_by_one`, `rejects_other_rounding_direction_at_ties` (both
  signs) and `rejects_nonzero_padding` use it.
- `rejects_flipped_half_at_tie`: `β` flipped with `L` kept and `tie = 0`.
  `rejects_half_outside_one_bit`: `β = 2` gives `out + 1`.
- `rejects_tampered_partner` (matmul), `rejects_wrong_pairing_and_position` (the
  other layout's, or the next position's, honest columns).
- `rejects_relation_without_each_constraint` deletes each identity and the matmul,
  and widens the `half` range. It asserts that some near miss is then admitted.

Mutation table: each constraint was deleted from `rope.rs` in turn and the tests run.

| Mutation | Tests that go red |
|---|---|
| delete `partner` matmul | `rejects_tampered_partner`, `rejects_relation_without_each_constraint` |
| delete `numerator` identity | `rejects_output_off_by_one`, `rejects_other_rounding_direction_at_ties`, `rejects_nonzero_padding`, `rejects_wrong_pairing_and_position`, `rejects_relation_without_each_constraint` |
| delete `half` identity | `rejects_flipped_half_at_tie`, `rejects_output_off_by_one`, `rejects_other_rounding_direction_at_ties`, `rejects_nonzero_padding`, `rejects_relation_without_each_constraint` |
| delete `sign` identity | `rejects_other_rounding_direction_at_ties` (negative tie), `rejects_relation_without_each_constraint` |
| `half` declared and ranged as unsigned 2 | `rejects_half_outside_one_bit`, `rejects_output_off_by_one`, `rejects_relation_without_each_constraint` |

- `accepts_static_validity_realistic_shapes`: Llama-3.1-8B Q/K (`dh = 128`, T = 64)
  and a `dh = 64` model validate.

Executor parity uses a restatement of `Executor::rotate`. Swap it for the E16-03
capture once that lands.

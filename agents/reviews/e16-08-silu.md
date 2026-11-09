# E16-08 SiLU gated product and gated row conversion: lemmas and review notes

**Scope.** `stele_reductions::silu::GatedProduct` and `GatedConversion` (RFC-0026 §5
row 10, the §5 gated-scale ceiling, §5.2), on branch `task/E16-08-silu`. Same-author
notes; the proof engine belongs to E16-02. RFC-0026 assigns row 10, including the gated
row conversion, to E16-08. The conversion reads this module's limbs and hands E16-05's
down `Projection` a `RowOutput`.

## Relation

One instance per layer. All columns use the layout `(t, j)`, `t < T`, `j < f`, each
dimension padded to a power of two, row index in the high bits. The domain has `n` bits.

| Column | Kind | Width | Discipline |
|---|---|---|---|
| `G`, `U` (gate, up; E16-05 outputs) | witness, upstream | signed 16 | upstream |
| `a = silu_q[G]` | witness | signed 16 | lookup (unselected) |
| `Ul`, `Uh` | witness | unsigned 8, signed 8 | range |
| `c` (low carry) | witness | signed 16 | range |
| `d`, `w` | witness | unsigned 8, unsigned 7 | range |
| `Th` (output high limb) | witness | signed 16 | range |
| `Tl` (output low limb) | witness | unsigned 15 | Compose of `d`, `w` |
| `mask` | public | unsigned 1 | — |

`mask` is 1 on real entries and 0 on padding. The table is the complete generated
`silu_q` component, `Table::generate(block.activation().components()[0])`: 65536 rows
`(t, silu_q[t])` with both columns signed 16. It is shared by every layer with the same
descriptor (`Relation::add_table` deduplicates).

Relations:

1. **L** `(G, a) ∈ silu_q`, no selector.
2. **Compose** `U = Ul + 2^8·Uh`. Bound `2^15 + 255 + 2^15 < p`.
3. **I low** `Ul·a·mask − 2^8·c − d = 0`. Bound `255·2^15 + 2^23 + 255 < 2^25`.
4. **I high** `Uh·a·mask + c − 2^7·Th − w = 0`. Bound `2^22 + 2^15 + 2^22 + 127 < 2^24`.
5. **Compose** `Tl = d + 2^8·w`. The composed range `[0, 2^15 − 1]` lies within unsigned 15.
6. **R** on `Ul, Uh, c, d, w, Th`.

The plain product `U·a` never appears whole. Its static magnitude is `2^30`, and so is
that of any representation of `T`, so a single identity would break the §3.6 bound.

## Interfaces (RFC-0026 §5.1)

- `GatedProduct` → `GatedConversion`: `GatedColumns { high, low }` on the `(T, f)`
  layout of `U`. `T = 2^15·high + low` over Z, exactly `U·silu_q[G]` (units `fu + E`);
  `high` signed 16 (range), `low` unsigned 15 (Compose); padding 0.
- `GatedConversion` → E16-05 down `Projection`: `RowOutput { codes, scale, log_rows,
  log_dimension, log_group = log_dimension, scale_bound = 8454661 }`. `codes` is signed 8
  on the same layout, and `scale` is unsigned 24, one per row, the Compose of its limbs.

## Lemma P (product output uniqueness)

*For any `G`, `U` with entries in signed 16, every assignment satisfying relations
1–6 has `2^15·Th + Tl = U·silu_q[G]` on real entries and `Th = Tl = 0` on padding.
All auxiliary columns are unique.*

**Padding.** The padding claim relies only on the public `mask`, not on the
producer pinning `U = 0` there: whatever `G` and `U` hold on padding, the masked
product terms vanish. Only the honest assignment (`a = silu_q[0]`, `Ul = Uh = 0`)
assumes the producer's zero padding. The lookup and the `up` Compose still constrain
padding entries; neither affects `T`.

**Totality.** `GatedProduct::new` rejects a table with an output outside
`(−2^15, 2^15)` (`silu_outputs`). So `|a| <= 2^15 − 1`, `|U·a| < 2^30`, and an
assignment exists for every int16 `G`, `U`. Generated `silu_q` tables satisfy this:
for `E <= F` their negative outputs stay above `−2^14` (SILU-CONSUMER), and `E > F`
fails generation.

Proof.

- By §3.6 every relation holds over Z: all bounds are below `p`, and every column
  lies in its declared width (range, lookup or Compose discipline).
- (1) The table has exactly one row per input `t`, so `a = silu_q[G]`.
- (2) With `Ul ∈ [0, 256)` and `Uh ∈ [−128, 128)`, `U = Ul + 256·Uh` is the
  Euclidean split: `Ul = U mod 256`, `Uh = floor(U/256)`.
- (3) On a real entry, `Ul·a = 256·c + d` with `d ∈ [0, 256)`. So
  `c = floor(Ul·a/256)` and `d = Ul·a mod 256`, both unique; `|c| <= 32640` fits.
  On padding the left term is 0, so `c = d = 0`.
- (4) `Uh·a·mask + c = 128·Th + w` with `w ∈ [0, 128)`. So `Th` and `w` are unique.
- (5) `Tl = d + 256·w`. Then `2^15·Th + Tl = 256·(128·Th + w) + d
  = 256·(Uh·a + c) + d = 256·Uh·a + Ul·a = U·a` on real entries. On padding,
  `128·Th + w = 0` with `w ∈ [0, 128)` gives `Th = w = 0`, so `Tl = 0`.
- The value `Th = floor(U·a/2^15)` lies in `[−2^15, 2^15)`, because `|U·a| < 2^30`
  (totality).

The honest split was also checked in Python on 200000 random pairs plus every endpoint
pair (`U ∈ {−32768, …, 32767}` endpoints, `a ∈ [−16383, 32767]` endpoints).

## Gated row conversion

Integer definition (RFC-0025 §2.5, RFC-0004 A8, flow §1;
`stele_cqis::row::Quantiser::convert_gated`, dynamic policy): per row,
`s = ceil(max|T|/127)` (at most `8454661`), and per lane
`q = floor((2|T| + s)/(2s))`, or 0 when `s = 0`; the code is `sign(T)·q`.

Columns. Lane `(t, j)`: `σ`, `κ`, `Al`, `Ah` (u15), `gl`, `gh` (u15), gap borrow `gb`,
hit `h`, `q` (u7), code (s8), `rl` (u15), `rh` (u10), carry `f` (s10), `pl` (u15),
`ph` (u10), carry `g` (s3). Row `t`: `Ml`, `Mh` (u15), `sl` (u15), `sh` (u9), `scale`
(u24, Compose), `slack` (u7, lookup), carry `e` (s8), `z` (u1). Public: `mask`, `one`,
the table `range/0..=126` (shared with E16-05).

Relations, each wrap-free (largest bound: `division/low`, below `2^25`):

| Name | Relation |
|---|---|
| `sign/low` | `mask·Tl − 2σ·mask·Tl − Al + 2^15·κ = 0` |
| `sign/high` | `mask·Th − 2σ·mask·Th − κ − Ah = 0` |
| `gap/low`, `gap/high` | `Ml − Al − gl + 2^15·gb = 0`, `Mh − Ah − gb − gh = 0` |
| `attained` | `h·gl + h·gh = 0` |
| `attained/one-hot` (M) | `Σ_j h(t, j) = 1` |
| `ceiling/low`, `ceiling/high` | `127·sl − Ml − slack − 2^15·e = 0`, `127·sh − Mh + e = 0` |
| `ceiling` (L) | `slack ∈ [0, 126]` |
| `scale` (Compose) | `scale = sl + 2^15·sh` |
| `zero` | `z·Ml + z·Mh = 0` |
| `division/low`, `division/high` | `2Al + sl + z − 2q·sl − 2q·z − rl − 2^15·f = 0`, `2Ah + sh − 2q·sh − rh + f = 0` |
| `spare/low`, `spare/high` | `2sl + 2z − 1 − rl − pl − 2^15·g = 0`, `2sh − rh − ph + g = 0` |
| `code` | `c − q + 2σ·q = 0` |

Each low/high pair sums (low + `2^15`·high) to one wide equation over Z:
`mask·T = (1 − 2σ)·A`; `M − A = gap >= 0`; `127·s − M = slack`; `2A + D − 2qD = r`;
`2D − 1 − r = p >= 0`, with `A, M, s, r, p, gap` the limb values and `D = s + z`.

## Lemma C (conversion output uniqueness)

*For `high` in signed 16 and `low` in unsigned 15, every assignment satisfying the
relations above has, on every real row, `scale = ceil(max|T|/127)` and codes equal to
the executor's; padded lanes have code 0 and padded rows scale 0.*

Proof.

- Sign/abs. On a real lane (`mask = 1`), `σ = 0` forces `κ = 0`, `Al = Tl`, `Ah = Th`,
  and `Ah >= 0` needs `T >= 0`. `σ = 1` forces `κ = [Tl > 0]`, `A = −T`, and `Ah >= 0`
  needs `T <= 0`. So `A = |T|`, with `σ` free only at `T = 0`. On padding, `A = 0`.
- Maximum. Every lane has `M − A >= 0`. The one-hot gives exactly one `h = 1` per row,
  and `attained` gives a zero gap there. So `M = max_j A_j`, and padded lanes
  (`A = 0`) never change it.
- Ceiling. `127·s − M ∈ [0, 126]` gives `s = ceil(M/127)`. The Compose gives
  `scale = s`.
- Zero row. `z·M = 0` (both limbs are nonnegative), so `M > 0` gives `z = 0` and `D = s`.
  If `M = 0` then `s = 0`. Then `0 <= r <= 2D − 1` needs `D >= 1`, so `z = 1`.
- Division. `0 <= 2A + D − 2qD <= 2D − 1` with `D >= 1` gives
  `q = floor((2A + D)/(2D))`, the executor's magnitude when `s > 0`. When `M = 0`,
  every `A = 0` and `q = floor(1/2) = 0`, the executor's zero branch.
- Code. `c = (1 − 2σ)·q` is `sign(T)·q`; at `T = 0`, `q = 0` for either `σ`.
- `q <= 127` never excludes an honest value, since `A <= M <= 127·s`. All auxiliary
  columns except `σ` at `T = 0` and the hit lane among equal maxima are unique.

Executor parity: `matches_executor_capture` converts the captured `gated` product
of every dynamic family-1 layer of the stele-cqis model-execution fixtures
(`Executor::capture`). It reproduces the captured `down_row` codes and scales.

Gap: only the dynamic per-row policy is supported. Static and grouped gated rows
return `Unsupported::Policy` (RFC-0026 §1.3 admits dynamic rows; grouped gated scale
folds need a plan that uses them).

### Deletion survey (conversion)

`rejects_relation_without_each_constraint` (in `silu/conversion/tests.rs`) builds one
hand-made, in-range attacker per constraint name, covering relations and ranges.
Each is a `Plan` with every other column derived from it, plus explicit cell patches.
The test asserts that `check` rejects the attacker and that
`check_except(.., [name])` accepts it.

The survey case is 3x8:
- row 0: `M = 127·2^15` and a runner-up `M − 1`;
- row 1: `M = 508 = 127·4`, attained at lanes 9 and 13, with a tie `6/4` at lane 8;
- row 2: all zero.

| Constraint | Attacker |
|---|---|
| `sign/low` | `A + 1` on a negative lane, downstream recomputed |
| `sign/high` | `A + 2^15` on that lane, now the row maximum, downstream recomputed |
| `gap/low`, `gap/high` | `M + 1`, `M + 2^15` with gaps kept from the honest `M` |
| `attained` | `M + 127`, `s + 1`, gaps from the new `M` (the hit lane has gap 127) |
| `attained/one-hot` | as above, with no hit lane |
| `ceiling/low`, `ceiling/high` | `s + 1` (honest slack and carry), `s + 2^15` |
| `ceiling` (lookup) | `s = 5`, slack 127 |
| `scale` (Compose) | `scale + 1`, limbs kept |
| `zero` | `z = 1` on a nonzero row, `D = s + 1` |
| `division/low`, `division/high` | `rl + 1, pl − 1` at the tie; `rh + 1, ph − 1` where `ph >= 1` |
| `spare/low`, `spare/high` | `pl + 1`, `ph + 1` |
| `code` | code + 1 |
| `sign/range` | `σ = 2` on a zero lane (`A = q = code = 0` for any `σ`) |
| `magnitude/low/range` | the row-0 maximum as `Al = 2^15`, `Ah = 126`, borrows and carry moved |
| `magnitude/high/range` | `σ = 1` on `T = 5`: `A = −5` (`Ah = −1`), `q = 0` |
| `gap/low/range` | the zero lane's gap as `gl = 2^15`, `gb = 1`, `gh − 1` |
| `gap/high/range` | `M` = the runner-up; the maximum lane's gap is −1 |
| `hit/range` | `h = 2` and `h = −1` on the two attained lanes |
| `remainder/low/range` | `rl + 2^15`, `rh − 1`, both carries moved |
| `remainder/high/range` | `q + 1`, so `r < 0` (code 1 instead of 0) |
| `spare/low/range` | `pl + 2^15`, `ph − 1`, spare carry moved |
| `spare/high/range` | `q − 1`, so the spare is negative (code 0 instead of 1) |
| `maximum/low/range` | row 1 as `Ml = M − 2^15`, `Mh = 1`, every gap borrow 1, ceiling carry + 1 |
| `scale/low/range` | row 0 (`s = 2^15`) as `sl = 2^15`, `sh = 0`, carries moved |
| `zero/range` | `z = 2` on the zero row (`D = 2`) |

Implied ranges. Each is still declared, because it is its column's range discipline
(§3.6):
- `borrow`, `gap/borrow`: the low identity puts the limb at `Tl(1 − 2σ) + 2^15·κ`
  (or `Ml − Al + 2^15·gb`). With the limb in `[0, 2^15)`, the borrow is fixed in
  `{0, 1}`.
- `quotient`, `codes`: `0 <= r <= 2D − 1` fixes `q = floor((2A + D)/(2D))`, and
  `A <= M <= 127·s` gives `q <= 127`. Then `c = (1 − 2σ)·q`.
- `remainder/carry`, `spare/carry`, `ceiling/carry`: each low identity with its
  ranged low limb (or `slack ∈ [0, 126]`) fixes the carry as a floor.
- `maximum/high`: at the hit lane `gl = gh = 0`. With `Ml >= 0`, that gives `gb = 0`
  and `Mh = Ah` in u15.
- `scale/high`: the ceiling fixes `s`, and `sl ∈ [0, 2^15)` then fixes
  `sh = (s − sl)/2^15 <= 258`.

### Widen-by-one-bit survey (conversion)

Each range is widened by one bit: every other constraint stays as declared, and the
column only has to fit the wider width.

| Range | Result one bit wider |
|---|---|
| `sign` u1 → u2 | **caught** (`rejects_code_through_widened_sign`): `σ = 2` on `T = −32668` takes `A = −3T`, giving code −9 instead of −1 |
| `magnitude/low`, `magnitude/high` | safe: the sign identities give `A = (1 − 2σ)·T` as a value, and `A >= 0` needs only the lower bounds; wider limbs are only non-canonical |
| `gap/low`, `gap/high` | safe: only `gap >= 0` (the lower bounds) is used |
| `maximum/low`, `maximum/high` | safe: `M = max A` follows from `gap >= 0` and `attained` as values |
| `scale/low`, `scale/high` | safe: the ceiling fixes `s` as a value |
| `remainder/low`, `remainder/high`, `spare/low`, `spare/high` | safe: `q` needs only `r >= 0` and `2D − 1 − r >= 0`, the lower bounds of nonnegative limbs |
| `quotient`, `codes` | safe: `q` and `c` are fixed by the division (above) |
| carries | safe: each is fixed as a floor by its low identity |
| `borrow`, `gap/borrow` | safe: a borrow of 2 puts the low limb at `>= 2^15 + 1` |
| `hit` u2 | safe: nonnegative `h` with `Σ h = 1` is still one-hot |
| `zero` u2 | safe: `z·M = 0` keeps `z > 0` to all-zero rows, whose codes are 0 |
| `slack` (lookup `0..=126`) | **caught**: one more value (127) admits `s + 1` when `127 | M` (the `ceiling` attacker: `M = 508`, `s = 5`), which changes every code of the row |

## Tests

- `matches_reference_*`: random and extreme rows (int16 endpoints, 0, ±1, ±2) for
  `silu_q` with `(F, E) ∈ {(8,8), (12,4), (14,14)}`, at shapes including `f = 1`,
  odd `T`, and `f = 100`. The Llama-3.1-8B fixture's block-0 SiLU uses `f = 14336`.
  `T` equals the executor product `U·silu_q[G]`, and `check` accepts.
- `rejects_product_near_misses`: at every entry, each of these fails one constraint:
  - `T ± 1` through `Tl` alone (`low` Compose);
  - `T ± 1` through `d`, with `c` honest (`low_product`) or with the best carry
    (`high_product`);
  - `T ± 2^8` and `T ± 2^15`, with `c`, `d` honest and `Th`, `w`, `Tl` recomputed
    (`high_product`, and the high limb `GatedConversion` consumes);
  - a forged split `Ul ± 1`, `Ul + 256·Uh ≠ U`, with every downstream limb
    recomputed (`up` Compose);
  - `a ± 1` with every limb recomputed (lookup).
- `rejects_wrong_table_entry`, `rejects_wrong_limb` (one radix unit moved between
  adjacent limbs, rejected by a range), `rejects_nonzero_padding`.
- `rejects_table_with_minimum_output`: a `−2^15` output or a short table is rejected.
### Deletion survey (product)

`rejects_relation_without_each_constraint` (in `silu/tests.rs`) works the same way
as the conversion survey: `check` rejects and `check_except(.., [name])` accepts.

| Constraint | Attacker |
|---|---|
| `low_product` | `T + 1` through `d`, `c` honest |
| `high_product` | `T + 2^8` with `c`, `d` honest |
| `up` (Compose) | `Ul + 1` with every downstream limb recomputed |
| `low` (Compose) | `Tl + 1` alone |
| `silu` (lookup) | `a + 1` with every limb recomputed |
| `up_low` (range) | `Ul + 256`, `Uh − 1`, `c + a`: the same `U` and `T` |
| `byte` (range) | `d + 256`, `c − 1`, `w − 1`: the same `T` and `Tl` |
| `middle` (range) | `w + 128`, `Th − 1`, `Tl + 2^15`: the same `T` |
| `high` (range) | implied: `T = U·a` with `|T| < 2^30` puts `Th` in s16 |
| `up_high` (range) | implied: `Ul ∈ [0, 256)` and `U` in int16 put `Uh` in s8 |
| `carry` (range) | implied: `d ∈ [0, 256)` fixes `c = floor(Ul·a/256) ∈ [−32640, 32639]` |

### Widen-by-one-bit survey (product)

Every limb range is safe one bit wider. The four identities telescope to
`2^15·Th + Tl = 256·(Uh·a + c) + d = U·a` for any limb values that satisfy them, so a
wider limb only allows a non-canonical split of the same `T`. A wider `byte` or `middle`
also breaks the `low` Compose discipline (`Tl` u15), which `validate` rejects. The
consumer needs `Tl` in u15 and `Th` in s16, and both hold for the canonical split,
which the true widths force.

Source mutation run: each relation was deleted from `silu.rs` in turn and the tests
run. Deleting the lookup or the `low` Compose also leaves `a` or `Tl` undisciplined,
so `validate` fails as well; the survey shows that each is still load-bearing once
validity is restored.

| Deleted | Tests that go red |
|---|---|
| `silu` lookup | `rejects_wrong_table_entry`, `rejects_wrong_limb`, `rejects_relation_without_each_constraint`, every `matches_reference_*`, `accepts_static_validity_realistic_shapes` |
| `up` Compose | `rejects_product_near_misses`, `rejects_relation_without_each_constraint` |
| `low` Compose | `rejects_wrong_table_entry`, `rejects_wrong_limb`, `rejects_relation_without_each_constraint`, every `matches_reference_*`, `accepts_static_validity_realistic_shapes` |
| `low_product` | `rejects_product_near_misses`, `rejects_relation_without_each_constraint` |
| `high_product` | `rejects_product_near_misses`, `rejects_nonzero_padding`, `rejects_relation_without_each_constraint` |

- `accepts_static_validity_realistic_shapes`: two layers at `f = 14336`, T = 64,
  sharing one table.

Executor parity: the conversion is checked against the real `Executor::capture`. The
product uses the generated component table, which `Executor` reads through the same
certified points (`activation::certify`).

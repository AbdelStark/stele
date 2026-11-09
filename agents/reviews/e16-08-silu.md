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

`rejects_relation_without_each_constraint` builds one in-range attacker per relation.
Each is a `Plan` with every other column derived from it, plus explicit cell patches.
It asserts that `check` rejects the attacker and that the relation set without that one
relation accepts it. The same deletions in `conversion.rs` turn that test red (source
mutation run).

| Constraint | Attacker (row 1 has `M = 508 = 127·4`; lane 8 is a tie `6/4`) |
|---|---|
| `sign/low` | `A + 1` on a negative lane, downstream recomputed |
| `sign/high` | `A + 2^15` on that lane, now the row maximum, downstream recomputed |
| `gap/low` | `M + 1` with gaps kept from the honest `M` |
| `gap/high` | `M + 2^15` with gaps kept from the honest `M` |
| `attained` | `M + 127`, `s + 1`, gaps from the new `M` (the hit lane has gap 127) |
| `attained/one-hot` | as above, with no hit lane |
| `ceiling/low` | `s + 1` with the honest slack and carry |
| `ceiling/high` | `s + 2^15` |
| `ceiling` (lookup) | `s = 5`, slack 127 |
| `scale` (Compose) | `scale + 1`, limbs kept |
| `zero` | `z = 1` on a nonzero row, `D = s + 1` |
| `division/low` | `rl + 1`, `pl − 1` at the tie |
| `division/high` | `rh + 1`, `ph − 1` on a lane with `D > 2^15` (row 0) |
| `spare/low`, `spare/high` | `pl + 1`, `ph + 1` |
| `code` | code + 1 |

No relation survives. Range checks are not surveyed: each is the only discipline of
its column (RFC-0026 §3.6), so deleting one makes `validate` fail.

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
- `rejects_relation_without_each_constraint` deletes each identity, Compose and the
  lookup inside the test. It ranges the column the deleted relation disciplined, so
  the relation stays valid. It asserts that some near miss is then admitted.

Mutation table: each constraint was deleted from `silu.rs` in turn and the tests run.
Deleting the lookup or the `low` Compose also leaves `a` or `Tl` undisciplined, so
`validate` fails as well. The in-test mutation above shows that each is still
load-bearing once validity is restored.

| Mutation | Tests that go red |
|---|---|
| delete `silu` lookup | `rejects_wrong_table_entry`, `rejects_wrong_limb`, `rejects_relation_without_each_constraint`, every `matches_reference_*`, `accepts_static_validity_realistic_shapes` |
| delete `up` Compose | `rejects_product_near_misses`, `rejects_relation_without_each_constraint` |
| delete `low` Compose | `rejects_wrong_table_entry`, `rejects_wrong_limb`, `rejects_relation_without_each_constraint`, every `matches_reference_*`, `accepts_static_validity_realistic_shapes` |
| delete `low_product` identity | `rejects_product_near_misses`, `rejects_relation_without_each_constraint` |
| delete `high_product` identity | `rejects_product_near_misses`, `rejects_nonzero_padding`, `rejects_relation_without_each_constraint` |

- `accepts_static_validity_realistic_shapes`: two layers at `f = 14336`, T = 64,
  sharing one table.

Executor parity uses the generated component table. `Executor` reads the same
certified points (`activation::certify`), and swaps to the E16-03 capture once
that lands.

# E16-08 SiLU gated product module: output-uniqueness lemma and review notes

**Scope.** `stele_reductions::silu::GatedProduct` (RFC-0026 §5 row 10, §5.2), on
branch `task/E16-08-silu`. Same-author notes. The gated row conversion that consumes
`T` belongs to E16-05; the proof engine belongs to E16-02.

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

## Output interface (RFC-0026 §5.1, E16-08 → E16-05)

`GatedColumns { high, low }`, with the same layout and log length as `U`:

- `T = 2^15·high + low` over Z, exactly `U·silu_q[G]` (int32, units `fu + E`);
- `high` is signed 16 with a range check; `low` is unsigned 15, disciplined by its
  Compose;
- padding is 0.

`T < 0` exactly when `high < 0`, and `T = 0` exactly when `high = low = 0`. This is the
whole gated-conversion input of RFC-0004 A8. The gated row conversion (row maximum of
`|T|`, gated-scale ceiling, codes) belongs to E16-05's reusable row-conversion pattern,
which reads these two columns. This module adds no sign or magnitude column. E16-05
derives the ones it needs from the limbs.

## Lemma (output uniqueness)

*For any `G`, `U` with entries in signed 16, every assignment that satisfies
relations 1–6 has `2^15·Th + Tl = U·silu_q[G]` on real entries and `Th = Tl = 0` on
padding. All auxiliary columns are unique too. If `U·silu_q[G] = 2^30`, no assignment
exists. That case needs `U = silu_q[G] = −32768`, which no valid `silu_q` table
contains: for `E <= F` its negative outputs have magnitude below `2^14` (SILU-CONSUMER).*

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
- The value `Th = floor(U·a/2^15)` lies in `[−2^15, 2^15)` exactly when
  `U·a ∈ [−2^30, 2^30)`. For int16 factors only `U·a = 2^30` falls outside.

The honest split was also checked in Python on 200000 random pairs plus every endpoint
pair (`U ∈ {−32768, …, 32767}` endpoints, `a ∈ [−16383, 32767]` endpoints).

## Tests

- `matches_reference_*`: random and extreme rows (int16 endpoints, 0, ±1, ±2) for
  `silu_q` with `(F, E) ∈ {(8,8), (12,4), (14,14)}`, at shapes including `f = 1`,
  odd `T`, and `f = 100`. The Llama-3.1-8B fixture's block-0 SiLU uses `f = 14336`.
  `T` equals the executor product `U·silu_q[G]`, and `check` accepts.
- `rejects_product_off_by_one`: `T ± 1` with canonical limbs, with the carry chosen
  to satisfy the low product wherever it can.
- `rejects_wrong_table_entry`: `a + 1`, with every limb recomputed honestly.
  Rejected by the lookup.
- `rejects_wrong_limb`: one radix unit moved between `Th`/`w`/`Tl`, `c`/`d`/`w` and
  `Uh`/`Ul`. Every identity and composed value is kept, and a range rejects.
- `rejects_nonzero_padding`.
- `accepts_static_validity_realistic_shapes`: two layers at `f = 14336`, T = 64,
  sharing one table.

Executor parity uses the generated component table. `Executor` reads the same
certified points (`activation::certify`), and swaps to the E16-03 capture once
that lands.

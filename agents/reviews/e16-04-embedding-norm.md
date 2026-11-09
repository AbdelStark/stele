# E16-04 review notes: embedding and rmsnorm_q modules (RFC-0026 §5 rows 1-2, §5.2)

Code: `crates/stele-reductions/src/development/{embedding,rmsnorm,limbs}.rs`.
Tests: `development/norm_embedding_tests.rs` (random, extreme, exact-branch, version-2, near-miss, static
validity) and `tests/dev_modules.rs` (every family-1 model-execution fixture).
Decision: ADR-080. Same-author pass; an independent soundness-auditor pass is requested.

## Shared mechanism: radix-256 chains

A wide equation `Σ_i 256^i·T_i = 0` (each `T_i` a sum of products of byte or 16-bit
columns) is one identity per position, `T_i + c_{i−1} − 256·c_i = 0`, with no carry
out of the last position. Summing `256^i` times each identity telescopes, so the
chain holds over Z exactly when the wide equation does. Each carry is range-checked
at a width computed from the static term magnitudes (one signed column below `2^15`,
else a u16 limb and a signed high limb). Every position identity then passes the
bound rule on its own, and `Relation::validate` checks it. The chain is the shared
E16-05 `development::Chain` (ADR-076); it fills carries without rejecting, so `check`
alone decides.

## Row 1: embedding output-uniqueness lemma

Inputs: the weight `E`, public tokens, mantissas and `s = ee + f0`.
1. The matmul with the public one-hot fixes `G[t,k] = E[x_t,k]`. Row blocks keep the
   domain within `MAX_VARS`, and a block-mask identity assembles `G`.
2. The lookup `(G, σ)` into `{(v, [v<0])}` fixes `σ = [G < 0]` and ranges `G`.
3. Let `P = G·m_t·w_k`, with `w` the public real-feature mask.
   - `s >= 0`: `R0 = P·min(m·2^s, 2^16)`. When the cap applies and `G != 0`, `|R0| >= 2^16`,
     so no assignment exists. The executor rejects the same row.
   - `s < 0`, `h = min(−s, 24)`: `ρ = 2^h·R0 − P + σ + 2^(h−1) − 1 ∈ [0, 2^h)` is exactly
     `R0 = R(P/2^h)` with ties away from zero, given `σ = [P < 0]`. At `P = 0` both `σ`
     give `R0 = 0`. Because `|P| < 2^23`, the cap at 24 changes no result.
   - Padded features have `P = 0`, which forces `R0 = 0`.

So `R0` is unique and equals the executor's. `R0` is declared at the narrowest
signed width that holds `R(Pmax/2^h)`, which is at most int16. The narrowing keeps
`2^h·R0` under the bound rule.

## Row 2: rmsnorm_q output-uniqueness lemma

The lemma is stated step by step in the `rmsnorm.rs` module comment. In outline:
1. The byte limbs of `X` are unique, and `σX = [X<0]` (sign lookup on the top limb).
   The matmul row sums `S_pq = Σ X_p·X_q` are exact, because they are disciplined by
   their operand widths, `d <= 8192`. The chain `S` gives the unique bytes of
   `S = Σ X²`.
2. The one-hot `h[t,K]`, `K = a + 23`, has one set entry, at a valid `K`. A `K` is
   valid when `a <= 9` (16 in version 2) and `e ∈ [−16, 90]` (97 in version 2). The
   selected bytes are the bytes of the public constants at that `K`.
3. The chains `quotient` and `remainder` give `N·fa = M·D + R` and `D = R + gap + 1`
   over Z. The `(M, J)` lookup bounds `M` to `[2^14, 2^16)`, and only one `a` attains
   that. So `a`, `M` and `J` are the executor's.
4. The chain `output` gives
   `Z = Y·2^Es − g·X·H·J + pos·(σ−1)·g + pos·2^(Es−1) ∈ [0, 2^Es)`, with
   `g = 2^(Es−e')`. Two branches, selected by `pos = [e' >= 1]` through the one-hot:
   - rounding branch: `Y = R(XHJ/2^e')` with half-away ties;
   - exact branch: `Y = XHJ·2^(−e')`.

   When `e' = min(e, bits(X)+30)` is below `e`, both shifts round to 0.

Upstream obligation: the padded entries of `X` (features `k >= d`) are 0, because every
producer pins its padding (RFC-0026 §2.1). Step 1 counts exactly the `d` real features
only under that obligation.

So `Y` is unique and equals `evaluate_rmsnorm`'s. An `R` or `gap` outside its bytes,
an `M` outside the table, and a `Y` outside int16 (the executor's `Overflow`) all
leave no satisfying assignment.

## Near-miss controls (plain checker)

Each control assigns the tampered capture, so every other witness follows it (exact
remainders, carries and `Z`), and asserts that `assign` succeeds and that `check`
rejects the result. The survey below covers each constraint individually.

| Output | Tamper | Rejected by |
|---|---|---|
| `R0` | ±1, other rounding direction | `ρ` range / identity |
| `G` | a code off the gathered row | matmul |
| `Y` | ±1 on every feature, other rounding direction | `Z` byte range |
| `a` | ±1, with the exact `M`, `R`, `D` of that exponent | rsqrt lookup / `gap` range |
| `M` | ±1, with `R` adjusted by `∓D` | lookup / `R` or `gap` range |
| `J` | ±1 | rsqrt lookup |

## Constraint mutation survey

The survey is in `development/norm_embedding_tests/mutation.rs`, with the attackers in `norm_attacks.rs` and
`embedding_attacks.rs`. It takes every range, lookup, Compose, identity and matmul `C`
of a module instance. For each one it looks for an attacker witness that every other
constraint accepts and `C` rejects: `check` rejects it, and
`check_except(relation, values, &[C])` accepts it.

How a witness is built:
- It starts from honest values, or from attacker-chosen inputs `X`. `X` is a free column
  of the module.
- It changes a few cells.
- It solves the rest as an attacker would: matmul outputs and their limbs, `M`/`J` from
  the selected constant bytes, chain carries and free bytes, and the output itself.
  Nothing is recomputed from the honest formulas.

Each row is classed:
- `output`: the witness changes `Y` (or `R0`), or gives an int16 `Y` where the executor
  rejects;
- `aux`: only auxiliary columns change;
- `none`: no witness was found.

The class of every constraint is pinned in a golden table:
- `development/norm_embedding_tests/rmsnorm-mutation.txt`;
- `embedding-round-mutation.txt` and `embedding-exact-mutation.txt`.

Deleting any constraint from a module changes the table, so a test fails. The CI test
searches only until it reaches the golden class. The `#[ignore]` test runs the
exhaustive search that produced the table.

The rmsnorm_q instance has 187 constraints. Its setup:
- `F = G = 0`, `E = 12`, `ed = 100`, `d = 4`, `T = 4`;
- an exact tie in row 0, with `H_0 = 2^(e−1)` and `J` odd;
- a zero row on the exact-multiply branch;
- gains that let `X` overflow int16 and let `S` be chosen freely.

The embedding has two instances:
- rounding: 14 constraints, 9 `output`, 1 `aux`, 4 `none`;
- exact: 13 constraints, 6 `output`, 3 `aux`, 4 `none`.

### Output attacks (examples)

| Constraint | Attack |
|---|---|
| `sigmaX` lookup | `σX = 1` at the tie `X = 1`: `Y` rounds toward zero |
| `X0` range | the tie with `X0 = 257`, `X1 = −1`, `σX = 1` (the lookup is satisfied): `Y` rounds toward zero |
| `rsqrt` lookup | `J + 1` (with its bytes), `Jg` and `Y` solved |
| Compose of `X`, of `S_pq`, of `J` | a limb off its value, then `S`, `M`, `J` and `Y` follow |
| `S_pq` matmuls; `alpha`/`beta`/`gamma`/`g`/`gp`/`pos` selections | a wrong row sum or selected byte, then `M`, `J` and `Y` follow |
| `R` top byte; `gap` top byte | `M ± k` with `J = rsqrt_q[M]`, the remainder leaving `[0, D)` |
| `Y` range | an overflowing row: the true `Y` (up to `2^27`) taken as is |
| `Z` byte ranges | `Z_(top−1) + 256`, `Y − 1` |
| `S`, `quotient`, `Jg` and `output` chain positions | a byte or a carry freed at that position, then `M`, `J`, `Y` |
| high `quotient` positions (3–7) | a wrong exponent with `A − k·256^i` (the statistic chosen through `X`) |
| high `output` positions (4–6) | an overflowing row, with `Y` wrapped modulo `256^(i−top)` into int16 |
| embedding gather, blocks, sign, `ρ` range, `round`/`exact` identities, `R0` range | `G ± 1`, the tie (`m = 8`, odd code), `R0 ± 1`, and a code under the `2^16` cap or a large mantissa |

### Why the remaining constraints show no output attack

**Carry ranges** (all chains; most of the `none` rows).
- Bottom-up, every carry is determined by the terms of its position, and those terms
  are range-checked: `c_i = (T_i + c_(i−1) − b_i)/256`, with the free byte `b_i` in
  `[0, 256)` fixed modulo 256.
- So over Z they never bind.
- They are needed by the bound rule (INV-5): without them a position identity can
  wrap mod p, and `validate`'s discipline rejects the relation.

**Selected-byte ranges** (`alpha*`, `beta*`, `gamma*`, `g*`, `gp*`, `pos`).
- The selection matmul with a 0/1 one-hot gives exactly a byte of a public constant.
- They are redundant over Z, and needed for discipline.

**Top limbs of a pinned value** (`S_pq` top limb, `M1`, `J1`, `S_4`, top `Jg` byte).
- The value is pinned (by a matmul, a lookup or a chain), and the lower limbs lie in
  `[0, 256)`, so the top limb is determined.
- They are needed for discipline.

**Lower limbs and bytes of a pinned value** (`aux`: `S_pq`, `M0`, `J0`, `S`, `Jg`, and
the lower bytes of `R`/`gap`).
- A neighbour can compensate an out-of-range limb, but every consumer reads the
  limbs only through their weighted sum (Compose or chain), which is pinned.
- For the lower `R` bytes, a change of `M` would need a byte near `−D`. The carry
  ranges keep each byte change within the size of the position's terms, which is
  below `D` in this instance.

**Low `remainder`, `quotient`, `Jg` and `output` chain positions**
(`aux`: a free byte at that position).
- Freeing one low position lets its byte move, but a value change of `M` or `Y` would
  need it to move by a multiple of `D` or of `2^Es`.

**High `quotient` positions 8–11.**
- They need `A' − k·256^i` in a window of width `3·2^14·D'` at some exponent.
- With `S <= 2^32` here, `A' < 2^67`, so only `i <= 8` is reachable, and the survey
  found none at 8.
- Larger `d` or input widths reach further positions, where these constraints become
  the only guard.

**High `output` positions 7–8.**
- They need a true `|Y| >= 2^31` to wrap into int16.
- In this instance `|Y| <= √d·|H|·2^(E−G+1) < 2^29`.

**`h` range and the one-hot matmul.**
- These are steps 2 and 3 of the lemma.
- The survey tried two-hot, `2/−1` and moved one-hots at every exponent, and found no
  single-constraint witness. A zero row gives `D = 0`, and then `gap = −1`.
- They stay, because no proof shows they are redundant.

**`invalid` identity, compose of `M`, embedding `E` range, the embedding sign lookup in
the exact branch, and gather block ranges.**
- A one-hot entry at an invalid exponent leaves every selection unchanged.
- `M` is pinned by the bytes the chains read.
- An out-of-range weight on an ungathered row, and a block entry, are caught by the
  `G` sign lookup through the block identity.
- The exact branch does not read `σ`.

These constraints bind auxiliary or unused cells. They stay, because each one is part
of the lemma's integer argument or of the bound rule.

### Widen-by-one-bit pass

Every range is also surveyed one bit wider:
- `widen-up`: one more bit at the top, for unsigned ranges;
- `widen-signed`: one more bit as a sign.

The attacker witness must lie inside the wider width, change an output, and still be
rejected at the true width. Those rows are pinned in the same golden tables.

The rmsnorm_q instance uses `ed = 100`. Remainders are then `R = 100·j + 4`, so both
edges of `[0, D)` are reachable. With `ed = 10^5`, the `R ∈ [D − 2^16, D)` edge cannot
be reached.

**Widened ranges with an output attack**:
- `X0`, up: the positive tie with `X0 = 257`.
- `X0`, signed: the negative tie written as `X0 = −1`, `X1 = 0`, `σX = 0`.
- `Y`, signed: an overflow with true `Y = −32772`.
- Every `Z` byte, up: `Z + 256` and `Y + 1` at a row with small `Z`.
- Every `Z` byte, signed: a row with `Z >= 2^Es − 256^(i+1)`, then `Y − 1`.
- Every `R` byte, signed: a row with `R >= D − 256^(i+1)`, then `M + 1`, with `J` and `Y` following.
- Every `gap` byte, signed: a row with `R < 256^(i+1)`, then `M − 1`.
- Embedding `R0`, signed: a code under a multiplier in `[2^15, 2^16)`.
- Embedding `ρ`, up and signed: `R0 ± 1` with `ρ ± 2^h`.

**Widened ranges that are safe, and why**:
- **Carries** (every chain). Bottom-up from `c_(−1) = 0`, each carry is
  `(T_i + c_(i−1) − b_i)/256`. The free byte `b_i` is range-checked at its true width,
  or the position has none, so the carry is unique whatever width it is declared at.
- **Selected bytes and `pos`**. The selection matmul with the one-hot gives the exact
  byte of a public constant.
- **`h`, up.** `h >= 0`, `Σ_K h·valid = 1` and `h·invalid = 0` together force a one-hot.
- **Limbs and bytes of a pinned value** (`S_pq` limbs, `M0`/`M1`, `J0`/`J1`, `S` bytes,
  `Jg` bytes). The value is pinned by a matmul, a lookup or a chain, and every consumer
  reads only that value. A wider limb only redistributes the value (`aux`).
- **`R` bytes and `gap` bytes, up.** The other column's bytes keep their true widths,
  so `R >= 0` and `D − 1 − R >= 0` still hold, and `M = floor(A/D)` is unchanged.
- **Embedding `E` and `G_b`.** A wider weight on a gathered row, or a wider block entry,
  reaches `G`, and the `G` sign lookup rejects it. An ungathered row changes nothing.

**Not demonstrated**:
- **`h`, signed** (`h ∈ {−2, …, 1}`). Combinations such as `1 + 1 − 1` keep
  `Σ h·valid = 1`. The survey tried `2/−1` pairs and moved entries at every exponent
  and found no witness with every selected byte in range and `M` in the table.
- The true-width `u1` range keeps `h >= 0`, which lemma step 2 uses. This row is left
  open: no proof is given either way.

## Limits

- rmsnorm_q requires `d <= 8192`. A signed 30-bit `S_00` holds `2^13·255²`, but not
  `2^14·255²`. Version 1 admits `d <= 16384`, so the plan rejects that model with
  `Unsupported::Shape` (RFC-0026 §1.3).
- The embedding assumes the committed weight padding is 0, so `G` is 0 at padded
  features. The output does not depend on that padding (mask `w`), only the
  honest `G` assignment does.
- Capture types are module-local (`EmbeddingCapture`, `RmsNormRow`). Until E16-03
  lands, tests build them from `Descriptor::evaluate_rmsnorm_wide` and
  `Executor::full` cuts.

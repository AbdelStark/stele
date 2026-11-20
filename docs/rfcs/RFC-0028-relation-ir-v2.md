# RFC-0028 — Relation IR v2: the commit rule, virtual columns and segments

Status: Accepted (development tier) · Version: 0.1.0 · Depends: RFC-0006, RFC-0008, RFC-0012, RFC-0026, RFC-0027

Scope: Accepted for the development tier (RFC-0027 §2, ADR-150). Nothing here is admitted to
`standard` or `treaty` until Workflow 10 promotes it. Questions: Q31, Q34, Q35, Q43.
Tasks: E18-01..E18-09. Companion amendments accepted: §1.4.

## 1. Statement

### 1.1 Motivation

The RFC-0026 engine commits every intermediate value. On the eight-layer synthetic
model it commits a stacked source of 2^25 cells and runs about 20 million lookup
positions for 64 tokens ([assessment §3](../assessment.md#3-the-end-to-end-prover-measured)).
RFC-0001 §1.4 item 1 said the opposite: commit nothing but the residual stream.
Neither is right.

A sumcheck reduces a claim to evaluation claims at a random point. Each final claim
must be discharged against something fixed before the point was drawn: a committed
oracle, a public polynomial, or a column whose values are a fixed polynomial function
of such columns. A value produced by rounding, clamping, selection, digit splitting or
a table is none of these. If it is not committed, the prover chooses its evaluation
after seeing the point, and the final check becomes one equation in a free unknown.

### 1.2 The commit rule

> A column is **committed** exactly when it is advice (its values are not a fixed
> polynomial function of other columns under §2.1) or a carried segment boundary
> (§2.3). Every other witness-side column is **virtual** and is never committed.

Consequences for CQIS operations:

| Operation | Committed | Virtual |
|---|---|---|
| matmul `A = X·W` | — | `A` |
| rounding `acc = 2^k·y + rem` | `y` | `rem = acc − 2^k·y` |
| virtual value wider than one table, `v = lo + 2^16·hi` | `hi` | `lo = v − 2^16·hi`; needs `mag(v) + 2^16·mag(hi) < p/2`, which holds for `|v| < 2^28` |
| advice wider than one table | its limbs, each range-checked | `v = Σ 2^shift·limb` (linear in the limbs) |
| sign and magnitude `x = (1−2σ)·a` | `σ` | `a = (1−2σ)·x` |
| table `y = f(t)` | `y` (or neither, by an Accepted answer to Q35) | — |
| masked or broadcast copy, residual add at equal scale | — (the residual stream at a segment boundary is carried, §2.3) | the copy or sum |

### 1.3 What is unchanged

The statement of RFC-0026 §1.1. The integer semantics of every relation (RFC-0026 §3).
The plain checker as the oracle. The transcript labels. The module contract
(`declare`, `assign`), except that a module declares which columns are virtual.

### 1.4 Companion amendments accepted with this RFC

This RFC changes what three Accepted texts say; all companion amendments are Accepted
for the development tier alongside it:

- **RFC-0008 A9.** RFC-0008 A2 item 4 and A6 previously excluded virtual tuple columns.
  A9 admits a tuple column that is virtual under §2.1 here at the development tier: it is
  a fixed polynomial function of columns whose roots are absorbed before the Unit, Beta,
  and Alpha draws (§2.4 steps 2.1 and 2.2 precede step 2.3).
- **RFC-0026 A27 and A28.** A27 (E18-06) scopes a lookup check (A3) to one segment and
  carries the segment boundary rule of §2.3 for committed columns; A28 (E18-01) restates
  A3's "split values bound" for a member value on a virtual column (absorbed when sent
  and reduced under §2.4 step 4) and states the segment rule for virtual columns.
- **RFC-0012 A19.** Registers the soundness ledger records for the reductions of §5 at
  the development tier; no new transcript label.

## 2. Protocol (transcript order)

### 2.1 Column kinds

`stele_ir::relation::Kind` gains `Virtual(Def)`. A definition may read only columns
with a smaller `ColumnId`, so declaration order is a dependency order.

- `Linear { constant, terms: [(c, Ref)] }`: `v(x) = constant + Σ c·f(x)`, integer
  `c ≠ 0`.
- `Pointwise { terms }`: `v(x) = Σ_t c_t · Π_f f(x)`, at most 3 factors per term (the
  term shape of an RFC-0026 identity).
- `Contraction { free, summed, lhs, rhs }`: `v(x) = Σ_y lhs(x,y)·rhs(x,y)`, the
  RFC-0026 §3.5 matmul with `v` in place of the committed `out`. A contraction past
  `MAX_VARS` is split into row blocks exactly as RFC-0026 A6 splits a matmul; each
  block defines one slice of `v`.

A `Ref` to a virtual column is allowed wherever a `Ref` to a witness column is:
identity factors, lookup tuples, range checks, operands of other definitions.

### 2.2 Derived widths and the bound rule

A virtual column has no declared width. `Relation::validate` derives its magnitude
from its definition by the RFC-0026 §3.6 formulas (`|constant| + Σ|c|·mag`,
`Σ|c|·Π mag`, `2^s·mag(lhs)·mag(rhs)`) and rejects a magnitude of `p/2` or more. The
derived magnitude is the column's magnitude in every rule of RFC-0026 §3.6.

Range discipline applies to witness and weight columns only. A virtual column needs
none: by induction over `ColumnId`, when every committed column lies in its width,
each virtual column's field value is the centered residue of its integer value.

A range check or lookup whose tuple reads a virtual column is the way advice is
constrained (for example `rem` in §1.2). The limb rule of RFC-0026 §3.5 stands: a
range check covers at most 16 bits, so a virtual value that needs a wider one is
split by committing its high limbs and checking the virtual low limb. The low limb's
derived magnitude is `mag(v) + 2^shift·mag(hi)` and must stay below `p/2`; a virtual
value too wide for that is restructured, never wrapped. Advice wider than 16 bits is
committed as limbs and is itself linear in them, so its width never rests on a check
that presumes it.

**A1 — Range-tightened downstream magnitude.** Once a virtual column `id`'s raw derived
magnitude from its definition satisfies `raw <= (p - 1)/2` (so its defining equation is
statically wrap-free over `F_p`, and its unique integer value equals its centered field
residue), every valid `Range { column: id, width }` (`1 <= width.bits <= 16`) proved by
LogUp confines that integer value to `width` (whose interval lies strictly inside
`(-(p-1)/2, (p-1)/2)`). Therefore `derived_magnitudes` tightens `id`'s downstream
magnitude bound to `min(raw, min_{Range on id} width.magnitude())`. An over-wide virtual
definition (`raw > (p - 1)/2`) is still rejected with `Invalid::Bound` before any range
check is considered (`NC-1340` / INV-5 unchanged).

### 2.3 Segments

Every commitment group belongs to a **segment**, numbered in plan order. A virtual
column belongs to the highest segment among its operands; one whose operands are all
weight or public columns (the embedding gather) belongs to the segment the plan
declares it in. A relation belongs to the highest segment among its columns.

A witness column may be declared **carried**. A relation or definition of segment `s`
may read witness and virtual columns of segment `s`, carried columns of segment
`s − 1`, weight columns and public columns. `validate` rejects anything else.

The residual stream at a segment boundary is carried. It is a committed cut even when
its value is arithmetic (an exact add): an identity of its segment equates it to the
virtual expression, and the next segment reads the committed column. Nothing else
needs to be carried.

### 2.4 Order

1. **Statement.** As RFC-0026 §4 step 1, including every model root.
2. For each segment `s` in order:
   1. commit the segment's stacked source (RFC-0026 A4 layout); absorb its root;
   2. commit and absorb the multiplicity sources of the segment's checks;
   3. run the segment's zerochecks (RFC-0026 §4 step 4), its lookup checks (step 5)
      and any matmul relation that still has a committed output (step 6); each emits
      claims on columns of any kind;
   4. **reduce.** For each virtual column of the segment, in decreasing `ColumnId`
      (columns of one definition kind and domain shape whose claims are all filed are
      reduced together: their claim batches and their sumchecks are combined with one
      coefficient per column, as RFC-0006 A2 batches instances):
      - `Linear`: for each claim `(z, c)` on `v`, the prover sends the operand
        evaluations `f̃(z|vars)`, which are absorbed; the verifier checks
        `c = constant + Σ c_i·f̃_i` and files each operand evaluation as a claim. No
        challenge is drawn.
      - `Pointwise`: if `v` has more than one claim, reduce them to one point `z` with
        RFC-0006 A2 mode 1 over `v`'s own table. Then one RFC-0006 A1 sumcheck of
        `Σ_x eq(z, x)·Σ_t c_t Π_f f(x)`. The verifier evaluates `eq` at the final
        point. No new label is used.
      - `Contraction`: if `v` has more than one claim, reduce them to one point with
        RFC-0006 A2 mode 1 over `v`'s own table. Then run the RFC-0026 §4 step 6
        sumcheck at that point (no fresh `relation/point` draw). When `v` is split
        into `2^k` row blocks, the prover first sends the `2^k` slice evaluations at
        the point with its split coordinates removed. They are absorbed, the verifier
        checks that they interpolate to the claim along the split coordinates, and
        each block runs its sumcheck on its slice claim.
   5. batch the claims on segment `s − 1`'s stacked source, which are now complete,
      and open it; segment `s − 1` leaves memory.
3. Open the last segment. Batch all weight claims per model source and open each
   once. This is the development form and reads each model source in the extension
   field. The stacked weight phase (task E18-07) replaces it: one certified source
   per weight role, one claim on it per proof, and an opening whose row combination
   is the weight pass (RFC-0029 §1.3).

For a relation with one segment and no virtual column, every engine message equals
its RFC-0026 message; only the container framing of §2.5 differs.

### 2.5 Proof container and canonical wire framing

- **Relation encoding (`stele/v0.1/relation/encoding/v2`).** Unsegmented relations without
  virtual columns keep `stele/v0.1/relation/encoding/v1` unchanged (RFC-0026 A15 §5).
  Segmented or virtual relations use 31-byte magic `stele/v0.1/relation/encoding/v2`:
  - each group appends `segment: u32le` after `log_len: u8` (RFC-0026 A27 §2);
  - each column appends `carried: u8` (`0 | 1`) after `log_len: u8`, and admits kind tag
    `3` (`Virtual`, rejected in `v1`): `def_tag: u8 || def_body || seg_opt`, where
    `def_tag = 0` (`Linear`) encodes `constant: i64le || list (coeff: i64le || Ref)`,
    `def_tag = 1` (`Pointwise`) encodes `list (coeff: i64le || u8 factor_count || [Ref])`,
    `def_tag = 2` (`Contraction`) encodes `free: u8 || summed: u8 || lhs: Ref || rhs: Ref`,
    and `seg_opt` is `0u8` (`None`) or `1u8 || seg: u32le` (`Some(seg)`). A virtual column's
    encoded `width` is `(signed = 0, bits = 0)`.
- **Container (`stele-dev-e2e-v2`, RFC-0026 A26 §1).** The v1 sections grouped per segment
  (`groups`, `multiplicities`, `identities`, `lookups`, `matmuls`, `reductions`, `openings`),
  plus top-level `model_openings`. In each lookup check (RFC-0026 A28 item 2), after
  verifying the A3 member split, if any member tuple slot reads a `Kind::Virtual` column,
  the verifier absorbs under `AbsorbLabel::Final` the payload
  `check_id: u64le || [(member_index: u32le || slot: u8 || member_val: 16B K)]` in
  `(member_index, slot)` order (no-op when no member reads a virtual column). Inside segment
  `s`, `reductions` holds one section per virtual column owned by segment `s` that has at
  least one claim, in strictly decreasing `ColumnId` order:
  - `Linear`: for each claim `claim_idx = 0..claims.len()` at `(z, c)`, `terms.len()` canonical
    `K` values `evals`, absorbed under `AbsorbLabel::Final` as
    `col_id: u32le || claim_idx: u32le || evals`, checked against
    `c == constant + Σ c_i · evals[i]` (else `LinearMismatch`), then routed as `(z|r_i, evals[i])`.
  - `Contraction`: if `claims.len() > 1`, an RFC-0006 A2 mode-1 `ClaimBatch`
    (`id = (1 << 62) | (4 << 48) | col_id`, `tensor = col_id`, `num_vars = log_len`,
    `log_len` rounds of `3 K` plus `1 K` final); then an RFC-0006 A1 sumcheck
    (`id = (1 << 62) | (5 << 48) | col_id`) over descending `vars` (`shared` free bits and
    `summed` bits), width `3` (or `4` when `shared` is nonempty) and `2` (or `3`) finals,
    checking `finals[0] == Π_{d ∈ shared} eq(z_d, r_d)` (`EqMismatch`) before routing `lhs`
    and `rhs`.
  - `Pointwise`: if `claims.len() > 1`, the same `ClaimBatch`
    (`id = (1 << 62) | (4 << 48) | col_id`); then an RFC-0006 A1 sumcheck
    (`id = (1 << 62) | (6 << 48) | col_id`, `num_vars = log_len`, inputs `[0 = eq(z, ·),
    1..=distinct_refs]` in first-appearance order, each term prefixed by factor `0`) with
    width `1 + max(1 + term.factors.len())`, checking `finals[0] == eq(z, r)` (`EqMismatch`)
    before routing each distinct `Ref` at `r` with `finals[1 + idx]`.
  The verifier derives every count and exact section length before reading a proof byte.

## 3. Prover algorithm and cost

- `Linear`: one MLE evaluation per operand per claim (`2^n` small-by-extension
  products), no sumcheck, no commitment.
- `Pointwise`: one batching sumcheck when the column has several claims, then one
  degree-4 sumcheck over the column's domain. Columns of one shape share both, so
  proof bytes and verifier rounds grow with the number of shapes and levels, not with
  the number of columns.
- `Contraction`: one batching sumcheck over the `2^a` outputs when needed, one partial
  evaluation of each operand (`2^(a+s)` small-by-extension products each), one sumcheck over
  `2^(s+k)`. Each weight is read once per contraction it enters.
- Memory: the witness of two consecutive segments and their commitment data.

Cost-model terms: committed cells fall from every intermediate to advice only, moving
`c_c`; lookups on dropped limb columns disappear, moving `c_a`. The measured effect is
recorded per conversion step on L1 and L2. Wide scaled products (RFC-0026 §5 row 4)
keep their limb chains under this RFC; removing them is a numerics question (Q36).

## 4. Verifier algorithm and cost

As RFC-0026 §8, per segment. For each virtual column the verifier performs the checks
of §2.4 step 4: a field equation per `Linear` claim, a sumcheck verification and one
`eq` evaluation per `Pointwise` batch, a batching verification and a sumcheck
verification per `Contraction`. It holds no witness and no table larger than the
public columns.

## 5. Soundness

No new error family.

| Source | Line | Formula | Status |
|---|---|---|---|
| `Linear` reduction | — | exact; operand evaluations are claims discharged downstream | proven (linearity of the multilinear extension) |
| `Pointwise` claim batch | RLC + SC | RFC-0006 A2 mode 1 | proven |
| `Pointwise` sumcheck | SC | `m·4/|K|` | proven |
| `Contraction` claim batch | RLC + SC | RFC-0006 A2 mode 1 | proven |
| `Contraction` sumcheck | SC | `(s+k)·δ/|K|` | proven |
| `Contraction` slice split (row blocks) | — | exact; a multilinear interpolation in the split coordinates | proven (multilinearity; the blocks are those of RFC-0026 A6) |
| carried-column claims | — | the segment root precedes every challenge that produces them | by order (§2.4) |

The composition argument (Q34): by reverse induction over `ColumnId`, every claim
filed on a column equals the evaluation of that column's true multilinear extension
except with the summed error above; claims on committed columns are discharged by the
openings. The argument is written in `formal/` before promotion to `standard` and is a
Lean statement before `treaty`.

Integer faithfulness follows from §2.2.

## 6. Negative controls

Catalogue IDs in `tests/negative-controls/catalog.md` (draft IDs 1320..1325 were
previously allocated by RFC-0026 A12/A14/A16; the two segment controls are already
executed as `NC-1335..1336` under RFC-0026 A27, and the four virtual-column controls
are reserved as `NC-1337..1340` for E18-02..E18-04). Each runs through the actual
verifier.

| NC | Tamper | Expected |
|---|---|---|
| 1337 | +1 on one operand evaluation sent for a `Linear` reduction | the consuming check's mismatch error |
| 1338 | prove with a virtual column's values that differ from its definition at one index | `RoundSumMismatch` or `FinalEvaluationMismatch` at its reduction |
| 1339 | commit `y + 1` for one rounding, with `rem` recomputed | the `rem` range lookup rejects (`RootMismatch`) |
| 1335 | read a non-carried column of segment `s − 1` from segment `s` (done, RFC-0026 A27) | `StatementMismatch` (validation) |
| 1336 | reorder two segment roots (done, RFC-0026 A27) | Policy 1: `RootMismatch`; Policy 2: `GrindMismatch` |
| 1340 | declare advice (a rounding output) as `Linear` with the integer that represents a field inverse of `2^k` | `StatementMismatch` (derived magnitude at least `p/2`) |

## 7. Open questions

- **Q31** (restated): this RFC answers it for tuples that are virtual under §2.1.
- **Q34**: the composition statement of §5, for Lean.
- **Q35**: an indexed-lookup argument that leaves the table output virtual by
  committing one table-sized vector per claim. If it holds at acceptable cost it
  removes the committed attention probabilities.
- **Q43**: a commitment-free attained-maximum argument (the product of `M − v_j` over
  the scope is zero), replacing the committed one-hot.

## 8. Amendment log

- **A1 & §2.5 wire specification (development tier, tasks E18-05a / E18-05):**
  1. Range-tightened downstream derived magnitude for statically wrap-free virtual columns
     (`§2.2`): after checking `raw <= (p - 1)/2` on a virtual column's definition, any valid
     whole-column `Range` on that virtual column tightens its downstream magnitude bound to
     `min(raw, range.width.magnitude())`, allowing ranged virtual low limbs, codes, and
     outputs to feed downstream multiplications and contractions without committing a
     redundant copy. Over-wide definitions (`raw > (p - 1)/2`) still reject with
     `Invalid::Bound` before range tightening (`NC-1340` / INV-5 unchanged).
  2. Canonical byte layout for `stele/v0.1/relation/encoding/v2` virtual definitions and
     `stele-dev-e2e-v2` `reductions` sections (§2.5) pinned for independent Lane-V replay
     (`stele-verifier`, ADR-128) and A16 registry vector normalization.
- **E18-04 implementation note (`Pointwise` reductions, `NC-1339..1340`):** Every claimed
  `Def::Pointwise` column is reduced individually in strictly decreasing `ColumnId` order,
  emitting one reduction section `[optional RFC-0006 A2 mode-1 claim batch] ||
  [eq-weighted RFC-0006 A1 sumcheck]` under disjoint instance IDs `VIRTUAL_BATCH | col_id`
  (`(1 << 62) | (4 << 48) | col_id`) and `VIRTUAL_POINTWISE | col_id`
  (`(1 << 62) | (6 << 48) | col_id`), checking `final_values[0] == eq(z, r)` (`Error::EqMismatch`)
  and routing each deduplicated operand `Ref` claim downstream. Controls `NC-1339` (committed
  `y + 1` with virtual `rem` range lookup rejecting with `RootMismatch`) and `NC-1340`
  (advice declared as `Linear` with field inverse of `2^k` rejecting with `StatementMismatch`)
  execute through `verify_segmented`.
- **E18-03 implementation note (`Contraction` reductions, unsplit `shared + summed <= MAX_VARS`):**
  Every claimed `Def::Contraction` column is reduced individually in strictly decreasing
  `ColumnId` order, emitting one reduction section `[optional RFC-0006 A2 mode-1 claim batch] ||
  [contraction sumcheck]` under disjoint instance IDs `VIRTUAL_BATCH | col_id`
  (`(1 << 62) | (4 << 48) | col_id`) and `VIRTUAL_CONTRACTION | col_id`
  (`(1 << 62) | (5 << 48) | col_id`). Whenever `free <= MAX_VARS`, `summed <= MAX_VARS`, and
  `shared + summed <= MAX_VARS` (even when `free + summed > MAX_VARS`), the contraction runs
  directly as one unsplit sumcheck over the `shared + summed` variables without emitting slice
  evaluations; `shared + summed > MAX_VARS` rejects with `Error::Unsupported`. Pre-split
  row-block contractions declared with `Ref::FIXED_0`/`Ref::FIXED_1` reduce each block column
  directly.
- **E18-02 implementation note (`Linear` reductions, `NC-1337..1338`):** For a
  `Def::Linear` virtual column (which has no sumcheck of its own), `NC-1337` (+1 on one
  sent operand evaluation) and direct `NC-1338` (forged virtual column values with honest
  operand evaluations) reject with `LinearMismatch` at the Step 2.4 `Linear` check; an
  adaptive `NC-1338` prover that compensates a sent operand evaluation to pass the `Linear`
  check rejects at that operand's downstream discharge (`PublicMismatch`, `Sumcheck`, or
  `Pcs`). `NC-1338` against `Pointwise`/`Contraction` sumcheck reductions (E18-03/E18-04)
  rejects with `RoundSumMismatch` or `FinalEvaluationMismatch`.
- **Acceptance (development tier, ADR-150, task E18-01):** Accepted for the development
  tier (RFC-0027 §2) together with companion amendments RFC-0008 A9, RFC-0026 A27/A28,
  and RFC-0012 A19. Segment controls `NC-1335..1336` are executed under RFC-0026 A27;
  virtual-column controls `NC-1337..1340` are entered as `todo` in the catalogue (draft
  numbers 1320..1325 collided with earlier RFC-0026 A12/A14/A16 allocations). Promotion
  to `standard` or `treaty` remains a separate Workflow 10 task.

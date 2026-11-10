# RFC-0028 — Relation IR v2: the commit rule, virtual columns and segments

Status: Draft · Version: 0.1.0 · Depends: RFC-0006, RFC-0008, RFC-0012, RFC-0026, RFC-0027

Scope: the development tier first (RFC-0027 §2). Nothing here is admitted to
`standard` or `treaty` until Workflow 10 promotes it. Questions: Q31, Q34, Q35, Q43.
Tasks: E18-01..E18-09. Companion amendments required at acceptance: §1.4.

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

### 1.4 Companion amendments required at acceptance

This RFC cannot be Accepted alone. It changes what three Accepted texts say:

- **A new RFC-0008 amendment.** RFC-0008 A2 item 4 and A6 say virtual tuple columns are not
  admitted, because nothing established that such a column is fixed before the Unit,
  Beta and Alpha draws. The amendment admits a tuple column that is virtual under §2.1 here: it
  is a fixed polynomial function of columns whose roots are absorbed before those
  draws (§2.4 steps 2.1 and 2.2 precede step 2.3).
- **A new RFC-0026 amendment.** It scopes a lookup check (A3) to one segment; it restates
  A3's "split values bound" for a member value on a virtual column (the value is
  absorbed when sent and then reduced under §2.4 step 4); and it carries the segment
  rule of §2.3. Task E18-06 may accept the segment part first, for committed columns
  only.
- **A new RFC-0012 amendment.** Ledger records for the reductions of §5; no new label.

## 2. Protocol (transcript order)

### 2.1 Column kinds

`stele_ir::relation::Kind` gains `Virtual(Def)`. A definition may read only columns
with a smaller `ColumnId`, so declaration order is a dependency order.

- `Linear { constant, terms: [(c, Ref)] }`: `v(x) = constant + Σ c·f(x)`, integer
  `c ≠ 0`.
- `Pointwise { terms }`: `v(x) = Σ_t c_t · Π_f f(x)`, at most 3 factors per term (the
  term shape of an RFC-0026 identity).
- `Contraction { free, summed, lhs, rhs }`: `v(x) = Σ_y lhs(x,y)·rhs(x,y)`, the
  RFC-0026 §3.5 matmul with `v` in place of the committed `out`.

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
        sumcheck at that point (no fresh `relation/point` draw).
   5. batch the claims on segment `s − 1`'s stacked source, which are now complete,
      and open it; segment `s − 1` leaves memory.
3. Open the last segment. Batch all weight claims per model source and open each
   once. This is the development form and reads each model source in the extension
   field. The stacked weight phase (task E18-07) replaces it: one certified source
   per weight role, one claim on it per proof, and an opening whose row combination
   is the weight pass (RFC-0029 §1.3).

For a relation with one segment and no virtual column, every engine message equals
its RFC-0026 message; only the container framing of §2.5 differs.

### 2.5 Proof container

`stele-dev-e2e-v2`: the v1 sections grouped per segment, plus a `reductions` section
per segment holding, per virtual column in reduction order, its operand evaluations
or its sumcheck messages. The verifier derives every count and length.

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
| carried-column claims | — | the segment root precedes every challenge that produces them | by order (§2.4) |

The composition argument (Q34): by reverse induction over `ColumnId`, every claim
filed on a column equals the evaluation of that column's true multilinear extension
except with the summed error above; claims on committed columns are discharged by the
openings. The argument is written in `formal/` before promotion to `standard` and is a
Lean statement before `treaty`.

Integer faithfulness follows from §2.2.

## 6. Negative controls

Proposed ids, entered in the catalogue when this RFC is Accepted. Each runs through
the actual verifier.

| NC | Tamper | Expected |
|---|---|---|
| 1320 | +1 on one operand evaluation sent for a `Linear` reduction | the consuming check's mismatch error |
| 1321 | prove with a virtual column's values that differ from its definition at one index | `RoundSumMismatch` or `FinalEvaluationMismatch` at its reduction |
| 1322 | commit `y + 1` for one rounding, with `rem` recomputed | the `rem` range lookup rejects (`RootMismatch`) |
| 1323 | read a non-carried column of segment `s − 1` from segment `s` | `StatementMismatch` (validation) |
| 1324 | reorder two segment roots | `RootMismatch` |
| 1325 | declare advice (a rounding output) as `Linear` with the integer that represents a field inverse of `2^k` | `StatementMismatch` (derived magnitude at least `p/2`) |

## 7. Open questions

- **Q31** (restated): this RFC answers it for tuples that are virtual under §2.1.
- **Q34**: the composition statement of §5, for Lean.
- **Q35**: an indexed-lookup argument that leaves the table output virtual by
  committing one table-sized vector per claim. If it holds at acceptable cost it
  removes the committed attention probabilities.
- **Q43**: a commitment-free attained-maximum argument (the product of `M − v_j` over
  the scope is zero), replacing the committed one-hot.

## 8. Amendment log

None.

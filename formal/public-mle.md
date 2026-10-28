# Candidate public-MLE semantics (Q20 / RFC-0006 A4)

Status: Draft. This is a proposed algebra contract, not permission for core code.
It resolves candidate Boolean tables and evaluator costs. It does not resolve A4's
complete reduction descriptor, transcript bytes, source authentication or ownership.
The original research evaluator uses M31. The weighted study in §7 uses both full
extension fields; neither supplies production evaluation or source authentication.

## 1. Common convention

A descriptor fixes ordered axes, bit widths b, real lengths n with 1<=n<=2^b,
and its kind parameters. Bits are most significant first within each axis;
axes concatenate in the stated order. Each bit width is at most 63. Checked
addressability and actual resource limits must precede materialization. A zero-bit
axis has real length one. Empty real axes and mismatched point lengths reject.

For a specified Boolean table T, the coefficient at r is its unique MLE:
`A(r)=sum_v T(v)*eq(r,bits(v))`. Values outside any real axis length are zero.
The table includes every padding/selector rule before extension. Do not replace
it with a product of separately extended unpadded values and validity masks.
An implementation can evaluate without materializing T, but must equal this sum.
All arithmetic in evaluations is exact in K; canonical source bytes never reduce
noncanonical limbs. No float or guessed CQIS approximation defines a table.

A reduction may multiply this public A by separately extended input factors.
That product has its own degree and is not the MLE of their Boolean product.
A4 must bind the choice and include every factor in the A1 degree bound. This
candidate neither adds a commitment nor discharges an original input claim.

## 2. Candidate tables

| Kind | Axes / parameters | Exact Boolean table inside real lengths |
|---|---|---|
| eq | arbitrary ordered axes; full-K target point z | eq(z,bits(v)) |
| causal_mask | equal-width row i then column j; lengths R,C | 1 when j<=i, else 0 |
| window_mask | same axes; positive integer w | 1 when j<=i and i-j<w, else 0 |
| onehot_sparse | row i then category j; lengths R,C; index list q of length R | 1 when j=q[i], else 0 |
| gqa_broadcast | head h then group g; lengths H,G; H divisible by G | 1 when g=floor(h/(H/G)), else 0 |
| rope_tables | explicitly ordered table axes and exact source values | the supplied, authenticated CQIS table entry |

The candidate descriptor in stacked-statement.md additionally defines selected-axis
weights for every kind. Its eq tag uses one as the primitive and places all target
points in those selectors; the all-axis equality above is its fully selected special
case. The general weighted study is described in §7; production evidence remains. These
Drafts do not authorize silently changing a production coefficient polynomial.

The window includes the current position and the preceding w-1 positions. Widths
covering the entire padded row domain reduce to the causal mask. Real row and
column lengths can differ; their padded bit widths must agree for these mask kinds.
Onehot indices must be canonical integers in [0,C); duplicate selections across
rows are allowed. GQA rejects a nonintegral group width; all padded heads/groups
are zero. RoPE's generic table evaluator does not define angles, scales, variants,
sin/cos rounding, a rotation reduction or CQIS table identity.

A per-layer selector can be an explicitly specified axis of the Boolean table;
this proposal does not authorize silently multiplying a separate selector after
extension. The complete coefficient composition and its wire form remain A4 work.

## 3. Bounded equality

For one axis, evaluate
`sum_{0<=v<n} product_j ((z_j*r_j) if v_j=1 else (1-z_j)*(1-r_j))`.
A two-state least-significant-bit dynamic program tracks the borrow in (n-1)-v.
Start with no borrow and value one. Each bit branches over v_j in {0,1}, multiplies
by the indicated weight and adds into the next borrow state. The final no-borrow
state is exactly the bounded sum. Reversing point iteration implements this
calculation without changing the canonical coordinate order. For multiple axes,
multiply their bounded sums: the valid rectangle and equality weights factor by
axis, so this product is the MLE of the specified padded equality table.
Cost is O(sum b) field operations and constant field state per axis.

## 4. Causal and window masks in O(log n)

Let F(k) be the MLE of `1[i<R and j<C and j+k<=i]`, with b row and column bits.
For k>=2^b, F(k)=0. Otherwise process bits least significant first with four bits
of state: carry in j+k, borrow in i-(j+k), borrow in (R-1)-i and borrow in (C-1)-j.
Start state zero with value one. For each candidate i_t,j_t in {0,1}, compute:

```
a = j_t + k_t + carry
carry' = floor(a/2)
compare' = 1 if i_t - (a mod 2) - compare < 0 else 0
row_bound' = 1 if (R-1)_t - i_t - row_bound < 0 else 0
column_bound' = 1 if (C-1)_t - j_t - column_bound < 0 else 0
weight = (r_t if i_t else 1-r_t) * (s_t if j_t else 1-s_t)
```

Add old_state_value*weight to the resulting state. After b steps, take state zero:
no addition overflow, nonnegative comparison, and both actual lengths respected.
R-1 and C-1 fit b bits even when the real length equals the padded length; no
extra boundary bit or invalid complement convention is needed. At b=0 the valid
single cell has F(0)=1 and F(k)=0 for k>0.

Induction: after t steps each state value is the sum of weights of exactly those
low-bit assignments producing its carry/borrows. Every full assignment occurs
once. Final state zero is equivalent to the three inequalities and no overflow,
so F(k) equals the direct Boolean-table MLE. The argument is polynomial expansion
using only ring addition/multiplication; it does not rely on points being Boolean.
The causal mask is F(0). The window is F(0)-F(w), since the second Boolean region
is a subset of the first. Linearity of MLE preserves their difference.

Each step has at most 16 states and four bit choices. Two field buffers of 16
entries suffice; each F costs O(b), with no row/column table allocation. Window
uses at most two such evaluations. This preserves RFC-0009's O(log n) requirement
for these two masks. It does not establish sequence-block-diagonal mask semantics.

## 5. Sparse selection, grouping and exact tables

Build the row and category equality-weight vectors by doubling a prefix vector
for each leading bit: append v*(1-r) and v*r for each old prefix weight v.
This takes O(2^b) field work and capacity. Onehot evaluation is
`sum_{i<R} row_weight[i]*category_weight[q[i]]`, so it takes
O(2^b_row+2^b_category+R) work and equality-vector storage. In RFC-0009's attention
case both domains use the canonical next-power-of-two padding of n positions,
yielding O(n) work, not an n-by-n table. Larger explicit padding is charged in full.
For unequal domains the category-domain cost must be stated; O(R) alone is false.
GQA similarly sums `head_weight[h]*group_weight[floor(h/(H/G))]` over h<H,
with O(2^b_head+2^b_group+H) work and weight-vector storage.

An exact padded public table can be evaluated by ordinary leading-axis folds,
with O(N) field work/storage for N supplied cells. The reference is the direct
weighted sum, so a fold implementation does not define its own polynomial.
RoPE table generation/identity remains governed by the unresolved CQIS contracts;
random scalar table tests are only evaluator tests, not valid RoPE instances.
All these costs move public-coefficient work in T_misc; there is no measured
constant, benchmark, extra weight pass or automatic source-memory bound here.

## 6. Authentication and remaining delivery requirements

The verifier must derive layouts, kinds, parameters and source identity from its
authenticated plan. Original public values must be actual bound public inputs.
A committed selection list requires its real opening/consumer before use; a
prover-provided list, digest, file path, equality to its own copy or caller-set
"verified" flag cannot establish that. RoPE values and identity require their
actual CQIS/passport source. This proposal does not supply either authentication
path and must not be used to mark a source binding complete.

Before A4 acceptance: specify exact descriptor bytes/transcript order and source
consumption; complete reduction degree/final obligations; per-round ownership
for both elimination orders; named errors, controls and registry/accounting edits.
Before E3-06 delivery: independent production prover/verifier evaluations at
10^4 seeded points per kind in both fields, original-source consumers, actual
NC-0203 and other bindings, byte/decision corpus, partial-sum/coordinate parity
and complete cost evidence. The M31 research script earns none of that credit.


## 7. General selected-axis coefficient study

The candidate statement in [stacked-statement.md](stacked-statement.md) fixes a
selector z on any complete axis. For query coordinate r, replace its Boolean
choice weights by `w(0)=(1-r)*(1-z), w(1)=r*z`; without a selector use `(1-r,r)`.
Each weight is linear in r. Use these weights inside the bounded-axis, mask,
sparse-selection and exact-table sums, before any Boolean assignments are added.
This implements the MLE of the complete Boolean table; multiplying a mask MLE
by an independently extended selector does not. It is valid over both K fields,
including nonzero extension limbs, without division or Boolean-only assumptions.

For an axis outside the primitive's chosen axes, its bounded weighted sum factors
out because its assignments and validity are independent. For a shared axis,
insert the same weights into the primitive's actual finite-state transition or
selection/table sum. The §4 induction is unchanged: each state's value is the
weighted sum over its unique low-bit assignments. Only final state zero is valid.
There is no multiplication by another validity MLE after that sum.

`research/stacked-gkr/weighted_mle.py` reuses the candidate codec's validation
and the existing research field arithmetic. Its independent comparison builds
each Boolean table from integer predicates and selector factors, then folds it in
canonical order; it does not call the evaluator's bit weights, DP or sparse sum.
Both paths share field arithmetic, so agreement is not independent field validation.
The script checks 10,000 seeded queries per kind per field, plus 63-bit equality,
31-bit full-K causal/window identities, unequal sparse domains, a three-axis
source, zero-bit axes and malformed query lengths/limbs. Sources are synthetic
resolved inputs; no CQIS identity, commitment opening or NC coverage is established.

Let m be total bits, D descriptor bytes, b_a chosen axis widths, R real rows and
N_s the number of exact source entries. Descriptor admission separately costs
O(D) time and transient bytes because the research evaluator calls the codec.
All kinds retain O(m) weighted pairs; this is additional to the constant-size DP
buffers. The following costs exclude the already-owned source and descriptor:

| Kind | Field work | Additional field storage beyond O(m) pairs |
|---|---|---|
| eq | O(m) | two borrow states per buffer |
| causal/window | O(m), at most two 16-state mask evaluations | two 16-state buffers and four bit-choice products |
| onehot/GQA | O(m + 2^b_row + 2^b_column + R) | O(2^b_row + 2^b_column) |
| exact table on k axes | O(m + sum_a 2^b_a + k*N_s) | O(sum_a 2^b_a) |

The exact-table implementation enumerates real source entries and multiplies k
axis-vector weights per entry; it does not claim the O(N) padded-fold algorithm's
constant. Broadcast axes use bounded sums and never materialize their domains.
These are explicit T_misc work/storage formulas, not benchmark measurements or
production admission limits. Source resolution and original claim consumers
remain separate obligations before A4 acceptance and E3-06 delivery.

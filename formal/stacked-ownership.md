# Candidate stacked round ownership (Q20 / RFC-0006 A4)

Sections 1-4 are adopted by RFC-0006 A4 for the complete A*P summand and a+1
inputs, under the [conditional runtime contract](stacked-runtime.md). The
research evidence and delivery limits in section 5 remain scoped to their
original executions. This lemma alone defines no source authentication or
distributed transport.

## 1. Layout and order

The common input layout has m canonical hypercube coordinates. Its first ell
coordinates are layer bits, most significant first, with 0<=ell<=m. There are 2^ell padded layer
slots and an explicit real layer count L with 1<=L<=2^ell. Remaining coordinates
are the plan's ordered inner axes. Every original input uses this same layout;
its tensor id refers to this exact m-dimensional tensor, not an implicit view of
a larger tensor. A partial view needs its own explicit virtual-tensor identity
and real consumer restoring the remaining coordinates.

Candidate elimination orders are layer-first `(0,...,m-1)` and layer-last
`(ell,...,m-1,0,...,ell-1)`. Each preserves canonical order inside the two groups.
The verifier derives the selected order, layout, real/padded dimensions and
input identities from the authenticated plan and binds them before challenges.
Neither order is a prover hint or timing-based choice. General permutations need
an explicit contract if subsequently admitted; the research baseline also checks
the mathematics of arbitrary axis folds but does not make them this API's modes.

Input padding is zero under the original tensor's semantics. This does not make
an arbitrary P vanish on padded rows: P(0) can be nonzero. The stated sumcheck
still sums its complete hypercube. A reduction that must exclude padding needs
its exact Accepted coefficient/selector polynomial and consumer; the runtime
cannot silently drop padded slots or insert a Boolean selector after extension.
The public reference adapter must check its supplied original padding. Private
padding obligations remain with their actual plan/reduction/PCS consumers.

## 2. Current state and representative ownership

Let pi be the selected order and R_j=(pi_j,...,pi_(m-1)) the remaining axes before
round j. The current input state is the original input restricted at every prior
challenge, stored in R_j order. Restriction happens on each input before nonlinear
P is evaluated; independently folding old P values is a different polynomial.

For a Boolean assignment on any subset U of remaining axes, define rep(U,x) as
the ell-bit layer id that puts each assigned layer bit in its original position
and puts every omitted layer bit at zero. Non-layer bits do not affect rep.
A complete current input entry belongs to rep(R_j,x). These ids select logical
block slots; a physical device can own several slots under the separate plan.

The endpoints paired for round j have current axis pi_j set to zero and one and
a common Boolean suffix x on R_(j+1). Their round destination is rep(R_(j+1),x).
Both endpoint input vectors must be available there before evaluating P. If pi_j
is an inner axis, both already have that owner. If it is a layer axis, the one
endpoint belongs to a different logical owner and must be coalesced with the zero
endpoint. Summing old round messages does not perform this input redistribution.

## 3. Per-block polynomial and fold

For ordered input ordinal i and suffix x, let a_i(x),b_i(x) be those actual
restricted endpoint values. Define

`g_(j,q)(X) = sum_{x: rep(R_(j+1),x)=q} P(a_0+X*(b_0-a_0),...)`.

Expose one delta+1 endpoint vector for every original padded block id q in
[0,2^ell), with zeros for slots owning no suffixes. Ownership depends only on the
fixed layout and Boolean suffix, not on X, challenges, values or polynomial terms.
Every suffix belongs to exactly one slot. Therefore
`sum_q g_(j,q)(X) = g_j(X)` as a polynomial, with degree at most the complete P's
delta. This equality is not limited to Boolean endpoints. Degree zero uses the
single A1 transmitted endpoint and its ordinary constant multiplicity rule.

After the engine absorbs the summed round and draws challenge r_j, store
`a_i(x)+r_j*(b_i(x)-a_i(x))` under the same destination, for every original input
including unused inputs. The next round repeats with the resulting restricted
inputs. It must not keep old layer polynomials and interpolate those instead.
State/round traversal is fixed in canonical slot/suffix/input order; no scheduling
or map iteration may change transcript bytes.

Induction gives both invariants. Initially a permutation only reindexes original
Boolean input values. A fold is exactly restriction of their MLE on the selected
axis, so the next state retains the same original-input meaning. Partitioning its
Boolean suffix assignments by rep is disjoint and exhaustive, proving the round
sum. The final scalar for every input is its original MLE at the canonical point.
Restore that point by setting canonical[pi_j]=r_j; never emit the draw-order list
as an original tensor point when layer-last order differs. Reuse the same restored
point for every corresponding original consumer; final values remain absorbed.

The m=0 case has no rounds, one layer slot, and the empty canonical point. Both
orders coincide when ell=0 or ell=m. Real-layer padding does not change rep's
padded-slot domain or authorize omission of any original input claim.

## 4. Cost and implementation boundaries

At a layer-axis round, exactly a*2^(m-j-1) current field values cross logical block
ownership under this reference rule, for a inputs. At an inner-axis round none do.
This counts one endpoint vector per pair. It is not a physical network byte count:
placement can co-locate owners and a real implementation must measure transport.
The model reads current restricted state, not original weight files. It does not
authorize an extra weight pass or establish fused-opening integration.

Reference state contains a*2^(m-j) input values, plus folded-output overlap if
implemented out of place. Explicit partials contain 2^ell*(delta+1) values.
Materialization, relocation, aggregation and any replica/transport buffers must
be included in actual c_sc/T_misc and memory measurements. The reference rule is
not claimed optimal, distributed, GPU-ready or bounded by partial messages alone.
The CPU prototype models values and logical ownership; it supplies no benchmark.

## 5. Historical closure requirements and research evidence

A4 must still bind the full consumed claim, source identities, public coefficient,
polynomial, canonical layout and elimination order with exact descriptor bytes.
Every public final must be independently evaluated and every original private
claim must reach its real consumer; point restoration is not authentication.
A view, digest or caller-set source flag cannot replace that consumer. Registry,
accounting, typed errors and actual wrong-layer/source/continuation controls must
be specified before this candidate enters core code.

The research oracle evaluates original tables directly at full canonical points
for every round endpoint and suffix, independently grouping the expected partials.
It covers both orders, constant/nonlinear polynomials, unused inputs, zero/one and
non-Boolean challenges, real/padded layers and empty coordinates. This scalar M31
study does not meet the required production both-field bytes/decisions, actual
NC-0203, complete consumers, cost ledgers or CPU/GPU parity gates.

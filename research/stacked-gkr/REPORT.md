# Stacked GKR contract question (Q20)

Question: which exact public coefficient, variable order and block ownership make
RFC-0006 §§3,6 one auditable stacked reduction? Cost terms: c_sc, public coefficient
work in T_misc and redistribution of folded state. Kill criterion: an alleged
interchangeable block/MLE algorithm changes a round polynomial or final claim.
No production implementation or performance measurement is made here.

Reproduce with `python3 research/stacked-gkr/check_stacking.py` (standard library).
The script checks two exact counterexamples and 1,000 seeded axis-elimination
orders against a direct multilinear evaluator in M31. These are algebraic checks,
not production NC credit or a Fiat–Shamir argument.

For two layer values f=(1,3) and P(v)=v², folding the stacked input at r=2 and then
applying P yields 25. Linearly combining the old layer expressions yields 17.
Both yield endpoint values (1,9), so the initial sum identity alone does not expose
the substituted polynomial. RFC-0006 A2's selector-weighted per-member polynomial
is not the same off-Boolean polynomial as P of a globally stacked input MLE.
Neither protocol is declared unsound by this example; silently interchanging their
semantics or final obligations is the error. No existing production bug is claimed:
stele-gkr is still a scaffold.

Likewise, with Boolean selector (1,0) and values (0,1), the MLE of their pointwise
product is zero. The product of their separate MLEs is -2 at r=2. A selector cannot
be flattened into a coefficient table or multiplied as a separate factor without
specifying which polynomial, degree bound and final check the verifier uses.

RFC-0005 §2 fixes tensor layer coordinates first; RFC-0006 §3 allows elimination
with layer bits first or last. These can coexist if the plan binds a permutation
and every emitted point is restored to canonical tensor-coordinate order. The
seeded checks confirm that folding arbitrary axes with the matching permutation
returns the direct canonical MLE value. They do not specify transcript bytes.

Recommendation: amend RFC-0006 through candidate A4 before core implementation.
The draft identifies the global relation, exact public-MLE contracts still needed,
layer-fold redistribution and the proof/consumer boundaries. Accept it only after
all open wire/selector/cost questions are resolved and required reviews pass.
Keep E3-06 blocked on that amendment; E3-03 remains independently deliverable.

## Candidate public MLEs

Question: can the six required coefficient kinds have explicit padded Boolean
tables, independent evaluations and costs consistent with RFC-0009? Cost term:
public-coefficient evaluation in T_misc. Kill criterion: any direct-table mismatch
or mask evaluator whose state/work grows with the full position domain.

Run `python3 research/stacked-gkr/check_public_mle.py`. Six evaluators each match
10,000 seeded direct M31-table queries. Cases include zero-bit axes, irregular
real lengths, Boolean/non-Boolean points, window endpoints, repeated selections,
non-power-of-two GQA group widths and random exact table values. Additional
Boolean queries exercise mask bit widths through 63 without domain allocation.
Malformed shapes, empty windows, out-of-range indices and indivisible groups reject.

The mask evaluator tracks one carry and three borrows over low bits. It retains
16 states, sums every Boolean assignment exactly once and selects the no-overflow,
no-borrow state. A window is the difference between causal-offset predicates at
zero and its width. This gives an algebraic O(log n) evaluator, not a timing claim.
Selection/grouping use equality-weight vectors; their full padded-domain cost is
explicit. A random table fold is not CQIS RoPE generation or authentication.

A padding counterexample remains material: target [5,7], point [2,3], real length
three gives padded equality 252, while multiplying separate unpadded/validity MLEs
gives 2147481337 in M31. Off-Boolean selectors cannot be silently interchanged.

Recommendation: continue Q20 with the candidate algebra in formal/public-mle.md.
Keep A4 Draft and E3-06 blocked until complete bytes, actual source authentication,
claim consumers, block ownership and required reviews are resolved. These checks
are M31 algebra, not full-extension production parity, NC credit, a bound certificate,
a benchmark or profile evidence. No research module is imported by core crates.

## Candidate round ownership

Question: can both permitted layer orders expose deterministic block partials
whose sum is the actual globally restricted polynomial? Cost terms: c_sc/T_misc,
current-state relocation and partial/input storage. Kill criterion: any partial
or restored final differs from direct evaluation of an original input table.

Run `python3 research/stacked-gkr/check_ownership.py`. Across 1,000 seeded layouts
and both orders, 4,000 rounds compare every block's endpoint vector with a direct
original-table restriction and independently computed owner. Final values for all
three inputs, including the unused input, equal original MLE evaluations at the
restored point. Degrees 0..4, empty coordinates, constant terms, zero/non-Boolean
challenges and real/padded layer boundaries are covered. The original tables are
zero-padded, but constant terms intentionally demonstrate why slots cannot be
dropped merely because their inputs are padded.

A suffix is owned by its remaining layer bits in their original positions, with
fixed/currently paired layer bits zero in the representative id. When a layer axis
folds, both endpoint input vectors must reach this representative before nonlinear
P is evaluated. The prototype counts the resulting logical owner crossings and
checks their exact dimension formula. It does not execute distributed transport.
An all-reduce of existing partial messages cannot replace that input movement.

Recommendation: continue Q20 using formal/stacked-ownership.md alongside the
public-MLE algebra. The full statement bytes, source authentication and actual
consumers remain acceptance prerequisites. No production/GPU parity, negative
control, benchmark or profile credit follows from this M31 research model.

## Candidate statement bytes

Question: can the full verifier-owned stacked statement be encoded without
implicit shape, selector, source or coordinate parameters? Cost term: descriptor
and resolved source-byte absorption in T_misc. Kill criterion: an omitted parameter,
ambiguous accepted byte string, unchecked count, or a source-authentication claim
based only on hashing supplied data.

Run `python3 research/stacked-gkr/check_statement.py`. The candidate codec covers
48 descriptors across both extension-field widths, all six coefficient kinds,
both orders and present/absent axis selectors. It retains nonzero extension limbs.
Every descriptor round-trips exactly; all 12,744 truncated prefixes reject, along
with trailing bytes, unknown tags/flags, oversized counts, noncanonical limbs,
invalid shapes/ordinals/source values and duplicate input/coefficient identities.
Independent scalar and source-payload byte constructions check framing. A consumed
claim may alias an input tensor if their layouts agree; ids do not erase points.

The proposed coefficient is the MLE of one Boolean table including validity and
selected-axis equality factors, followed by the separate product A*P. A4 binds
an explicit coordinate frame around A1 and exports only restored original claims.
Its proposed Stack absorb adds no challenge. The field-width codec does not test
full-extension algebra or actual transcript/protocol parity.

Recommendation: continue Q20 with formal/stacked-statement.md and Draft companions
RFC-0012 A6 / RFC-0020 A2. Resolved source bytes are included, but the codec does
not resolve or authenticate a committed index list or CQIS table. The actual fixed
source-consumer interface, weighted evaluator tests, exact production errors,
controls and reviews remain prerequisites. No production registry/dependency,
negative-control coverage, benchmark or profile claim changes here.


## Weighted full-extension coefficients

Question: does the candidate selected-axis descriptor admit the same exact public
coefficient evaluation when selectors overlap mask/source axes? Cost term: T_misc
public evaluation and temporary storage. Kill criterion: any direct-table mismatch,
a separately extended selector product, or domain-sized causal/window state.

Run `uv run --locked --script research/stacked-gkr/check_weighted_mle.py`.
The weighted evaluator multiplies Boolean bit-choice weights before its bounded
or mask DP; sparse/source sums use those same weighted axis vectors. An independent
path builds canonical Boolean tables from predicates/source indexing and folds them.
The paths share the existing research K arithmetic, not evaluator helpers.

The seeded run checks 10,000 queries per kind per field: 120,000 agreements with
nonzero QM31/OM31 limbs, optional selectors, overlapping/reordered axes, irregular
padding, zero-bit axes and source values. Additional cases check unequal sparse
domains, a three-axis source, 64 zero-bit axes, 63-bit equality, a 31-bit full-K
causal/window partition identity, malformed query lengths/limbs and a concrete
failure of multiplying separate mask/selector MLEs.

Recommendation: continue Q20 with formal/public-mle.md §7. Keep A4 Draft and E3-06
blocked pending actual source resolution, Rust consumers/controls, canonical
protocol parity and reviews. The candidate evaluator retains O(m) bit weights
beyond its constant-state DP, copies D descriptor bytes during admission, and
charges k products per exact-table source entry. No measured performance, bound
certificate, authenticated CQIS/index source or production NC credit is claimed.


## Closed public-stage integration study

Question: does the proposed Stack/A1 wrapper restore canonical points, check A
and consume every original public table without losing the continuation? Security
properties: coefficient/original-final binding and the coordinate frame. Cost terms:
c_sc plus T_misc for descriptor processing, actual table movement/evaluation and
public consumption. Kill criterion: accepting a wrong-layer original value, unchecked
coefficient final or stale continuation, or exporting a draw-order original claim.
The study is a closed public algebra relation; it does not authenticate a private
index source, derive a CQIS table or certify a complete inference.


Run `uv run --locked --script research/stacked-gkr/check_stage.py`. The prototype
uses existing field/A1/transcript arithmetic, the independent Boolean-table
coefficient builder, both frame orders and the weighted coefficient verifier.
The fixture binds the actual canonical original table bytes into Public before
Stack; source and selector bytes remain in Stack. A context string without those
original inputs is not sufficient binding evidence.

600 seeded stages per field cover all six coefficient kinds, both orders, degrees
0..4, full-K values, scalar and three-bit domains. Twelve extra cases have no
original inputs, with empty/constant P at m=0/1/3. The public consumer checks all
original values at the restored point; both sides reach the same continuation.
Malformed shapes/limbs/padding and field mismatch reject before replay. Independent
Stack framing and original-public-byte sensitivity checks cover the fixture context.

The one-value wrong-layer and draw-order final examples target an unused original
claim: the conditional reduction accepts them, while the real public consumer
rejects ClaimMismatch. A changed one-entry source with empty P and m=0 rejects
CoefficientMismatch. A stale continuation produced by omitting the first Final
changes only the next proof's original final and rejects FinalEvaluationMismatch.
The verifier has no omitted-final mode or check bypass. These are research
examples, not production controls or private source authentication.

Recommendation: continue Q20 with formal/stacked-statement.md §5. Keep A4 Draft;
exact private source/CQIS consumers, Rust protocol parity, production errors,
resource admission and complete control closure remain open. Charge dense table
reordering/materialization, direct O(a*m*2^m) original consumption, retained table
copies and the bound public context bytes; no performance or inference claim.

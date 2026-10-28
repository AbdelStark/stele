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

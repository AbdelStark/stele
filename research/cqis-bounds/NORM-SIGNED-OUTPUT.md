# RMSNorm signed output (Q26 / Q31)

Revealing research under Draft RFC-0004 A3 for RFC-0022 §2.3's signed-output
equation. The question is whether the same raw X/H sources and signed Y
can bind q=abs(Y) and its sign without allowing rounded zero to hide a
missing canonical product-sign check. Costs are c_a/c_sc/c_lu/T_misc.
Kill the design if a negative product cannot round to zero, q=0 authorizes
a false product sign, a signed source loses its whole range, or an original
claim is accepted only because another operand is zero.

Retain one complete norm_sign child. It consumes both actual signed16 X/H
sources, their magnitude product xy and canonical product sign s, including
both nonzero predicates independently of the rounded output. Retain one
complete signed16 Y consumer, with magnitude q and canonical source sign sy.
Use actual verified magnitude bytes to form q<=32768 and actual verified
flag planes to form Boolean s/sy. One degree-two A3 over N=2^a proves
q*s=q*sy. Both nonnegative sides are<=32768<p/2. All three original views
have independent consumers at emitted points, even when q=0 or s=sy.

For nonzero q, the equation equates the product and output signs. For q=0,
canonical signed Y is zero with sy=0, while s may remain one for a negative
nonzero input product. The complete norm_sign child still enforces canonical
s and both nonzero predicates. Together with Y's signed-source relation,
this is equivalent to (Y+32768)+2*s*q=32768+q. Rounding must separately
join this actual q root with the left-factor or output-division consumer;
this sign relation alone does not establish q's rounded magnitude.

Six external roots bind X,H,xy,s,Y,q. The complete expected schema and
all six roots plus both verified child states precede parent weights,
rounds and finals. No new root or challenge is needed for the three views.
Expected counts retain zero padding in every child and parent relation.
No supplied selector, sign certificate or child receipt is accepted.

Namespace: identity<2^40, base=2^63+2^22*identity. The norm_sign child
uses4*identity+1, whose span starts at base+2^20. The signed-Y child uses
8192*identity+1, whose span starts at base+512. These spans are disjoint.
Parent A3 id262144*identity+131072 follows every child A3 id. View ids
are base+16..18. Six distinct external ids remain outside the parent span.

Account before implementation: the complete norm_sign child contributes
A3 numerator131a+148, signed Y contributes43a+35, and the parent adds3a.
Total A3 loss is(177a+183)/|K|. Each nonlookup label has74a+75 draws.
Retain the ordered norm_sign lookup dimensions (six a+2, then four a+3)
followed by three signed-Y dimensions a+2. Each keeps its separate identity
((2^m+255)/|K|)^r and reduction r*[F(m)+F(8)+3m]/|K|,
F(m)=3m(m-1)/2+2m. At full a14, A3=2661 and each nonlookup label has1111
draws across13 lookup units. Runtime receipts must agree; no reduction is
squared with lookup repetitions.

Tests first:10000 NumPy signed-source and view checks, both signed endpoints,
ragged rows, negative products rounded to zero and padded source zeros.
Forge a valid Y of the wrong nonzero sign, canonical product predicates/sign
at q=0, signed-Y reconstruction and preserving original finals. Check every
external root and zero-hidden operand. Compose actual left-factor and
division proofs on the same q source. Require both fields/repetitions and a
full16384-row proof with nonzero outputs and rounded zeros before publication.

Continue Q26/Q31. Configured branch selection and magnitude rounding remain
separate obligations, as do full normalization, native/model/private inference,
fidelity and original task criteria. No Accepted cut, native control credit,
benchmark number or additional weight pass is claimed.

The tests-first run rejected the missing module. Seed2722 passed10000
NumPy cases and2545743 view cells, including signed endpoints and negative
products rounded to zero. Frozen corpus hash:
`1b8c73debc78bcb8f1e30525b558ced4008d42f96490569fb8f294ab4a3c28a3`.
All six external-root controls, wrong output signs, q=0 canonical-sign/
predicate forgeries and signed-source reconstruction controls passed.
Preserving finals and all three zero-hidden originals rejected. Boundary and
actual left/division composition checks passed. All16 complete proof cases
passed in both fields/repetitions, including exact losses and transcript draws.
Frozen proof-state digest:
`728d00f9932462247186efdd0d4c319be5aa4a2fbe7a289c55b214716e78394c`.
The full-row maximum remains running; gates and hosted CI remain required.

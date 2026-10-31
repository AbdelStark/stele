# Positive attention normalization denominator (Q26 / Q31)

Draft RFC-0004 A3/A6 and RFC-0009 A2 research. Before code: can the actual
eight-byte probability sum prove Q<=Z<=LQ and the correctly scaled positive
denominator D, for both exact and block modes? Costs are c_a/c_sc/c_lu/T_misc.
Kill the design if zero/below-Q Z, a wrong scale, source substitution, modulus
alias, truncated output or missing child is accepted.

Use attention_normalization_bounds.Spec without reducing its domain. Let
Q=2^E, zmax=LQ, F=2^max(fraction-output_fraction-drop,0). A complete wide
range proves 0<=g<=zmax-Q. An existing complete limb product with count 2,
left_max=max(zmax-Q,Q), right_max=1 and radix 8 proves Z=g+Q. Its exact inputs
are the verified gap bytes and public Q bytes, with both right operands one.
Join its scalar output to the full eight-byte external Z root. This proves
the lower and upper bound through faithful columns, without a whole-field Z
equality. A zero gap remains a complete range and proof.

A second complete limb product with count 1, left_max=zmax, right_max=F and
radix 8 proves D=Z*F. Its left bytes must equal that same verified positive
sum output; its right bytes equal the expected constant F. Every high source
byte outside a compact operand is zero. Both products retain their complete
input, output and carry consumers, actual operand claims and public powers.

The external denominator always has sixteen bytes. Exact mode permits
L=2^20, E=14, fraction=30, output_fraction=0, drop=0, giving Dmax=2^64 and
nine significant bytes. Eight bytes would truncate a valid boundary. Zmax
still fits eight bytes. Static expected schemas determine every range and
limb-column bound. No observed value determines admissibility or a bound.

Reserve identity<2^44 and base=2^63+2^18*identity. The gap wide range uses
id 4096*identity+1 with root base+1. Positive-sum and denominator limb products
use ids 64*identity+1/+2 with input/output roots base+2/+3 and base+4/+5.
External source/output ids are distinct and outside this span. Confirm every
inherited namespace remains disjoint. Full normalization schema, roles,
field/repetition bytes, both external roots, five internal roots and three
verified child states bind the returned composition state.

No wrapper challenge is added. Metadata with identical arithmetic may reuse
the same valid child proof, but the returned state must change. Callers must
bind that state and the actual upstream Z root. This does not prove global
attainment or key ownership; it rejects an inadmissible divisor even if an
upstream sum proof is otherwise valid.

Let bg be the gap compact-byte exponent. Let bp,gp,kp be the positive-product
input-byte/output-slot exponents and result-column count; bd,gd,kd are those
of the denominator product. Seven independent lookup dimensions are
bg+1,bp+3,gp+3,gp+3,bd+2,gd+3,gd+3. Each retains ((2^m+255)/|K|)^r and
unsquared reduction r*(F0(m)+F0(8)+3m)/|K|, F0(m)=3m(m-1)/2+2m.
Range/A3 numerator is 7bg+9(bp+bd)+18(gp+gd)+73. Product identity losses
kp-1 and kd-1 remain separate; total A1 reduction is 2+4(bp+bd).
Nonlookup draws are 3bg+4(bp+bd)+8(gp+gd)+31 ZeroWeight and
3bg+6(bp+bd)+8(gp+gd)+34 Sumcheck. Confirm actual receipts before claiming
evidence. Every inherited original consumer remains mandatory.

Tests first: 10000 independent integer products, full byte roots and NumPy
column convolutions over both modes, unit directions, legal shifts and
short/full lengths. Both fields/repetition counts cover zero gap and the
2^64 denominator. Attack every root, exact input/constant join, zero-hidden
one, output/carry relation, original and public power. Include genuine ranged
Z-p and D-p aliases, below-Q/zero divisors, gap overflow and full high planes.
Compose actual global probability sums, including a separately valid zero
sum which normalization must reject. Require full-metadata exact and block
boundary proofs and every repository gate.

This establishes an admissible divisor source for normalization. Magnitude
scaling, signed division/rounding, source ownership, shared global attainment,
native/private model inference, fidelity and all original criteria remain
required. No measured constant, benchmark, new cut or extra weight pass is
claimed. Continue Q26/Q31; Draft amendments remain unaccepted.

Seed 2742 passed all 10000 independent cases and 52440 byte-column cells,
including 3711 zero gaps. Exact/block modes, all admissible shifts, both unit
directions, all compact widths and the exact D=2^64 boundary were covered.
NumPy integer products, complete roots and independent convolutions matched.
Frozen corpus SHA-256:
`de3d8ef594b88bdb8a3bf6a3fe8394b2fc7cb39b8ab7e1da76eba50977fff5bd`.

Primary controls passed. Both external roots and every gap/Q/one/Z/factor
join retained their consumers. All four actual operand views and four public
powers rejected forged claims. Equivalent arithmetic metadata changed the
returned state. Boundary, composition, matrix and full-metadata proofs remain
under validation, with required repository gates queued once.

Boundary controls passed: genuine output-ranged Z-p and D-p aliases rejected
at the positive-sum and denominator product equations. Zero and below-Q sums,
gap overflow, high external planes and zero-cap overflow also rejected.
A complete global probability-sum proof composed on its actual source root;
valid changed and zero sums could not replace that admitted divisor source.
The matrix and two full-metadata boundary proofs continue in the original
runner. Required repository gates remain queued.

All 16 matrix proofs passed across both fields and repetition counts with
exact child receipts, draw totals and all original consumers. Frozen SHA-256:
`2520ceaff93a6febade2446752866ccc783348fe26dd2a11a363387e9427f134`.
Both full-metadata scalar proofs passed at length 1048576 and width 16384:
exact D=2^64 and block D=2^48. Their combined frozen SHA-256 is
`6219b6f737469a0ee7ea8e0d1f2d8b08296c4c8534a89b8ec00bba4f4cd2dfbd`.
The original runner completed successfully. These scalar proofs establish
the divisor boundary; upstream key/channel ownership and repository gates
remain separate obligations.

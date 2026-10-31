# Consumed signed attention block totals (Q26 / Q31)

Draft RFC-0004 A3/A6 and RFC-0009 A2 research. Before code: can one sumcheck
consume actual block signs and rounded quotients for every channel, preserving
both sources when rounding produces zero? Costs are c_a/c_sc/c_lu/T_misc.
Kill the design if a false channel total, modulus alias, substituted block root,
zero-hidden original or supplied projection can pass.

The expected attention block schema fixes qmax<=32767 and Bmax=ceil(L/1024).
Let G=Bmax*qmax. Consume increasing unique absolute block ids within Bmax,
one sign root per block, one dense two-plane quotient root, and an eight-plane
output-offset root over channels. The conditional research cap remains16384
actual block/channel entries, including all1024 block ids at narrow widths.
The original full-entry and ownership requirements remain open.

Three complete ranges, in order sign,quotient,output, bound b in[0,1],
q in[0,qmax] and U in[0,2G]. Dense sign/quotient domains use one final padding;
each sign root gathers its actual verified bytes with per-block channel padding.
Quotients retain two external planes when their compact cap is zero. U retains
eight external planes, with channel padding zero. The intended relation is

    U_c - G = sum_b (1-2*b_bc)*q_bc.

A negative raw sign with rounded q=0 is valid. Never suppress its source root
or original-point obligation. No signed-block intermediate is committed.
The exact integer identity can be written U+2*sum(b*q)=G+sum(q). Each
nonnegative side is at most4G; require8G<p from static metadata. Thus distinct
integer totals cannot alias in M31 before channel batching.

Draw ac=log2(padded channels) coordinates only after all schema/role/block
metadata, external/auxiliary roots and verified child states. Their equality
weights lambda_c project the channel equations. Construct actual linear view
A_bc=lambda_c*q_bc on real dense entries, zero on padding, and actual view B=b.
One degree-two A1 over a=log2(padded dense entries) proves
sum(A-2*A*B)=sum_c lambda_c*(U_c-G), subtracting G only on real channels.
The verifier forms linear views of verified bytes; it never recomputes b*q.
Both original views retain independent consumers at the emitted point.

Reserve identity<2^48, base=2^63+2^14*identity. Three wide ranges use ids
256*identity+1..3 and roots base+1..3; all external roles are distinct outside
the span. Parent A1 id1024*identity+128 uses views base+16,+17. No new label,
cut, profile or production control credit is introduced.

For compact byte exponents bq,bo, ordered lookup dimensions are a+1,a+bq+1,
ac+bo+1. Each retains independent identity ((2^m+255)/|Kfield|)^r and unsquared
reduction r*(F(m)+F(8)+3m)/|Kfield|, F(m)=3m(m-1)/2+2m. Range/A3 numerator is
18a+9ac+7(bq+bo). Channel identity ac and degree-two A1 reduction2a remain
separate. Parent draws ac+a of Sumcheck only. Full nonlookup draw totals are
8a+4ac+3(bq+bo) ZeroWeight and9a+5ac+3(bq+bo) Sumcheck. Dimension zero draws
no challenge and still consumes both originals. Confirm exact runtime receipts.

Write tests first:10000 independent NumPy signed sums and byte roots across
policies, shifts, short/partial/full lengths, sparse blocks and zero quotients.
Both fields/repetitions cover dimension zero, ragged channels and compact zero
caps. Attack every root/range, false bounded totals, compensating channels,
output+p with relaxed range witnesses, nonboolean signs and quotient/output
bounds. Change each original while preserving the final polynomial; retain
zero-quotient signs. Reject metadata replay, valid swapped block sources,
padding and high external planes. Compose actual canonical-sign and complete
block-rounding proofs on the same roots, including valid replacement rejection.
Require full128x128,1024x16 and1x16384 geometries and repository gates.

This establishes an unsigned offset for signed rounded totals. Canonical total
sign/magnitude, the actual global probability sum, restored normalization units,
complete absolute-key/block/model ownership, native/private inference, fidelity
and every original production criterion remain required.

The tests-first run rejected the missing module. Seed 2739 passed10000
independent cases and165678 entries, including6835 all-zero quotient cases
and64010 negative raw signs paired with rounded zero. These are valid raw
signs, not a noncanonical sign encoding of zero magnitude. Short, partial and
full lengths, sparse blocks, all admissible shifts and compact byte widths
were covered. Frozen corpus SHA-256:
`aa02e228b2512898004c4f1261746a7fab48f7513408c81bb542d58bd101fa00`.

Primary and boundary controls passed. False bounded totals, compensating
channels, output+p, metadata replay and valid source substitutions rejected.
Both original consumers rejected compensated final values; negative raw signs
at q=0 remained consumed. Boolean bounds, whole bounds, dense/per-block padding
and full high planes rejected. Initial receipts and draw totals matched.
Complete canonical-sign and block-rounding proofs composed for shifts26 and62,
including negative raw signs at rounded zero. Valid replacement sign and
quotient sources rejected their pinned roots. The matrix and three full
geometries continue in the original runner; repository gates remain queued.

All 16 matrix proofs passed across QM31/OM31 and both repetition counts.
Every receipt, original count and draw total matched. Frozen SHA-256:
`701f68e006fa0f2b22c62703ecfadb4ce7c23a649d91406dc2ab5f98718aa14d`.
The three full geometries continue in the original process; their completion
and the queued repository gates are still required.

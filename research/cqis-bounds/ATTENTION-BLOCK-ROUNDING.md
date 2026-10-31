# Consumed attention block rounding (Q26 / Q31)

Draft RFC-0004 A3/A6 and RFC-0009 A2 research. Before code: can one batched
byte-column proof round actual magnitude sources from distinct absolute blocks
without losing their source roots, strict remainder, bias or high shift bits?
Costs are c_a/c_sc/c_lu/T_misc. Kill the design if a modulus alias, coherent
r=D, omitted bias, wrong block join or compensated original passes.

The expected block schema fixes length, channel width, value units/policy,
probability exponent and drop c in [0,62]. Existing block bounds derive
Hmax=1024*Q*S, D=2^c, h=floor(D/2), qmax=floor((Hmax+h)/D)<=32767 and rmax=D-1.
Reject a schema that cannot guarantee this quotient cap. The block id tuple
is increasing, unique and within ceil(length/1024). The conditional research
capacity is 16384 actual block/channel entries; the original full domain and
source completeness remain required. Support all 1024 absolute block ids.

Consume one eight-plane magnitude root per supplied block. The complete M
range uses dense block/channel order with one final power-of-two padding.
For each block, gather its actual verified bytes and add the channel padding
required by that block's source root. This O(entries) join preserves separate
source identities without a supplied projection or plaintext magnitude claim.
Bind two additional roots: two-plane quotient and eight-plane remainder over
the dense padded domain. Compact q may use one byte or have cap zero; external
q still uses two planes. Remainder width must cover all 62 shift bits.

Five complete ranges, in order M,q,r,carry_0,carry_1, precede the parent.
They bound M<=Hmax, q<=qmax, r<D and two four-plane carry groups. For each byte,
M_k+h_k+c_k=Q_k+r_k+256*c_(k+1), where Q_k is the appropriate actual quotient
byte times 2^(c mod 8). Natural carries lie in [-129,2]. Offset each by 129
on real entries and zero on padding. Then

    M_k + h_k + 32895 + B_k = Q_k + r_k + 256*B_(k+1).

Initial and terminal B equal 129 on real entries. Static nonnegative sides
are at most 66431<p/2. Before using eight columns, require Hmax+h<2^64 and
qmax*D<2^64. This rules out discarded high products even at c=62, where the
configured q cap is zero. One degree-one A3 consumes terminal carries; a
second degree-one A3 batches all eight columns. Retain all eight originals,
including quotient bytes hidden by a large shift and public bias/masks.

Reserve identity<2^48 and base=2^63+2^14*identity. Five ranges use ids
256*identity+1..5 and internal roots base+1..5; all block-source and output ids
are distinct and outside the span. Parent A3 ids are1024*identity+128..129,
views base+16..23. Expected schema, block ids, source roles, field/repetition
metadata, every external/internal root and all verified child states precede
parent challenges. No new label, cut or Accepted role is introduced.

For a=log2(padded dense entries), bm,bq,br compact byte exponents, ordered
lookup dimensions are a+bm+1,a+bq+1,a+br+1,a+3,a+3. Each independently keeps
((2^m+255)/|Kfield|)^r and unsquared reduction r*(F(m)+F(8)+3m)/|Kfield|,
F(m)=3m(m-1)/2+2m. Total range/A3 numerator is49a+7(bm+bq+br)+42; the parent
contributes4a+6, already included. Parent draws2a+3 per nonlookup label;
full totals are22a+19+3(bm+bq+br) per label. Confirm actual receipts.

Write tests first:10000 Fraction/NumPy rounding, canonical roots and independent
prefix-carry cases across both value policies, all legal shifts and rejected
static bounds. Exercise sparse absolute blocks, ragged channels, compact zero
quotients and high remainders. Both fields/repetitions must cover dimension
zero and mixed widths. Attack every source/output root and range, bounded M+p,
coherent r=D, missing bias, carry endpoints, padding and all original claims.
Reject valid source substitutions, block/unit metadata replay and bad lengths.
Compose complete canonical-sign proofs from multiple blocks using exact roots.
Require full 128x128, 1024x16 and 1x16384 geometries plus repository gates.

This proves unsigned rounded magnitude and remainder. The raw sign can be
negative when the rounded quotient is zero; downstream signed output must
handle that case correctly. Signed block outputs, aggregate totals, restored
normalization units, actual block/key/source ownership, native/private proof,
fidelity and every original production criterion remain required.

The tests-first run rejected the missing module. Seed 2738 passed 10000
independent cases: 7524 accepted configurations, 2476 expected static-bound
rejections and 200396 accepted entries. All admissible shifts 2 through 62
were covered. The frozen corpus SHA-256 is
`1850340c4ffdd3789ae47ee3facd3b917ffbd287708d7c626c5f8f9fb71b8f06`.
Separate checks passed for short, partial and full absolute-block domains.
Observed carries ranged from -127 to 1; the static envelope remains [-129,2].

Primary and boundary controls passed, including bounded M+p, coherent r=D,
omitted bias, every original, metadata replay and valid source substitution.
Shift 62 retained its zero quotient, actual original consumer and full external
planes. Complete canonical-sign proofs from two blocks composed through ragged
source joins; a valid replacement rejected its pinned block root. Initial
receipts and draw totals matched. The matrix and three full geometries continue
in their original runner; required repository gates remain queued.

All 16 matrix proofs passed in both fields/repetition counts. Every receipt,
original count and draw total matched. Frozen SHA-256:
`bf7336eb47a775cb6e1386fda3d8a93cc4c264510d9605fa36759c250f12e566`.
The original runner continues the three full geometries; those proofs and
required repository gates remain pending.

# Attention quotient product (Q26 / Q31)

Draft RFC-0004 A3/A6 and RFC-0009 A2 research. Before code: can every bounded
quotient q bind Qp=q*D to the actual shared denominator across all 16384
channels, with sixteen product bytes and complete two-byte carries? Costs are
c_a/c_sc/c_lu/T_misc. Kill the design if a false product, wrong broadcast,
source substitute, modulus alias, dropped carry byte or missing original
consumer is accepted, or the supported domain is narrowed.

Use the full attention_normalization_bounds.Spec. A complete wide range
proves 0<=q<=32768 with two external byte planes; scalar D retains sixteen
external bytes and its complete expected whole range. The product cap is
32768*Dmax<2^128. Product outputs retain all sixteen external planes. Use
G=1 when N times the compact output width is at most 131072, otherwise G=2.
Each G=2 child has exactly N/2 caps, with the product bound on real channels
and zero on unused channels. Repack verified groups in plane-major order.
This preserves the existing range capacity and every ragged channel count.

For column j, prove
q_low*D[j]+q_high*D[j-1]+carry_in=Qp[j]+256*carry_out,
where D[-1]=0. Both q byte planes are actual verified sources. D and its
one-column shift broadcast the actual verified scalar bytes to all N
channels; padded q bytes are zero, so their products remain zero. Four
complete carry ranges each cover four planes of N entries, capped at 510 on
real channels and zero on padding and the final column. Initial carry is
zero. Their two-byte words must be reconstructed from both verified planes;
whole carries are at most 510 and safely embed into M31. Each group contains
at most 65536 words and 131072 bytes, within the existing range capacity.

The left side is at most 2*255^2+510=130560. The independent right-side
bound is 255+256*510=130815. Use the larger bound for both sides and check
2*130815<p before proving. Static product bounds exclude overflow beyond
sixteen columns. No whole-field D or product equality, dynamic bound or
verifier-side plaintext multiplication admits Qp.

One degree-two A3 over 16N entries consumes seven actual originals: both q
bytes, D, shifted D, carry-in, Qp and carry-out. All inherited packing, range,
lookup and original claims remain mandatory. Full schema, field/repetition
bytes, three external roots, every internal root and verified child state
precede the parent transcript. Zero q or D never removes a consumer. A
standalone D=0 product does not prove positivity; the actual positive source
must compose on the same root. q is only bounded here: its correct rounding
requires the strict division/remainder relation on the same q and Qp roots.

Identity<2^48 reserves base=2^63+2^14*identity. Ordered children are q,
G product groups, D and four carry groups: 6+G ranges. Their wide-range ids
are 256*identity+1..count with source roots base+1..count. Inherited spans
start at base+64..base+64*count. Parent A3 id is 1024*identity+128, with
original ids base+16..22. External roles are distinct and outside this span.
Test all namespace limits and retain exact canonical encodings.

Let a=log2(N), bp/bd be product/denominator compact-byte exponents and G the
product group count. Independent lookup dimensions are a+2, G copies of
a-log2(G)+bp+1, bd+1 and four copies of a+4. Each identity is
((2^m+255)/|K|)^repetitions, with unsquared reduction
repetitions*(F(m)+F(8)+3m)/|K|, F(m)=3m(m-1)/2+2m.
Range/A3 numerator is 57a+7bp+7bd+119 for G=1, or
66a+14bp+7bd+101 for G=2. Parent loss is 3(a+4).
Parent draws a+4 per ZeroWeight/Sumcheck label. Full nonlookup draws per
label are 25a+3bp+3bd+51 for G=1, or 29a+6bp+3bd+43 for G=2.
No A1 or new challenge label. Verify exact receipts and all seven original
points; binding/FS/H and complete upstream source proofs remain additional.

Tests first: 10000 independent NumPy integer products, byte roots and column
carries, including nonzero high carry bytes, q=32768 and D=2^64. Capacity
cases cover both group families and ragged 8193 channels. Both fields and
repetition counts must retain all seven originals, including q hidden by
D=0 and D hidden by q=0. Attack every root, fresh false values, high carry
bytes, a genuine product-minus-p alias, whole caps, endpoints and padding.
Compose actual positive denominators and reject valid substitutes. Require
complete 16384-channel proofs for the G=2 maximum Qp=2^79 and a G=1 case
with nonzero high carry bytes, plus every repository gate. Queue full proofs
behind the existing full biased-numerator runs without restarting them.

Continue Q26/Q31. Strict remainder, signed output and final conversion must
consume these actual roots. Global attainment, complete key/block/model
ownership, native/private inference, fidelity, independent audit and all
original task criteria remain required. No benchmark, new cut, capacity
increase or additional weight pass is claimed. Draft amendments remain
unaccepted.

# Canonical accumulated block sign (Q26 / Q31)

Draft RFC-0004 A3/A6 and RFC-0009 A2 research. Before code: can the actual
accumulated offset U prove M=abs(U-G) and canonical b=[U<G] through complete
small-integer consumers, including G=0? Costs are c_a/c_sc/c_lu/T_misc. Kill
the design if negative zero, a range-bypassing modulus alias, a wrong total,
metadata replay or a compensated original passes.

The expected block schema gives qmax<=32767 and G=ceil(L/1024)*qmax<2^25.
Retain its expected increasing unique absolute block ids. This stage consumes
one eight-plane U root over channels and emits eight-plane M and one-plane b
roots. Its work depends on channel width, at most16384, and block metadata.
It does not allocate or prove the upstream block/channel grid. The maximum
conditional proof therefore does not establish full upstream source ownership.

Four complete ranges, in fixed order offset,magnitude,sign,predecessor, bound
U<=2G, M<=G, b<=1 and g<=G. Preserve canonical padded zeros. Only after these
ranges may actual byte values be lifted to M31. One degree-two A3 enforces

    U + 2*b*M = G*real_mask + M.

One degree-one A3 enforces M=g+b. The first equation gives signed magnitude;
the second excludes negative zero. A negative raw block sign can accompany
rounded zero upstream, but the accumulated total zero must have b=0.
Nonnegative sides are at most4G for sign and G+1 for canonical zero. Require
2*max(4G,G+1)<p from static metadata. This includes G=0 without an alternate
verification path or missing child. No wide field equality replaces a bound.

Both A3s retain every original view: U,b,M,Gmask and M,g,b, seven claims in
all. The same actual M and b views are independently consumed at both emitted
points. Derive Gmask only on real channels. Keep all eight external U/M planes
when compact ranges use one, two or four bytes. No new carry grid is needed.

Reserve identity<2^48 and base=2^63+2^14*identity. Four wide ranges use ids
256*identity+1..4 and roots base+1..4. Parent A3 ids1024*identity+128..129 use
virtual views base+16 U,+17 b,+18 M,+19 Gmask,+20 g. External roles are distinct
and outside the span. Expected schema/block/role/field/repetition bytes, all
three external roots, four internal roots and verified child states precede
parent ZeroWeight and Instance/Round/Final schedules.

For a=log2(padded channels), bo and bm the compact byte exponents of U and M,
ordered lookup dimensions are a+bo+1,a+bm+1,a+1,a+bm+1. Each independently
retains ((2^m+255)/|Kfield|)^r and unsquared reduction
r*(F(m)+F(8)+3m)/|Kfield|, F(m)=3m(m-1)/2+2m. Full range/A3 numerator is
41a+7(bo+2bm), including parent5a. Parent draws2a per nonlookup label; full
totals are18a+3(bo+2bm) per label. Dimension zero has no parent challenge.
Confirm every receipt and original count. No new A1, label or cut is added.

Tests first:10000 independent NumPy differences, canonical signs, whole
predecessors and byte roots across policies, legal shifts, lengths and compact
widths. Both fields/repetitions cover G=0, mixed U/M widths, cancellation and
extreme totals. Forge negative zero while the sign equation still holds;
attack each root/range, relaxed-cap U/M/g+p witnesses, all seven original
claims, metadata replay, whole bounds, padding and high planes. Compose
complete block-sum proofs on the actual U root, including negative raw signs
at rounded zero and a valid changed aggregate. Require a full16384-channel
proof at maximum block metadata and every repository gate.

This supplies canonical magnitude/sign for block normalization. The actual
global probability sum, restored normalization units, full block/key/model
ownership, native/private inference, fidelity and all original criteria remain
required. No production admission or measured performance claim follows.

Seed 2740 passed all 10000 independent corpus cases over 329725 channels,
including 6660 zero-bound cases. Both unit policies, every admissible shift,
short/partial/full lengths and all five observed U/M compact-width pairs
passed. Whole predecessors, canonical signs and complete external byte roots
matched NumPy. Frozen SHA-256:
`14c2f3733de98a71593e189c89e72d4d7facd86e07c38f8a64faf9d29f40e2f2`.

Primary and boundary controls passed. Negative zero rejected at CanonicalZero,
including dimension zero; relaxed-cap modulus aliases rejected at their cap
relations. All seven original views, metadata replay, Boolean/whole bounds,
dense padding and full external high planes retained their consumers.
Complete block-sum sources composed at shifts 26 and 62. A valid changed
aggregate rejected the pinned U root. At rounded zero, a changed upstream
sign rejected its upstream root while the unchanged aggregate remained valid.
The proof matrix and full 16384-channel proof continue in the original runner;
required repository gates remain queued once.

All 16 matrix proofs passed across both fields/repetition counts, including
the zero static bound and mixed compact widths. Every original, receipt and
draw total matched. Frozen SHA-256:
`6ad91d56e515a63ac2ccab994cd9f5b5c6cca5ef517f6a70d0c328392b4ac595`.
The full 16384-channel proof continues in the original runner. Required
repository gates remain queued.

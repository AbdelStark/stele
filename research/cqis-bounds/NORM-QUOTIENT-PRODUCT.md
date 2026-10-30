# RMSNorm quotient product (Q26 / Q31)

Revealing research under Draft RFC-0004 A3 for RFC-0022 §§2.1,2.3,5.
This consumes qd=q*B only. The selected branch, rounding equation, strict
remainder, signed output and complete normalization remain required.

Question before implementation: can one batched byte-column relation consume
q<=32768 and a positive scalar B<=Bmax across all16384 rows, including
Bmax=2^90, without increasing the current range/lookup domain? Cost terms are
c_a/c_sc/c_lu/T_misc. Kill the design if separate result halves are mistaken
for a whole-result bound, a column or original source claim escapes checking,
a carry endpoint is omitted, a zero quotient hides a substituted factor,
or the divisor is presented as authenticated solely because its id matches.

Range q as a whole two-byte word. Range the scalar offset B-1<=Bmax-1;
reconstruct B exactly from its verified bytes and add one. Compare the
canonical16-slot B root to the independently expected root. This enforces
positivity without reducing a wide integer into M31. Complete same-exponent
factor authentication remains separate and must compose on actual bytes.

Let Zmax=32768*Bmax. Range the low64 output part with cap min(Zmax,2^64-1)
and, when nonzero, the high part with cap floor(Zmax/2^64). The two ranges
have at most eight byte planes each. Zero-extend their verified views to a
canonical16-plane qd root. These independent caps supply digit bounds; they
do not establish qd<=Zmax. That whole bound follows only after integer
multiplication by the actual bounded q and B is proved.

Use the closed quotient_product column certificate. Partition C1..C16 into
four families of four planes. A family with all static caps zero is public
zero; otherwise give it a whole-word range with real row caps from the
certificate and padded row caps zero. Its width is at most two bytes, so
4N words still fit131072 bytes. Every terminal and unused carry is zero.
There are no supplied selectors or choices of active families.

Let P=2^c pad the closed column count K to a power of two. One degree-two A3
over PN entries proves q0*B_k+q1*B_(k-1)+C_k=qd_k+256*C_(k+1).
Public zero extension covers missing B bytes and every output byte beyond P.
All seven original derived views have independent consumers at emitted points.
External roots, every auxiliary root and every verified range state precede
parent weights, rounds and finals. No per-element proof loop or new public
MLE kind is introduced.

At maximum metadata, K14/P16 and Zmax=2^105. Carry caps are
[0,254,382,382,382,382,382,382,382,382,382,382,132,2,0]. Maximum column side
is98047, with twice that below p. Full whole-input and digit/carry bounds,
zero endpoints and faithful columns yield the integer product. The external
result has262144 canonical-u32 slots at N16384; each range remains at most
131072 bytes and each lookup dimension at most18.

Namespace: identity<2^44, base=2^63+2^18*identity. Range ids are
4096*identity+1..8: quotient, offset, low, optional high, and carry families0..3.
Omitted families retain their reserved ids. Quotient source is external;
other sources use base+1..7. Parent A3 id is16384*identity+512, and seven
view ids are base+16..22. Three distinct external ids stay outside the whole
span. All descendant A3 ids end before the parent invocation.

Before implementation, let a=log2N, bd/bl/bh be the offset/low/high range byte
width exponents, h indicate an active high range, and g count active carry
families with byte exponents bg. Define X=1+bd+bl+h*bh+sum(bg).
Total A3 numerator is (21+9h+9g)*a+7X+18g+3c. Each nonlookup label has
(9+4h+4g)*a+3X+8g+c draws. Lookup dimensions are a+2, bd+1, a+bl+1,
a+bh+1 when h=1, and a+bg+3 for each active carry family. Retain each separate
identity ((2^m+255)/|K|)^r and reduction r*(F(m)+F(8)+3m)/|K|,
F(m)=3m(m-1)/2+2m. At full metadata A3=1106 and each nonlookup label has
484 draws. Runtime receipts must verify these counts, including smaller shapes.

Tests first:10000 independent NumPy byte convolutions and exact wide products,
metadata/width transitions, full-domain geometry, both fields/repetition counts,
and exact receipt totals. Fresh false products, field aliases, independently
valid halves beyond Zmax, changed carries/offsets, zero-hidden originals,
padded rows and endpoints must reject. Compose actual signed-Y magnitude and
verified output-factor bytes; reject valid substituted factors. A full16384-row
proof with90-bit B must pass before publication. No native/physical/model/private
admission, new production cut, NC credit or measured performance is claimed.

## Current evidence

The tests-first run rejected the missing module. Seed2718 passed10000
independent NumPy convolutions and exact wide products, covering6767440
byte-column entries, metadata boundaries and full-domain geometry. Frozen
corpus SHA-256:
`9070ddcc675628bc070b46e26f5c548aa7a2b9c554682066ab9c04557bb2197b`.
Controls, composition and the honest field/repetition matrix are running.
Full-row proof, required CI integration, repository gates and final review
remain pending. Reproduce with
`uv run --locked --script research/cqis-bounds/check_norm_quotient_product.py`.

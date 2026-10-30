# Full-row RMSNorm statistic (Q26 / Q31)

Revealing research under Draft RFC-0004 A3 for RFC-0022 §§2.1,2.3,5.
The existing statistic adapter and its proof encoding remain unchanged.

Question before implementation: can the complete signed16 source support the
entire d<=16384 domain with three direct byte-column sums and bounded scalar
carries? Cost terms are c_a/c_sc/c_lu/T_misc. Kill the design if it needs an
observed bound, aliases S with S+p, omits an original source claim, drops a
boundary or high byte, or claims full/private RMSNorm from this one role.

Verify a complete signed16 source, a scalar whole range S<=d*2^30, and the
closed statistic carry vector from RFC-0022. Include both zero endpoints in
the carry range. The vector has five to seven entries and pads to eight.
Read low/high magnitude byte views from the verified signed source. Three
degree-two A1 instances over N=2^a padded rows prove sums of low^2,
2*low*high, and high^2. Their initial sums are S_k+256*C_(k+1)-C_k,
derived from the actual verified scalar bytes. Five further dimension-zero
A1 instances with no terms enforce the remaining byte columns through k=7.
Every carry beyond the closed vector is zero; all output padding is retained.

All four original byte-view claims have independent full hypercube consumers
at their emitted points. Zero operands do not remove these obligations. The
three child states, four roots and complete expected norm metadata precede
the parent instances. Each initial sum is absorbed in its A1 instance before
round challenges; finals precede the next instance. There is no polynomial
compression challenge, random column combination or per-row proof loop.

The whole S range uses four or eight byte slots. Reconstruct the external S
root from its actual verified bytes with exact zero extension to eight slots.
This preserves the old statistic and numerator root layout. The raw X root
also preserves the signed16 byte-plane layout. Neither root is packed model
storage or a private commitment. Full source ownership remains separate.

At d=16384 the closed carry caps are
[0,4161600,4194176,1064959,4159,16,0]. The largest nonnegative column side is
1073709311; twice that is 2147418622<2147483647. Whole magnitude/S ranges,
actual carry bounds, and both zero endpoints lift each accepted field column
to an integer equality. Weighted column summation cancels carries and yields
S=sum X_i^2. No verifier-side integer sum of squares establishes acceptance.

Namespace: identity<2^44, base=2^63+2^18*identity. Signed child identity is
512*identity+1, occupying [base+512,base+1024). Output/carry range identities
are 4096*identity+65,+66, occupying [base+4160,base+4288). Magnitude and
scalar range source ids are base+1,+2,+3. Parent A1 ids are
16384*identity+512..519; byte views use base+16,+17. The signed child's
descendant A3 ids end below the scalar ranges' A3 ids, which end below parent
A1 ids. Distinct external raw/S ids remain outside the whole parent span.

Before implementation: let bs=log2(S byte width), bc=log2(carry byte width).
The signed child contributes A3 numerator43a+35. Scalar ranges contribute
27+7*(bs+bc), so total A3 is 43a+62+7*(bs+bc). Parent A1 adds 6a separately.
Lookup dimensions are a+2 three times, bs+1 and bc+4. Retain each identity
((2^m+255)/|K|)^r and reduction r*(F(m)+F(8)+3m)/|K|,
F(m)=3m(m-1)/2+2m. Neither A1 nor A3 loss is squared with lookup repetitions.
Nonlookup ZeroWeight count is18a+26+3*(bs+bc); Sumcheck count is
21a+26+3*(bs+bc). At a14/bs3/bc2 these are A3=699, A1=84, ZeroWeight=293,
Sumcheck=335. Runtime receipts must establish every total.

The producer and exact byte views are O(N). The independent revealing public
MLE consumers cost O(N*a); inherited full-opening range/hash consumers remain
charged. There is no benchmark, fitted constant or succinct verifier claim.

Tests first: 10000 NumPy int64 dot/convolution cases, endpoints and ragged rows,
all width transitions/full static shapes, both fields/repetition counts and
exact receipt totals. Fresh false S/carries, S+p, zero/terminal/padded carries,
output high bytes, pinned raw sign changes preserving S, and original-final
substitutions preserving products must reject. Compare actual old/new roots
and compose the old proof on small inputs. A complete 16384-element proof is
required before publication. Native/model/private lowering, remaining output
roles, fidelity and original task criteria remain open.

# Strict attention normalization division (Q26 / Q31)

Draft RFC-0004 A3/A6 and RFC-0009 A2 research. Before code: can complete
quotient-product, biased-numerator and doubled-denominator proofs on the same
D root bind the rounded magnitude across all 16384 channels? Costs are
c_a/c_sc/c_lu/T_misc. Kill the design if a wrong quotient, non-strict
remainder, shared-source substitution, modulus alias or missing original
consumer is accepted, or the supported domain is narrowed.

Compose the complete existing children Qp=q*D, W=2U+D and D2=2D. Expected
external roles are U,D,q,Qp,W,D2,R, all distinct. Each child consumes the same
expected D root and full normalization schema. Every inherited whole range,
lookup, source/public claim and verified transcript remains mandatory. q has
two external byte planes; all other scalar/channel roles retain sixteen.
No duplicate W, Qp or D2 range is needed after their complete children verify.

Add whole ranges for remainder R and gap g, each capped at 2Dmax-1. Use G=1
when N times the compact width fits 131072 bytes, otherwise G=2 with exactly
N/2 caps per child, explicit zero caps for unused channels and plane-major
repacking. Eight carry groups each contain four planes of N entries: four
equality groups capped at 2 and four strict groups capped at 1. Padded and
final carries are zero. Each group fits existing range capacity.

Two degree-one A3s cover all 16N byte columns:

- Equality: 2*Qp[j]+R[j]+carry_in=W[j]+256*carry_out, initial carry zero.
- Strict remainder: R[j]+g[j]+carry_in=D2[j]+256*carry_out, initial carry
  one on real channels and zero on padding. D2 is masked to real channels.

Each relation consumes five actual originals. Independent column sides are
bounded by 767 and 511 respectively, both below p/2. Whole bounds are static
and below 2^128; final carries exclude overflow. Thus R+g+1=2D implies
0<=R<2D and D>0. Together with W=2U+D and Qp=qD, equality fixes
q=floor((2U+D)/(2D)), including ties away from zero in the magnitude.
No verifier-side plaintext division or whole-field multiplication admits q.
Actual D and U provenance still requires positive-denominator and scaled-
numerator sources; signed int16 output and configured conversion remain open.

Identity<2^38 reserves base=2^63+2^24*identity. Quotient and bias child ids are
1024*identity+1/+2, occupying spans at base+2^14 and base+2^15. The doubled
child id is 64*identity+1, occupying base+2^18. New wide-range ids are
262144*identity+1..(2G+8), roots base+1..(2G+8), with inherited spans starting
at base+64 through base+64*(2G+8). Parent originals use base+32..41;
A3 ids are 1048576*identity+32768/+32769. External roles lie outside the
entire reserved span. Check nested namespaces at the maximum identity.

Let a=log2(N) and br be the remainder compact-byte exponent. New independent
lookup dimensions are 2G copies of a-log2(G)+br+1 and eight copies of a+3.
Each identity is ((2^m+255)/|K|)^r with unsquared reduction
r*(F(m)+F(8)+3m)/|K|, F(m)=3m(m-1)/2+2m. New range/A3 numerator is
94a+14br+160 for G=1, or 112a+28br+124 for G=2, including parent4(a+4).
New full nonlookup draws per ZeroWeight/Sumcheck label are 42a+6br+72 or
50a+12br+56 respectively. Parent draws 2(a+4) per label. Add all three
complete child accounts unchanged, including the doubled child's separate
K-1 polynomial-identity and 4b A1 losses. No new label or A1. Full schema,
all external/internal roots and verified child states precede parent draws.
Binding/FS/H and complete upstream source proofs remain additional.

Tests first: 10000 independent NumPy integer divisions, byte roots and carry
columns across exact/block configurations, ties, zero and maximal remainders.
Capacity cases cover G=1/2 and 8193/16384 channels. Attack every root, complete
child substitution, all ten compensated original claims, ranged R=2D,
genuine aliases, whole caps, padding and carry endpoints. A forged strict
initial zero with a compensating gap byte must fail its original consumer.
Actual scaled-numerator and positive-denominator proofs must compose in both
modes and reject valid replacements. Both fields/repetition counts must
match exact receipts. Require full G=2 at Dmax=2^64 and G=1 with large q,
plus every repository gate. Queue these behind existing quotient-product
full proofs without restarting any completed or live work.

Continue Q26/Q31. Complete source/model/key/block ownership, global
attainment, signed output, configured conversion, native/private inference,
PCS/ZK/FS, GPU parity/scale, fidelity and independent audit remain required.
No benchmark, new cut, range capacity increase or additional weight pass is
claimed. Draft amendments remain unaccepted; original task criteria remain.

Focused source-view controls passed. Equivalent arithmetic metadata replay,
changed remainder high planes and separately valid denominator substitutions
in either product or bias child rejected, including q=0. An unmasked D2
broadcast on padding rejected at StrictRemainder:RoundSumMismatch. These new
controls ran separately because the original suite was already loaded; future
boundary runs include them. Corpus, primary/boundary suites, compositions,
matrix, full proofs and repository gates remain pending.

Primary controls passed. Every external/internal root, fresh false remainder,
gap/carry value and complete child substitution retained its consumer. All
ten compensated original-final attacks rejected at Equality:ClaimMismatch
or StrictRemainder:ClaimMismatch. The initial complete receipt matched the
static account. Corpus, remaining boundaries, source compositions, matrix,
full proofs and repository gates remain pending.

Seed 2747 passed all 10000 independent cases and four capacity cases,
covering 378879 channels, 7844 zero remainders and 92247 maximal remainders.
The observed counts and SHA-256 are frozen in the checker:
`390669772c84ae3667822f7417690d395e2b76389df305bbe9b654a37bb196b7`.
The original boundary suite passed, including genuine ranged R+p, R=2D,
zero D, strict initial one and carry/padding endpoints. Complete scaled-
numerator and positive-denominator proofs composed in both modes; valid
source replacements rejected. Matrix, full proofs and gates remain pending.

CI preserves all 158 inherited commands and adds the five normal division
modes as command 159. Both full-width modes are mandatory matrix jobs with
fail-fast disabled. All 11 inventory/CLI/aggregate tests passed, covering
every supported mode and rejecting unsuccessful required results. The
original proof matrix, full-size runners and gate queue are preserved.

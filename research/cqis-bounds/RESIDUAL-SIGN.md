# Canonical residual numerator sign (Q26 / Q31)

Question: can the same aligned offset O determine the exact magnitude M and
canonical sign s before residual rounding? This is revealing Draft RFC-0004
A3/A8 research following [aligned sources](RESIDUAL-ALIGNED.md). Costs are
c_a/c_sc/c_lu/T_misc. Kill the design if an in-range whole-field alias, negative
zero, forged carry, or valid substituted aligned source can pass a consumer.

Expected fractions define A,B, H=32768*(A+B), U=65535*(A+B). Consume complete
ranges O<=U, M<=H and Boolean s; require O+2*s*M=H+M exactly. Thus the signed
numerator O-H is (1-2*s)*M. All O/M external roots have eight canonical-u32
byte planes; s has one canonical-u32 flag per row. Reuse the actual O root
from aligned addition; these research roots do not authenticate packed models.

For each of eight columns, encode the natural signed carry c in[-2,2] as
c'=c+2 in[0,4]. Initial and terminal c' are2 on real rows and0 on padding.
Enforce O_k+2*s*M_k+c'_in+510=H_k+M_k+256*c'_out on real rows. Both constants
are masked by expected row count. Each side is at most1534<p/2; two complete
four-column carry ranges retain every padded position. A separate terminal
A3 enforces the endpoint. This representation is derived from the static
byte bounds, never from an observed carry or whole field residue.

Canonical zero uses B_M=sum of the eight actual M bytes, so0<=B_M<=2040<p/2
and B_M=0 iff M=0. A complete range0<=g<=2040 and the small integer equality
B_M=g+s exclude s=1 at M=0. This g is a digit predecessor, not the earlier
static schema's whole-magnitude sign_gap. It proves the same canonical-zero
condition without claiming a native record change. No inverse or runtime bound
is required. Rounding can still produce zero from a negative nonzero numerator.

Six complete ranges remain in order O,M,s,g,carry_0,carry_1. Parent A3s are
TerminalCarry (degree1,m=a,two originals), SignColumns (degree2,m=a+3,seven
originals), CanonicalZero (degree1,m=a,three originals), N=2^a. Every original
has its actual point consumer, including zero-hidden signs and public views.
Expected schema/role bytes, external and auxiliary roots and all six verified
states precede weights, instances, rounds and finals. No supplied receipt
or plaintext absolute-value result authorizes verification.

Namespace before implementation: identity<2^48, base=2^63+2^14*identity.
Wide children256*identity+1..6 reserve64 slots each at base+64..384. Their
sources use base+1..6; parent view ids use base+16..26. Parent A3 identities
1024*identity+128..130 follow every child A3 id. Three distinct external ids
stay outside the whole parent span. Supported research rows1..16384 preserve
the original2^20 static-domain obligation.

Let b_o,b_m be log2 of the actual O/M range byte widths. Lookup dimensions
are a+b_o+1,a+b_m+1,a+1,a+2,a+3,a+3. Preserve each identity
((2^m+255)/|K|)^r and unsquared reduction r*(f(m)+f(8)+3m)/|K|,
f(m)=3m(m-1)/2+2m. Total range/A3 numerator is61a+7(b_o+b_m)+52;
parent contribution is7a+9. Full nonlookup draw counts for each ZeroWeight/
Sumcheck label are27a+22+3(b_o+b_m). Binding, FS/H and private losses remain
additional. These static formulas are not measured performance results.

Tests first:10000 NumPy signed numerator/magnitude/sign cases and independent
byte-carry checks; all shifts, mixed O/M widths, endpoint signs and zero.
Forge negative zero while all wide equations hold, range-valid M+p, original
finals preserving arithmetic, terminal and padded carries, and whole bounds.
Compose an actual aligned proof and reject its valid replacement. Require both
fields/repetitions, ragged rows and a complete16384-row proof before publication.

Continue Q26/Q31. This proves numerator sign and magnitude only; exact one-round
quotient/remainder and signed residual output remain required. Native lowering,
physical/model/private inference, fidelity, independent review and all original
task criteria remain open. No new Accepted cut, benchmark or weight pass.

Tests-first rejected the missing module. Seed2726 passed10000 independent
signed-value and byte-carry cases covering3383720 column cells, all31 shifts,
O/M widths(4,4)/(8,4)/(8,8) and maximum namespace bounds. Frozen digest:
`d88ee6a794487bbbc38d742252bd016d82c7ca29b4cfff8916dcca7ef4ca5c19`.
The primary controls rejected all external roots and range words, range-valid
M+p, coherent negative zero, actual carries and every parent original claim.
Whole-bound, nonboolean-sign, predecessor, padded-carry and high-plane controls
also passed. A complete aligned proof composed on the same O root; its valid
replacement rejected. All16 complete matrix cases passed across both fields
and repetition counts, including exact account and draw totals. Matrix SHA-256:
`e0460faaa4f89e6f928734c52105e63e1f18de8f9c318154dbbe5d15bddc08d0`.
The complete16384-row proof is running; required local gates remain queued
once. No completed review or CI claim.

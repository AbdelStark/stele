# Consumed residual magnitude rounding (Q26 / Q31)

Question: can the same proved numerator magnitude M feed the exact one-round
quotient and strict remainder under the configured residual units? This is
revealing Draft RFC-0004 A3/A8 research after [canonical sign](RESIDUAL-SIGN.md).
Costs are c_a/c_sc/c_lu/T_misc. Kill the design if a field alias, coherent
remainder r=B, omitted bias, source substitution or forged carry is accepted.
No source may be rounded before alignment.

Let f=max(Fl,Fr,Fo), t=f-Fo in0..30, B=2^t, h=floor(B/2). Expected fractions
fix B and h, with h=0 for B=1. Consume complete whole ranges M<=H=32768*(A+B0),
q<=32768 and r<=B-1, where A,B0 are the source alignment factors. Enforce
M+h=q*B+r exactly. This proves q=floor((M+h)/B), signed ties-away magnitude
rounding. A quotient above32768 rejects. Positive32768 still requires rejection
by the complete signed-output consumer; this unsigned role alone permits it.

External roots retain M's eight byte planes, q's two and r's four, each with
canonical-u32 leaves. Complete actual q bytes supply q*B as a byte shift plus
a residual bit factor at most128. No whole wide integer enters M31. Natural
column carry c stays in[-129,2]: the coarse minimum is
-255*128-255-129=-33024=-129*256 and maximum255+255+2=512. Represent c as
c'=c+129 in[0,131]. Initial/final c' are129 on real rows and0 on padding.

Eight columns enforce M_k+(h_k+32895)+c'_in=Q_k+r_k+256*c'_out, with public
h_k+32895 masked by expected row count. Q_k is the actual shifted quotient
byte contribution, not a supplied product. Both sides are at most66431<p/2.
Two complete four-column carry ranges retain all positions, and a separate
terminal A3 enforces the endpoint before the column relation. Strict r<B is
an actual whole-value range, including B=1; no inactive range is omitted.

Five complete ranges remain in order M,q,r,carry_0,carry_1. Parent A3s are
TerminalCarry (degree1,m=a,two originals), then RoundColumns (degree1,m=a+3,
six originals), N=2^a. Every original, including public bias/carry views and
zero quotient, keeps its actual-point consumer. Expected schema/role bytes,
three external roots, five auxiliary roots and all five verified states
precede the parent challenge schedule. No plaintext division authorizes verify.

Namespace before implementation: identity<2^48, base=2^63+2^14*identity.
Wide children256*identity+1..5 reserve64 slots each at base+64..320; sources
use base+1..5. Parent views use base+16..23, and A3 identities
1024*identity+128/+129 follow all child A3 ids. Three distinct external ids
stay outside the parent span. This research supports16384 rows while preserving
the original2^20 static-domain obligation.

For range widths2^bm and2^br of M/r, lookup dimensions are
a+bm+1,a+2,a+br+1,a+3,a+3. Retain each identity ((2^m+255)/|K|)^rpt and
unsquared reduction rpt*(F(m)+F(8)+3m)/|K|, F(m)=3m(m-1)/2+2m. Here rpt
is the lookup repetition count, distinct from the remainder r. Full range/A3
numerator is49a+7(bm+br)+49; parent contribution4a+6. Each nonlookup label
has22a+22+3(bm+br) draws. Binding, FS/H and private losses remain additional.
These are static formulas, not measured performance claims.

Tests first:10000 independent Fraction/NumPy rounding and byte-carry cases,
all31 shifts, exact/tie boundaries, q32768 and overflow, both carry signs,
all actual widths and maximum namespace. Forge r=B with coherent division,
range-valid M+p, quotient/source changes, terminal/padded carries and original
finals preserving the equality. Compose the actual canonical-sign M root and
reject a valid replacement. Require both fields/repetitions and a complete
16384-row proof with all five ranges before publication.

Continue Q26/Q31. Full residual composition and signed output, native lowering,
physical/model/private inference, fidelity and original task criteria remain
open. No new Accepted cut, benchmark or additional weight pass is claimed.

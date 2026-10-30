# Consumed canonical rotary rows (Q26 / Q31)

Can actual signed16 rows pass through the configured A7 rotary function,
position, pairing and one-round signed output with every range/source consumed?
This is revealing Draft RFC-0004 A3/A6/A7 research after the
[static envelope](ROTARY.md). Costs are c_a/c_sc/c_lu/T_misc. Kill the design
if a supplied coefficient, wrong position/pairing, field alias, negative zero,
non-strict remainder or passthrough substitution is accepted.

Expected rotary Spec fixes heads, width, rotary width, adjacent/split layout,
fraction and position length. A separately expected absolute position stays
in that length. For nonzero rotary width, an exact rope.Parameters descriptor
must match width/layout/length. The verifier regenerates the selected coefficient
row with the existing integer-certified A7 generator. Base, linear and llama3
retain their exact definitions; arbitrary supplied coefficient rows confer no
authority. Zero rotary width requires no descriptor and means full passthrough.
The static domain L*max(1,r/2)<=2^20 and full16384-element row remain unchanged.

Public paired views give N=x0*C0+x1*C1. Left outputs use(C,-S), right outputs
(S,C), and unchanged channels use(16384,0) with their original input. Every
view is masked on padding. The fixed envelope |C0|+|C1|<=23171 gives
|N|<=B=759267328<p/2; no observed extremum selects the bound. There is no
committed numerator. Complete signed-source consumers enforce actual X/Z raw
bytes, magnitudes and canonical signs. Four whole ranges consume M<=B,
Boolean s, predecessor g<=B and remainder r<=16383. Actual output magnitude
supplies q<=32768. Six external roots X,Z,M,s,q,r retain2/2/4/1/2/2 byte planes;
two auxiliary roots bind input magnitude and g, all with canonical-u32 leaves.

Four A3s run in fixed order: N=M-2sM (degree2,six originals), M=s+g
(degree1,three originals), M+8192=q*16384+r (degree1,four originals), then
q*(s-sZ)=0 (degree2,three originals). Every original retains its actual-point
consumer, including public coefficients and values hidden by zero. Negative
numerators may round to canonical Z=0; negative zero numerator is forbidden.
Both signed sources and all four ranges remain mandatory for full passthrough.
Integer faithfulness follows from the static envelope and whole-value ranges:
biased magnitude<=759275520, g+s<=759267329 and division side<=536887295,
each below p/2. Positive32768 rejects through the actual signed output relation.

Namespace before code: identity<2^48, base=2^63+2^14*identity. Signed-source
children32*identity+1/+2 occupy512..1024 and1024..1536. Wide children
256*identity+1..4 occupy64..320; auxiliary source ids use base+1/+2.
Parent views occupy base+16..31, and A3 ids1024*identity+128..131 follow all
child ids. Six distinct external ids stay outside the span. Expected metadata,
canonical descriptor, absolute position, eight roots and six verified child
states precede the parent challenge schedule. A bounded immutable coefficient
cache is keyed by exact descriptor bytes and validated integer position.

For N=2^a, preserve ten separate lookup identities: six at a+2, then a+3,
a+1,a+3,a+2. Each is ((2^m+255)/|K|)^rpt, with its unsquared reduction
rpt*(F(m)+F(8)+3m)/|K|, F(m)=3m(m-1)/2+2m. Total range/A3 numerator is
132a+105, including parent10a. Parent draws are4a per ZeroWeight/Sumcheck
label; complete nonlookup totals are56a+43 each. Binding, FS/H, physical/model
ownership and private losses remain additional. These are static formulas.

Tests first:10000 independent NumPy/Fraction row rotations with independently
checked canonical coefficients, all three families, both layouts, partial/full/
zero rotation, padding, positions, exact endpoints and overflow. Check full
namespace/capacity. Attack every root, canonical zero, whole bounds, coherent
r=16384, supplied receipts/coefficients, valid source/output substitutes and
every original final, including public coefficients at zero input. Require
both fields/repetition counts and one complete16384-row proof before publication.

Continue Q26/Q31. This is an O(heads*width) revealing reference with public
coefficient generation and MLE evaluation charged to T_misc, not a native fast
verifier. No new cut, benchmark, weight pass or NC-0106/0109 credit is admitted.
Native generation/lowering, function/passport registration, model/private
inference, other required variants and fidelity remain open. Original task
criteria and A3/A6/A7 Draft statuses are preserved.

Tests-first rejected the missing module. Primary controls then rejected all
six external and two auxiliary root mutations, independently valid source and
opposite-sign output substitutions, and changed magnitude/predecessor/remainder
values. A forged r=16384 with a reduced q retained the exact whole division;
the actual remainder cap consumer rejected it. Initial receipt/account checks
passed. All public/original/boundary controls also passed: whole-value bounds,
M31 aliases, positive32768, output padding and full-passthrough substitutions
rejected at their named consumers. The corrected corpus, matrices, maximum
and gates remain under validation.

The first corpus run reached its coverage assertion with overflow cases
unexercised: the unscaled sampling quarter coincided with position zero,
whose rotation is the identity. The position schedule now varies independently
of that quarter. Keep overflow coverage mandatory and rerun only the affected
corpus; no verifier or rejection reason changed. All sixteen original-final
controls, public padded coefficients, negative zero and expected position/
layout/unit replay controls passed in the independent proof run.

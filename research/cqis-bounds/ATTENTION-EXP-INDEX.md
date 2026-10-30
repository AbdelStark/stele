# Consumed exponential index decomposition (Q26 / Q31)

Can the actual bounded attention difference prove u=2^k*h+l without a field
alias, including u=2^31 and the inclusive endpoint? This is Draft RFC-0004
A3/A6 research for RFC-0021 §2.1 and RFC-0009 A1. Cost terms are c_x/c_sc/
c_lu/T_misc. Kill the design if a modular alias, endpoint with nonzero low
index, wrong mask/split, truncated high byte or source substitution accepts.

Expected metadata includes an attention-maximum Spec and an exact exponential
Representation. Product mode1 and nearest/corrected mode2 have the full
supported B/F/E/k domain; B and F must match the maximum schema. Direct mode0
has no split and does not use this consumer. The maximum Spec supplies exact
query/key positions, block/window mask, source identity and delta cap. It does
not itself confer an attained-maximum proof; actual composition must verify
that complete child against its own expected roots and join the same delta.
At most16384 actual keys and the original absolute span2^20 are supported.

Four complete ranges consume u<=min(2S,2^B), h<=2^(B-k), l<=2^k-1 and one
four-plane carry array. Masked and padded entries have zero caps. Three
external roots bind u,h,l in their static byte widths; the carry root is
auxiliary. These canonical-u32 research leaves are not physical model roots.
All range widths come from expected caps: u uses1,2,4 bytes, h/l use1,2.
All four byte columns remain present, with high zero extension where required.

Write q=floor(k/8), c=2^(k mod8). At byte position j, the shifted h view
selects its actual byte j-q or public zero outside its stored width. Enforce
c*h_byte + l_byte + carry_in = u_byte +256*carry_out. Initial carries are
public zero; last-column carry caps are zero. Other carry caps are c<=128.
Each column side is at most c*255+255+c<=33023<p/2. Thus the four columns
establish exact integer reconstruction, not congruence modulo M31. Combined
with u<=2^B and l>=0, h=2^(B-k) forces l=0. No endpoint flag is supplied.

One degree-one A3 over4N consumes all five original views, including values
hidden by zero and shifted high zeros. Full expected metadata, representation,
four roots and four verified range states precede the parent challenge
schedule. Full source openings and their derived byte views are reference
costs; private source lowering remains a separate obligation.

Namespace before code: identity<2^50 with base=2^63+4096*identity, disjoint
from the maximum consumer's reserved span. Range children64*identity+1..4
occupy64..320, the carry source uses base+1, views use base+16..20, and parent
A3 id256*identity+64 follows every child id. New h/l ids are distinct from all
maximum source roles and outside both spans. All u/h/l ids stay outside the
index span. Composition introduces no extra random challenge.

For N=2^a and byte widths2^bu,2^bh,2^bl, four lookup dimensions are
a+bu+1,a+bh+1,a+bl+1,a+3. Retain each identity ((2^m+255)/|K|)^rpt and each
unsquared reduction rpt*(F(m)+F(8)+3m)/|K|, F(m)=3m(m-1)/2+2m. Total range/A3
numerator is38a+22+7*(bu+bh+bl), including parent2a+4. Parent draws are a+2
of each ZeroWeight/Sumcheck label; all nonlookup draws are
17a+10+3*(bu+bh+bl) each. Binding, FS/H and model/private losses are additional.

Tests first:10000 independent NumPy divmod and prefix-sum column checks,
all B/k pairs, both represented function families, all byte widths, masks,
zero and inclusive endpoints, namespace limits and malformed metadata.
Attack every root, five original finals, real source substitutions, u=M31+1
versus u=1, masked/padded values, whole caps, last carry and shifted high
bytes. Compose with the actual maximum proof and reject a valid different
maximum's delta. Require both fields/repetition counts and a complete16384-key
proof before publication, followed by all required local gates.

Continue Q26/Q31 with canonical high/low/correction membership, exact output
product/remainder, direct nearest lookup and masked probability outputs.
This arithmetic split does not establish exponential values or full attention.
Native/private inference, physical/model ownership, fidelity and original
task/control requirements remain open. No benchmark, weight pass, new cut,
production control or profile credit is claimed.

Tests-first rejected the missing module. Primary root/arithmetic/field-alias
controls passed. The first original-view suite stopped because the split replay
expected a round-sum error, but the verifier rejected the changed public cap
at its original claim. A linear relation that vanishes on the original rows
has zero round messages; the changed cap is rejected when its claimed value
is consumed. The test now requires that exact ClaimMismatch diagnostic. No
verifier code, accepted relation or rejection condition changed. The affected
suite is rerun separately; successful primary controls are retained.

The seed2731 corpus passed all10000 cases, covering all235 supported B/k pairs,
both represented function families, all source byte widths and maximum namespace
geometry. Independent NumPy divmod and prefix-sum byte equations matched every
row, with maximum observed carry127. Frozen correctness SHA-256:
`7c266b61aa41fc8bec8bc14e99b6653b506426a217e6c936703e5979da3b68ca`.
This is correctness evidence, not a performance measurement. The remaining
control suites, proof matrices, full-row proof and required gates are pending.

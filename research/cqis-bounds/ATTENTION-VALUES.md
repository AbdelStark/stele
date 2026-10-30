# Restored attention value sources (Q26 / Q31)

Draft RFC-0004 A3/A6 research for RFC-0009 A2. Before implementation: can
actual signed8 codes and per-position scales prove D=s*V across a complete
value view, with the same roots used by prepared rows and weighted sums?
Costs are c_a/c_x/c_sc/c_lu/T_misc. Kill the design if a scale can move to a
different position, raw two's-complement bytes are treated as signed field
values, zero scale permits nonzero codes, or an original operand disappears
because its product is zero. No Accepted semantics or production cut changes.

Expected metadata fixes the attention sum schema, increasing absolute key
positions and channel width. The schema retains length, fraction, exponent,
value policy and accumulation mode. Flatten real entries in row-major order;
cap their total at 16384 and pad the flattened vector to N=2^a. Independently
pad the position vector to R=2^ar. Keep masked real value sources: probability
masking belongs to the probability consumer. This resource cap does not admit
a complete sequence, physical source view or native inference plan.

Reuse the existing complete signed8 source consumer. Its external raw bytes
are V modulo 256, with zero padding, exactly as prepared row-code outputs.
Its verified magnitude root also feeds a complete tighter magnitude range:
Cmax=127 for dynamic policy, or min(127,floor((65536+s)/(2*s))) for static
scale s. In particular -128 cannot enter a symmetric value source. Every
signed-source range, sign equation and original consumer remains mandatory.

Dynamic scales have their own complete whole range 0<=s<=259 on R positions.
Their external root has two byte planes. Static policy fixes s in 1..65535;
its expected scale root is the exact public two-plane vector with padded zeros.
The single-position encoding agrees with both existing wide-row converters.
Source/scale association with complete prepared projection rows, GQA/head views
and cached prefixes still requires actual source composition. Bounds alone
confer no such ownership.

Set S=Cmax*smax using the closed attention-sum schema. Prove offsets U=S+s*V
in [0,2*S], with zero on padded entries. Range U completely, then zero-extend
its actual byte planes to four planes for the external output root. For each
real entry broadcast only its position's actual scale. One degree-two A3 is

    U + 256*s*sign = S*real + s*raw.

The signed child establishes V=raw-256*sign. Both nonnegative sides are
statically bounded by max(2*S+256*smax,S+255*smax)<=16908030<p/2.
All five actual views retain independent original-point consumers. The offset
representation supports a later weighted sum by subtracting S*Z; that later
sum, its carries and canonical sign are separate obligations.

For dynamic policy, completely range Boolean n and predecessor k<=258 on
positions. One degree-two A3 over 2R entries enforces s=k+n and s*(1-n)=0.
Use four actual views: s in both halves, k only in the first, n only in the
first, and n only in the second. Another degree-two A3 enforces
magnitude*(1-broadcast(n))=0 on all N entries. Thus s=0 forces every code
in that position to zero. Do not infer the scale from observed codes or use
zero outputs to omit either predicate or source verification.

Before code, reserve identity<2^44 and base=2^63+2^18*identity. The signed
child uses identity 512*identity+1 at offsets 512..1024. Wide ranges use
4096*identity+65..69 for magnitude, output, scale, n and k. The magnitude
source is base+1, compact output base+2, flags base+3 and predecessor base+4;
scale is external. Static mode retains reserved inactive ids. Parent A3 ids
are 16384*identity+512..514 and view ids base+16..26. Three distinct external
ids stay outside this span. All expected metadata, external/auxiliary roots
and verified child states precede parent weights, rounds and finals.

Let bo be the compact output byte-width exponent. The signed8 child has
A3 numerator 43a+9 and 18a+4 draws per nonlookup label. Static mode totals
64a+9+7bo and 27a+4+3bo draws per label. Its five lookup dimensions, in order,
are a+1,a+1,a+2,a+1,a+bo+1. Dynamic mode adds scale/n/k dimensions ar+2,ar+1,
ar+2. Its total A3 numerator is 67a+30ar+26+7bo and each nonlookup count is
28a+13ar+11+3bo. Each lookup keeps its identity ((2^m+255)/|K|)^r and
unsquared reduction r*(F(m)+F(8)+3m)/|K|, F(m)=3m(m-1)/2+2m. These are
planned formulas; runtime receipts must verify every total before acceptance.

Tests must precede implementation: 10000 independent NumPy int64 restored
values, explicit two's-complement/plane encodings and all static width limits.
Cover both fields/repetitions, ragged positions/channels, dynamic zero scale,
signed endpoints and static scale 65535. Forge valid false offsets, -128 codes,
changed scales, source permutations, predicate/predecessor values and finals
hidden by zeros. Retain masked real sources and all padding. Compose actual
dynamic and static row-code proofs, including a valid different row source.
Require complete 16384-entry dynamic and static proofs and repository gates.

The consumer is implemented; complete proof evidence remains pending.
Continue Q26/Q31 with weighted
restored sums and normalization. Complete projection-row preparation, sequence
assembly, physical/model ownership, native/private PCS/ZK/FS, fidelity and
original task/control criteria remain open. No benchmark or profile is claimed.

The tests-first run rejected the missing module. Seed2734 passed10000
independent NumPy cases over226948 value cells, including2153 zero scales
and all compact output widths. Frozen corpus hash:
`e9b2d757efa88648081269849d7886ddc78ed44119c2930b1c5fc932a85a53fb`.
Primary source/root/offset/predicate controls passed, including valid source
children carrying nonzero codes at zero scale. Zero-hidden scale/raw/sign
finals and a false real-row mask rejected their actual original consumers.
Symmetric code caps, padding, static scale and full output extension controls
also passed. The M31 offset-alias, tighter static cap and remaining parent
original controls passed. Complete dynamic and static prepared-row proofs
composed on the same code/scale roots; valid alternate prepared sources
rejected. The field/shape proof matrix is running with initial dynamic and
static receipts checked. Two full 16384-entry proofs and all required local
gates remain required.

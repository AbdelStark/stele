# Consumed residual alignment (Q26 / Q31)

Question: can two actual signed16 sources in different configured units feed
one exact aligned offset before any residual rounding? This is revealing
research under Draft RFC-0004 A3/A8, following the [static residual schema](RESIDUAL.md).
Costs are c_a/c_sc/c_lu/T_misc. Kill the design if a same-magnitude source
substitution, whole M31 alias, nonzero padding or incorrect carry is accepted,
or if any source is rounded before addition. No Accepted behavior changes.

For expected fractions Fl,Fr,Fo in0..30, set f=max(Fl,Fr,Fo), A=2^(f-Fl)
and B=2^(f-Fr). Consume two complete signed-source proofs, then enforce
O=(X+32768)*A+(Y+32768)*B as an exact nonnegative integer in each real row.
Signed source roots retain the existing two-byte plane representation.
Leaves are canonical-u32 research values; packed model-source authentication
remains separate.
Flip the verified high byte's sign bit to obtain X+32768 and Y+32768;
apply that map only to real rows. Padding remains zero, not the offset32768.
The O root has eight byte planes, including required high zero planes.
A complete whole-value range binds O<=65535*(A+B)<2^47.

Use the expected power-of-two factors as byte shifts and residual bit factors
at most128. Eight byte columns satisfy left+right+carry_in=O_byte+256*carry_out.
The initial carry is zero. Derive each outgoing cap from static source byte
caps and the prior carry cap; each is at most255, and the terminal cap is zero.
Both sides are at most65535, below p/2. Carry families contain four columns
per row; statically zero families are public zeros. All nonzero families retain
complete ranges, including zero terminal and padded positions. One degree-one
A3 over8N consumes all five original views at their actual emitted points.

Namespace before implementation: identity<2^44, base=2^63+2^18*identity.
Signed children512*identity+1/+2 reserve512 slots each at base+512/+1024.
Wide children4096*identity+65..67 reserve64 slots each at base+4160..4288.
Auxiliary source ids base+1..5 name both magnitudes, output and two carry groups;
parent views use base+16..20, parent A3 identity16384*identity+512.
Three distinct external ids stay outside the whole parent span. Fixed schema,
roles, roots and verified child states precede the parent challenge schedule.

Let a=log2(N), b=log2(output range byte width), and g be the number of nonzero
four-column carry families. Two complete signed16 children contribute six
lookup units at dimension a+2. Output contributes a+b+1; each carry family
a+3. Preserve every identity ((2^m+255)/|K|)^r separately and add its unsquared
lookup reduction r*(f(m)+f(8)+3m)/|K|, f(m)=3m(m-1)/2+2m.
Total range/A3 numerator is (97+9g)*a+76+7b+18g. The parent adds2(a+3),
already included, and a+3 draws for each ZeroWeight/Sumcheck label. Binding,
FS/H, private composition and model ownership remain additional losses.

Tests first:10000 independent NumPy int64 aligned sums and byte/carry grids;
all31 shifts on either source; signed endpoints; every root and carry family;
valid alternate sources, an in-range O+p, compensated original finals,
padded offsets and terminal carries. Require both fields/repetitions and a
full16384-row proof with both carry families. A separate four-proof matrix
uses disjoint byte shifts, where every carry family is statically zero. Exact
outputs and source roots
must compose with the existing signed consumer. No per-row proof loop.

This adapter supports16384 rows, preserving the static schema's original
2^20 dimension obligation. It proves only aligned O. Canonical numerator sign,
one-round quotient/remainder and signed residual output remain required.
Native/physical/model/private inference, fidelity and original tasks stay open.
Continue Q26/Q31; no benchmark, additional weight pass or production NC credit.

The tests-first run rejected the missing module. Seed2725 passed10000 NumPy
aligned-sum and carry-grid cases covering3383720 column cells, all31 source
shifts, whole output widths4/8 and maximum namespace bounds. Frozen corpus:
`aa7a6fa5bcb9a5011b9efeb4c3ad021f3d1dd6f39f9daf24b23b0ecb584edbb9`.
All three-root controls, valid same-magnitude source substitutions, in-range
O+p, both carry families and compensated original finals rejected at the
specified consumers. Terminal/padded carries, offset padding and high output
planes also rejected at their required consumers. Complete proof matrices
remain running. The separate no-carry matrix and full-row proof are queued
after success; required repository gates are queued once.

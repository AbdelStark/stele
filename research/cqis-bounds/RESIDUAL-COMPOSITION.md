# Complete residual arithmetic composition (Q26 / Q31)

Can actual signed16 inputs reach the exact single-rounded signed16 residual
output through complete consumers? This is revealing Draft RFC-0004 A3/A8
research after [magnitude rounding](RESIDUAL-ROUNDING.md). Costs are
c_a/c_sc/c_lu/T_misc. Kill the design if a source substitution, pre-rounded
sum, wrong signed output or zero-hidden original can pass.

Retain four complete children in order: aligned inputs, canonical numerator
sign, magnitude rounding and signed output source. Eight external roles are
X,Y,O,M,s,q,r,Z, with2/2/8/8/1/2/4/2 canonical-u32 byte planes per padded row.
Every shared role uses exactly the same root. The routes are (X,Y,O), (O,M,s),
(M,q,r) and (Z,q). No supplied child receipt or plaintext forward evaluation
authorizes verification.

One degree-two A3 enforces q*(s-sZ)=0 on actual verified values. A nonzero
rounded magnitude inherits the canonical numerator sign; a negative nonzero
numerator may round to canonical Z=0. Both sign consumers remain mandatory
at q=0. The signed source enforces its actual raw-byte range, so negative32768
is representable while positive32768 must reject at the parent relation.
All three original views retain consumers, including those multiplied by zero.
The static product bound32768<p/2 establishes integer faithfulness.

Expected schema/role bytes, eight external roots and four verified states
precede the parent ZeroWeight and Instance/Round/Final schedule. No new table,
product identity, selector or alternate rounding branch is introduced.

Namespace before code: identity<2^42 and span2^20, base=2^63+2^20*identity.
Aligned child4*identity+1 occupies offsets2^18..2^19; sign64*identity+1 uses
2^14..2^15; rounding64*identity+2 uses2^15..3*2^14; signed output2048*identity+1
uses512..1024. Parent views use base+16..18 and A3 identity65536*identity+32768,
after every child A3 identity. External ids are distinct and outside the span.
The16384-row research limit preserves the original2^20 domain obligation.

Let N=2^a, bo/bm/br be log2 of the actual O/M/r range byte widths, and g the
number of static nonzero alignment carry families. Preserve all21+g separate
lookup identities and their unsquared reductions. Full range/A3 numerator is
(253+9g)*a+212+14*(bo+bm)+7*br+18g. The parent contributes3a; its draws are a
per ZeroWeight/Sumcheck label. Full nonlookup draws per label are
(109+4g)*a+89+6*(bo+bm)+3*br+8g. Binding, FS/H, physical/model and private
composition losses remain additional. Static geometry is not a benchmark.

Tests first:10000 independent Fraction/NumPy cases, all31 rounding shifts,
source extrema, cancellation, signed ties, both overflow directions and zero.
Verify exact root joins and namespace intervals. Consume both fields and
repetition counts, including negative numerator rounding to zero. Attack all
eight roots and substitute independently valid aligned/sign/rounding/output
children. Forge positive32768 using genuine negative32768 signed bytes;
forge the sum of separately rounded inputs; compensate final originals even
at q=0. Require one complete16384-row proof with every child retained.

Continue Q26/Q31. This composes revealing residual arithmetic only. Native
lowering, physical source/model ownership, PCS/ZK/FS, full inference, fidelity,
original task criteria and independent audit remain open. No Accepted cut,
production control credit or measured performance claim is added.

Observed corpus evidence: seed2728 passed all10000 cases, with8552 representable
outputs and1448 expected signed-output overflows. Independent Fraction and
NumPy calculations covered all31 shifts, all three carry-family counts, seven
actual O/M/r width combinations and negative numerators rounding to zero.
Corpus SHA-256 is
`867f8ea8bdf678c51b9c8ef984f6d5eaffecaa3077c75b5d4d9f3b2fb8e2295a`.
All eight root mutations and four independently valid replacement children
rejected at their intended consumers. Wrong signed output and compensated
original finals rejected; at q=0 all three original views remained consumed.
Boundary controls, matrix, maximum and repository gates remain under validation.

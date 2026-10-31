# Scaled attention normalization numerators (Q26 / Q31)

Draft RFC-0004 A3/A6 and RFC-0009 A2 research. Before code: can the actual
canonical magnitude M produce U=M*2^max(fo-fv+drop,0), across exact/block
modes and all 16384 channels, without a whole-field equality or wider range
capacity? Costs are c_a/c_sc/c_lu/T_misc. Kill the design if a wrong shift,
carry, channel group, source substitute, modulus alias or truncated high byte
is accepted, or any original claim is left unconsumed.

Use the full attention_normalization_bounds.Spec. Its static Tmax and Umax
must satisfy Tmax<2^64 and Umax=Tmax<<shift<2^128 before constructing views.
The external source retains eight byte planes and output sixteen. Write
shift=8q+r, c=2^r. Across all sixteen columns require
c*M[j-q]+carry_in=U[j]+256*carry_out, with source byte zero outside 0..7.
Initial carry is zero. Complete carry ranges cap every real entry by c-1,
with the final carry capped at zero; padded channel entries are zero.
Each side is at most 256c-1<=32767<p/2. The whole source bound ensures that
source bits shifted above the sixteen output planes are zero, including
Tmax=0 at shifts up to 92. No observed value sets a certificate or a bound.

A complete wide range consumes the source M<=Tmax. Output ranges prove
U<=Umax. Let N=2^a be padded channels and 2^bu the compact output width.
Use G=1 if N*2^bu<=131072, otherwise G=2 and split channels at N/2. Each
output group uses the same cap and its actual channel count; complete range
padding remains zero. Repack the verified groups in plane-major order into
all sixteen external output planes. This preserves width 16384 at sixteen
compact bytes without changing wide_range capacity. Four complete carry
ranges each contain four planes of N entries, at most 65536 one-byte words.
Even shift zero and zero bounds retain all range and arithmetic consumers.

One degree-one A3 over 16N entries consumes four actual originals: shifted
source, carry-in, output and carry-out. Every table is derived from complete
verified byte arrays. Expected schema, source/output roles, field/repetition
bytes, all external/internal roots and verified child states precede this
parent transcript. Identity<2^48 reserves base=2^63+2^14*identity. Child
wide-range ids are 256*identity+1..(5+G), source roots base+1..(5+G).
Their internal spans start at base+64..base+64*(5+G). Parent A3 id is
1024*identity+128, with original ids base+16..19. External ids are distinct
and outside the reserved span. Verify all namespace boundaries in tests.

For source compact exponent bm, output exponent bu and G in {1,2}, retain
independent lookup dimensions a+bm+1, G copies of a-log2(G)+bu+1, and four
copies of a+3. Each identity is ((2^m+255)/|K|)^repetitions and each unsquared
reduction is repetitions*(F(m)+F(8)+3m)/|K|, F(m)=3m(m-1)/2+2m.
Range/A3 numerator is 56a+7(bm+bu)+80 for G=1, or
65a+7bm+14bu+62 for G=2. This includes parent loss 2(a+4).
Parent draws a+4 per ZeroWeight/Sumcheck label; full nonlookup totals per
label are 25a+36+3(bm+bu) for G=1, or 29a+28+3bm+6bu for G=2.
No A1 or new challenge label. Confirm exact runtime receipts and all four
original points. Binding/FS/H and upstream source proofs remain additional.

Tests first: 10000 independent NumPy integer shifts and byte roots, plus
column carries, all legal shifts/modes, compact widths and both group layouts.
Both fields/repetitions cover positive/zero bounds and ragged channel padding.
Attack every external/internal root, all originals, source/output caps,
carry endpoints, zero-hidden source bytes and channel-group ownership.
Include genuine ranged false U and U-p aliases when the static bound permits.
Compose actual raw and accumulated-block canonical magnitude sources and
reject separately valid replacements. Require two complete 16384-channel
proofs, one positive G=2 case and one G=1 identity-shift case. Every required
repository gate remains mandatory; full-size proofs may queue behind the
existing parent runs without restarting them.

This supplies scaled magnitudes for signed normalization. Positive divisor,
biased numerator, quotient product, strict remainder and signed output must
compose on their actual roots. Global attainment, full key/block/model
ownership, native/private inference, fidelity and independent audit remain
required. No benchmark, new cut, weight-pass change or production admission
is claimed. Continue Q26/Q31; Draft amendments remain unaccepted.

Primary controls passed. Both external roots, every internal root and complete
child retained their checks. Genuinely ranged changed source/output/carry
values rejected at Shift:RoundSumMismatch. All four compensated original
claims rejected at Shift:ClaimMismatch. Metadata with unchanged arithmetic
also rejected at that original consumer; the first test expected a round
failure and was corrected without changing the verifier. The failed log is
retained. Corpus, boundaries, source compositions, matrix and full-size proofs
remain under validation, with repository gates queued once.

Ragged-group refinement: for G=2, each output range must contain exactly N/2
caps, with Umax on real channels and zero on unused channels. Giving the
second child only its actual count lets wide_range pad an 8193-channel row's
second group to one entry; the fixed half-domain check correctly rejected
that configuration. A focused regression reproduced Capacity before the fix.
Explicit zero caps and zero witness values preserve the declared dimensions,
full output join and unchanged account. G=1 and fully occupied G=2 layouts
are unchanged. The original corpus run is retained; corrected corpus and
focused capacity checks must pass before freezing evidence.

Focused 8193/16384-channel checks passed complete external roots and explicit
group padding. Boundary controls also passed, including genuine ranged U-p,
all carry endpoints and zero-bound shift 92. Both complete raw and block
canonical magnitude sources composed; separately valid changed magnitudes
rejected their pinned source roots. The matrix continues in the original
runner, while the corrected corpus and full-width proofs remain queued.

The corrected corpus passed all 10000 cases plus the two full-capacity cases
at widths 8193 and 16384. Seed 2743 covered 354302 channels, 3352 zero-bound
cases and every shift from 0 through 92. Complete byte roots, column carries
and explicit ragged half-domain caps matched. Frozen SHA-256:
`52884129cf30f2439d1a29263c1f5b11d6a7aba6b00ad0ed8a987f074e3f88f6`.
The original failed corpus log is retained; its corrected driver completed
successfully. Matrix, full-width proofs and repository gates remain pending.

All 16 matrix proofs subsequently passed across both challenge fields and
repetition counts, including shift 92 and zero bounds. Runtime receipts and
all actual original consumers matched. Frozen SHA-256:
`d578a52ab2d44b8d3c0996326c8a4172febeba8335347da95b243ff08b4327ff`.
The original corrected proof runner completed successfully. Both full-width
proofs and repository gates remain queued behind their existing prerequisites.

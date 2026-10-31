# Biased attention normalization numerator (Q26 / Q31)

Draft RFC-0004 A3/A6 and RFC-0009 A2 research. Before code: can actual
sixteen-byte scaled magnitudes U and scalar denominator D produce W=2U+D
for all 16384 channels, retaining every source and range consumer? Costs are
c_a/c_sc/c_lu/T_misc. Kill the design if a false output, channel permutation,
source substitute, modulus alias, wrong shared-denominator broadcast or
missing original claim is accepted, or the supported domain is narrowed.

Use the full attention_normalization_bounds.Spec. Its static Umax, Dmax and
Wmax=2Umax+Dmax must fit sixteen bytes before constructing views. Both
channel tensors always expose sixteen byte planes; D exposes sixteen scalar
bytes. Prove complete whole ranges U<=Umax, D<=Dmax and W<=Wmax. For each
channel family choose G=1 when N times its compact byte width is at most
131072, otherwise G=2. Every G=2 child has exactly N/2 caps, with the whole
bound on real channels and explicit zero caps on unused channels. Repack all
verified groups in plane-major order. This retains the existing range limit
and the full 8193..16384 ragged domain as well as the full maximum width.

Across sixteen columns prove 2*U_byte+D_byte+carry_in=W_byte+256*carry_out.
D_byte is the actual verified scalar byte broadcast only to real channels;
its padded-channel view is zero. Four complete carry ranges each cover four
planes of N entries. Cap carries at two on real channels, zero on padding,
and zero at the final column. Initial carry is zero. Both column sides are
at most 767<p/2, and the static Wmax excludes overflow above sixteen bytes.
No whole-field wide equality or verifier-side plaintext sum admits W.

One degree-one A3 over 16N entries consumes five actual originals: U, the
masked D broadcast, carry-in, W and carry-out. Every view comes from verified
byte arrays and expected dimensions. Full schema, field/repetition bytes,
three external roots, all internal roots and verified child states precede
the parent transcript. Zero U, zero D and zero static U bounds retain every
consumer. Standalone bounded D=0 does not establish positivity; normalization
must compose the actual positive-denominator and scaled-magnitude proofs on
these same roots. Complete ownership and global attainment remain separate.

Identity<2^48 reserves base=2^63+2^14*identity. Ordered ranges are the GU
source groups, GW output groups, scalar D and four carry groups, at most nine.
Their wide-range ids are 256*identity+1..count with source roots base+1..count.
All inherited spans start at base+64..base+64*count. Parent A3 id is
1024*identity+128, with original ids base+16..20. External ids are distinct
and outside the reserved span. Test every namespace boundary.

Let a=log2(N), bu/bw/bd be the compact-byte exponents, and GU/GW be the
source/output group counts. Wmax>=Umax implies GU<=GW. Independent lookup
dimensions are GU copies of a-log2(GU)+bu+1, GW copies of
a-log2(GW)+bw+1, bd+1 and four copies of a+3. Each identity is
((2^m+255)/|K|)^repetitions; each unsquared reduction is
repetitions*(F(m)+F(8)+3m)/|K|, F(m)=3m(m-1)/2+2m.
Range/A3 numerator is
(9(GU+GW)+38)*a+7(GU*bu+GW*bw+bd)+80-9(GU*log2(GU)+GW*log2(GW)).
This includes parent loss 2(a+4). Parent draws a+4 per ZeroWeight/Sumcheck
label. Full nonlookup draws per label are
(4(GU+GW)+17)*a+3(GU*bu+GW*bw+bd)+36-4(GU*log2(GU)+GW*log2(GW)).
No A1 or new challenge label. Verify exact receipts and all five original
points. Binding/FS/H and complete upstream source proofs remain additional.

Tests first: 10000 independent NumPy integer sums, sixteen-byte roots and
column carries over exact/block modes, legal shifts, zeros and all compact
widths. Capacity cases cover GU/GW=1/1,1/2,2/2 and ragged 8193 channels.
Both fields/repetition counts must retain original claims, padding and zero
bounds. Attack every root, five compensated originals, genuine ranged W-p,
whole caps, all carry endpoints, shared D broadcasting and external high
planes. Compose actual positive denominators and scaled magnitudes, rejecting
separately valid replacements. Require three full 16384-channel proofs, one
per group family, and all repository gates. Queue the full proofs behind the
existing full numerator run without restarting completed or live work.

Continue Q26/Q31. Quotient product, strict remainder, signed output and final
conversion must consume these actual roots. Native/private inference, full
key/block/model ownership, global attainment, fidelity, independent audit and
all original task criteria remain required. No benchmark, new cut, range
capacity increase or additional weight pass is claimed. Draft amendments
remain unaccepted.

Primary controls passed. Every external/internal root, complete child and
false source/output/carry value retained its consumer. All five compensated
original-final attacks rejected at Bias:ClaimMismatch, including the shared
denominator view. Equivalent arithmetic metadata rejected at that consumer
as well. Corpus, boundary/composition suites, matrix and full-size proofs
remain under validation, with repository gates queued once.

Boundary controls passed. Whole caps, dense padding, all carry endpoints,
the genuine output-ranged W-p alias, an incorrectly unmasked D broadcast and
all external high planes rejected at their stated consumers. Source
composition, corpus, matrix and full-width proofs remain under validation.

The independent seed-2745 corpus passed all 10000 cases and six capacity
cases, covering 403456 channels and 3333 zero-bound cases. Both 8193 and
16384 channels retain all three group families. The frozen digest is
`2142863c9f6b3ce4f9c744b91d57f2570e5b6aa7463abea40df046ee62f96e65`.
Both exact and block-mode scaled-numerator/positive-denominator compositions
also passed, including valid source replacement rejection. The original
matrix continues; full proofs and repository gates remain queued.

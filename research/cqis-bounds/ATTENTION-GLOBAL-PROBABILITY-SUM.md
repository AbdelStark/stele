# Eight-byte probability aggregation (Q26 / Q31)

Draft RFC-0004 A3/A6 and RFC-0009 A2 research. Before code: can complete
per-block probability sums compose into an eight-byte normalization divisor
for a configured length up to 1048576? Costs are c_a/c_sc/c_lu/T_misc. Kill
the design if a wrong total, short-block overflow, source substitution,
coefficient other than one, modulus alias or missing child is accepted.

Use the existing complete limb-product consumer with right operands fixed to
one, rather than introducing another random projection. Expected metadata is
the attention_block_bounds schema, increasing unique absolute block ids,
one external source id per block, an output id, identity and repetition count.
For block b, cap z_b by min(1024,L-1024*b)*2^E using a complete wide range.
Its padding is zero. Each external source root is a four-byte scalar even
when the compact range uses one or two bytes.

The limb-product schema has count B, left_max=max(caps), right_max=1 and
radix_bits=8. Every left digit must equal the corresponding verified source
byte. Right digits are one in the low plane on real blocks and zero elsewhere,
including padding. Verify the entire limb product, all carry/output ranges,
both original operands and both public power claims. Its scalar output is
zero-extended to eight bytes, preserving every external high plane. The sum
is at most sum(caps)<=L*2^E<=2^34. No whole global field lift is valid or used.

The static limb certificate bounds every byte column in M31. Input whole
ranges exclude aliases; exact source joins associate the arithmetic with
the pinned block roots. This reference proves the sum of the expected roster.
It does not establish that the roster includes every required key or block.

Reserve identity<2^44 and base=2^63+2^18*identity. The source wide range uses
id 4096*identity+1 and root base+1. The complete limb product uses identity
64*identity+1 with roots base+2/base+3. All external ids are distinct and
outside the reserved span. Verify the disjoint inherited namespaces. Bind
full schema/block/role/field/repetition bytes, every external/internal root
and both verified child states into the returned composition state.

This wrapper draws no challenge. Existing child transcripts, claims and error
events remain complete. Metadata changes that preserve child caps may reuse
the same valid arithmetic proof but must change the returned composition
state. That state and actual upstream roots must be bound by the caller;
the wrapper does not prove block membership from metadata alone.

For a=log2(padded blocks), b the compact source-byte exponent, g the limb
output-slot exponent and k its number of result columns, lookup dimensions
are a+b+1,a+b+2,g+3,g+3. Each independent identity retains
((2^m+255)/|K|)^r and unsquared reduction r*(F(m)+F(8)+3m)/|K|, where
F(m)=3m(m-1)/2+2m. Range/A3 numerator is 20a+16b+18g+31; the inherited product
identity is k-1 and its A1 reduction is 2a+4b. Full nonlookup draws are
9a+7b+8g+13 ZeroWeight and 10a+9b+8g+14 Sumcheck. Confirm all receipts.

Tests first: 10000 independent NumPy sums, byte roots and carry identities;
short/partial/full lengths, sparse/full rosters, exponents 0..14 and compact
widths. Both fields/repetition counts cover zero, cancellation-free extrema
and ragged block padding. Attack all roots, every join, zero-hidden right
coefficients, short-block caps, aliases, carry/output bounds and all original
consumers. Compose complete probability-sum proofs on actual four-byte roots,
including valid alternate sums and all-zero blocks. Require a full 1024-block
proof at total 2^34 and every repository gate.

All exponential sources must use one shared globally attained maximum.
Independent block maxima change relative weights and are invalid. The source
composition here proves arithmetic sums, not that global attainment or full
key ownership. Positive Z, restored normalization units, native/private model
inference, fidelity and all original criteria remain required. No production
admission, benchmark result, new cut or weight pass is claimed.

Seed 2741 passed all 10000 independent cases over 79504 source blocks,
including 1552 zero totals. NumPy sums, complete source/output roots and
independent byte-column carries matched. All admissible shifts, exponent and
compact-width families, short/partial/full lengths and namespace limits were
covered. Frozen corpus SHA-256:
`8038fb212d844cc75ea49c5540ba58248b85b28a19caf5415c47eaed41ea23ee`.

The initial proof run passed receipt checks and every external root control.
An altered source word rejected at Source:SourceCopy:ClaimMismatch, rather
than the test's expected commitment mismatch: the internal source root is
recomputed, and the complete copy consumer catches the inconsistency. The
test now names that actual consumer; no verifier behavior changed. Remaining
controls, matrix, maximum and required gates are still pending.

All primary and boundary controls subsequently passed. Actual byte joins,
zero-hidden coefficient one, false totals/carries, both actual originals and
both public powers retained their consumers. Short-block overflow, source
aliases, dense padding, carry endpoints, output padding and full external
high planes rejected. Complete per-block probability sums composed for
nonzero and zero totals; valid replacements rejected their pinned roots.
The both-field matrix and full-size sum/alias control continue in the original
runner. Required repository gates remain queued once.

Normalization width check: the existing normalization schema permits exact
mode with L=2^20, E=14, source fraction 30, output fraction 0 and drop 0.
Then Zmax=2^34 and Dmax=Zmax*2^30=2^64, requiring nine significant bytes.
The global Z root remains eight bytes; a shared denominator representation
for exact and block modes must preserve this case with sixteen bytes.
Its positivity and scaling consumers are still required.

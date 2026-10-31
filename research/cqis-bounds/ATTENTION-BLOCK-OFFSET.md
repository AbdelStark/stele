# Complete weighted attention block

Q26/Q31, E5-03; Draft RFC-0004 A3/A6 and RFC-0009 A2. Before code: can one
weighted-offset consumer admit every value in a canonical 1024-key block at
width 16384, with complete source ranges and one A1 over key rows? Costs are
c_a/c_x/c_sc/c_lu/T_misc and temporary source storage. Kill the design if a
missing group, changed actual source, compensated channel error, whole-field
alias, zero-hidden original or unchecked padding/carry can be accepted.

Expected metadata fixes the full attention-sum schema, block, Boolean mask,
identity, three external source ids and repetitions. For B=ceil(L/1024),
0<=block<B and C=min(1024,L-1024*block). Every position in that contiguous
block is mandatory in both accumulation modes. The mask has exactly C bits.
This fixes the local roster; query/mask/GQA/model ownership remains upstream.
Keep original consumers unchanged. A new stream format admits C*w<=2^24
actual entries, with no proof loop over channels and no sparse-row substitute.
The older plaintext witness helper keeps its own entry-capacity guard; this
stream derives its domain from C and w under its separate versioned context.

Consume P_j in 0..Q*allowed_j, Q=2^E, every U_jc in 0..2S, and every O_c in
0..2*C*Q*S. The probability root retains one/two configured byte planes. The
U root retains four planes over the flattened row-major domain padded once
to next_power_of_two(C*w), not independently padded rows and channels.
The O root retains eight planes over padded channels. Each byte is a canonical
four-byte M31 payload in the existing Merkle descriptor.

Partition U into consecutive whole-row groups of at most floor(32768/w) rows.
Each complete wide range fits 131072 byte leaves and 65536 words. There are
at most 512 groups. Discard only their proven-zero internal padding when
reconstructing the flat external root; retain all global zero padding. Spool
the actual ranged words as four little-endian bytes each, at most 2^26 bytes.
Reauthenticate every group against its verified compact root during replay.
Keep only one complete range proof at a time, plus source metadata, O(w*K)
column state and the O(C*d) projected parent tables. Caller/codec memory is
additional. This is a structural bound, not measured process-memory evidence.

Use the existing radix-16 certificate with count C, left cap Q and right cap
2S. At C=1024,Q=16384,S=65535 it has eleven result columns, maximum sides
797696/797711 and maximum carry 49856, all below p/2. Preserve sixteen carry
planes, including initial/final and unused zero slots. Group them using the
existing min(16,65536/Nc,131072/(Nc*wc)) rule. The producer may obtain integer
convolution columns using base-field matrix arithmetic only because the
static certificate bounds each partial and complete nonnegative coefficient
below p. The verifier never recomputes the weighted integer products.

Canonical records are one complete range per expected index: probability,
all U groups, output, all carry groups, then one sum proof and exact EOF.
Every root and verified child state precedes rho and the ac channel draws.
Form A_j=sum_i nibble_i(P_j)*rho^i, B_j=sum_c lambda_c*sum_l nibble_l(U_jc)*rho^l,
and T=sum_c lambda_c*sum_k rho^k*(O_kc+16*C_(k+1,c)-C_(k,c)). One degree-two
A1 over padded key rows proves sum_j A_j*B_j=T. Both actual projected tables
are independently consumed at the emitted point, including zero factors.
Base-field matrix projections are linear in actual ranged digits; no supplied
view, receipt or plaintext output equality can authorize acceptance.

Reserve identity<2^42, base=2^63+2^20*identity. Wide-range identities are
16384*identity+offset, with offsets 1 for P, 2..513 for U, 514 for O and
515..522 for carries. Their compact source ids are base+2^18+offset, outside
all descendant spans. Parent views are base+2^19+1/+2 and the A1 identity is
65536*identity+4096. External roles are distinct and outside the entire span.
The full schema, inferred positions, mask and every role bind the context.

For each complete range retain its independent lookup identity at dimension
m=a_i+b_i+1, ((2^m+255)/|Kfield|)^r, and unsquared reduction
r*(F(m)+F(8)+3m)/|Kfield|, F(m)=3m(m-1)/2+2m. Range/A3 loss numerator is
sum_i(9a_i+7b_i); each nonlookup label has sum_i(4a_i+3b_i) child draws.
The parent adds 1+ac+ar Sumcheck draws, identity loss ac+K-1 and separate
A1 loss 2ar. Binding/FS/H and upstream ownership remain additional.

Tests first: 10000 independent NumPy integer cases and carry-prefix checks;
all full parameter boundaries and disjoint namespaces; irregular flat/group
padding; both modes/policies/fields/repetition counts; exact stream roster;
actual range/source substitutions; bounded false sums and M31 aliases;
zero-hidden originals; complete probability/value composition at shared roots.
Require complete 1024x16384 and ragged 1023x16383 source proofs without
reducing their domains, plus a tail block. Independent size/resource evidence,
full restored-value preparation, signed rounding/global composition, native
private PCS/ZK/FS, GPU parity, fidelity and independent audit remain required.

The validated root builder from commit 3078b87 and field arithmetic from
8840c258 are prerequisites, imported with their frozen parity tests. Their
joint checks run before this consumer. No benchmark result is transferred to
this larger workload. Original task status/criteria and all live runs remain.

Prerequisite checks passed together: 40409 field products, four complete
range artifacts and four complete lookup artifacts retained their frozen
digests. The tests-first consumer run rejected the missing module. Seed 2759
then passed all 10000 independent integer cases over 225862 value cells,
including 2759 zero outputs. Counts and SHA-256 are asserted in the checker:
`789b0fb45e25c38ac6fd686fde1f5e08f8167aff56140b90b092ac62a4660013`.
All ten full-shape/namespace cases passed. Primary source/root, strict roster
and zero-hidden-original controls passed, including all-masked contributions.

The first boundary runner stopped while constructing a forged padded source:
the producer's replay reauthentication correctly rejected its changed compact
root. The corrected fixture submits that invalid child directly to the
verifier, targeting its range check; verifier code is unchanged. Corrected
boundaries, complete source composition, the matrix and full-size proofs
remain in validation. No independent audit or native coverage is claimed.

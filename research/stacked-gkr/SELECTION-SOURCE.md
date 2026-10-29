# Typed selection-source question (Q20)

Status: research. RFC-0006 A4 and the full private PCS/ZK path remain unresolved;
E3-06 retains every original criterion. This does not admit a commitment format.

Question: can a canonical bit-plane representation of the existing committed
index source make selection claims direct source evaluations, with actual
Booleanity, padding and range reductions instead of a trusted integer oracle?
Security properties: injective integer interpretation, one fixed source, complete
claim consumption and transcript order. Cost terms: source message/encoded cells,
c_sc/T_misc and all original openings. Kill criterion: a false bit/range/padding
statement accepted by complete reference consumption, a field-congruent index
alias, an unaccounted challenge or hidden source-storage expansion.

## Representation and identity

RFC-0004 §5.5 already names committed selection indices. This candidate changes
their representation, not the set of cuts: one M31-valued tensor F has a leading
bit-plane axis followed by the ordered source-grid axes. For k in 0..63 index
bits, M is the least power of two >=max(1,k), ell=log2(M), a is the source bit
count, N=2^a and D=ell+a<=63. There are at most 63 source axes, preserving the
64-axis physical limit. Plane j<k stores the j-th MSB index bit. All source-grid
holes and planes j>=k are zero. For k=0 the one dummy plane is entirely zero.

On valid rows, Boolean bits define the integer I by their ordinary binary string;
no scalar field sum reconstructs a possibly 63-bit integer. Indices 0 and p have
different source tensors even though they have the same M31 residue. Validity
proofs below make this interpretation unique. The argument uses Boolean logic
with gate values in {0,1}, not a wide field-to-integer equality; it introduces no
Accepted CQIS arithmetic record or replacement for other static certificates.

Expected metadata has exactly source_id, axes, bits, categories, instance_base
and tensor_base. Require 1<=C<=2^k and canonical grid bounds. Source absorbs
`stele/v0.1/research/onehot/source` with little-endian bytes:
`u8(1),u8(d),u64(source_id),u8(axis_count),each(u8(bits),u64(real)),u8(k),
u64(C),u64(instance_base),u64(tensor_base)`. This is at most 603 bytes and contains
no source values. The source must already be fixed before this absorb.

The expected plan reserves an aligned 128-id invocation block b and aligned
256-id virtual-tensor block t; each entire block must fit u64. The source id
lies outside the tensor block. Invocations b,b+1 check bits/padding; b+2 checks
the range root and b+3+j checks chain node j. Tensor t is the full validity mask;
t+1+j names suffix predicate R_j, t+65+j the bit-plane view, t+128+j its public
equality table, and t+191 the source-row mask. No virtual table is committed.
The stage adapter checks matching source/layout/k/C, disjoint invocation blocks
and separation from stage tensor ids. Authentication of the complete plan, its
semantic axis mapping and its remaining namespaces is still required.

## Actual conditional consumers

Let V(j,z) select j<k and every valid source coordinate. Its MLE is evaluated
independently with bounded-prefix products on disjoint axes. Two A3 zerochecks,
with skip count zero, assert `V*F*(F-1)=0` and `(1-V)*F=0`. Their degrees are three
and two. Mask finals are recomputed; every F final becomes an original source
claim. Even an unused original under V=0 is retained. Padding is therefore an
explicit obligation, not an assumption about honest capture.

When C=2^k, Booleanity already proves the range; the range payload must be None.
Otherwise the payload contains a root zerocheck and exactly k A1 nodes. Put
R_k=0. For public MSB bound bit c_j, define on Boolean source rows:

`R_j = (1-B_j)*R_(j+1)` if c_j=0;
`R_j = (1-B_j)+B_j*R_(j+1)` if c_j=1.

Induction on the suffix proves R_j is Boolean and compares the corresponding
index/bound suffixes. The two cases in the second expression are disjoint. Thus
R_0=1 exactly when I<C. An A3 degree-two zerocheck asserts
`valid_rows*(R_0-1)=0`. Padded rows are masked. Its actual R_0 final feeds a chain
of degree-three A1 instances for `R_j(u)=sum_z eq(u,z)*relation(B_j,R_(j+1))`.
Every equality final is checked, every bit final reaches the source, and the
terminal R_k final must be zero. Zero coefficients never discard bit claims.

A bit-plane claim (j,z,value) maps to the exact original F point
`bits_ell(j) || z`, in MSB order. Both range-chain and weighted-selection claims
use this mapping against the same source id. Actual stage composition runs the
source validity proof, the private coefficient stage, all original stage tensor
consumers and all mapped F consumers on one transcript. Its verifier reference
consumer receives F and the original stage tensors; it does not receive the
integer index vector as an authentication oracle.

The test context binds actual F/tensor bytes before challenges. It is a public
reference fixture. Private PCS must authenticate every emitted F claim against
the same previously fixed commitment, with the actual encoding/layout metadata.
A receipt or a metadata id alone is not that opening. Messages are unmasked and
reveal evaluations, including individual bits in scalar cases. No private PCS,
joint simulator, profile admission, new commitment format or inference is proved.
Failure after an absorb invalidates the attempt; no rollback/retry is provided.

## Accounting and costs

A3 retains all three phase records, including the zero skip record. Bitness costs
D+3D, padding D+2D, and the optional range root a+2a. Each of its k A1 nodes costs
3a. The conditional numerator is `7D + 3a(k+1)` over |K| for C<2^k, and 7D
otherwise. Draw counts are `4D+a(k+2)` or 4D: existing ZeroWeight and Sumcheck
draws only, no RLC or skip draw. Add the stage/selection losses separately.
Fixed-source/PCS, possible opening batching, FS/H and joint ZK obligations remain
additional; no conditional algebraic bound is promoted to a certified profile.

Raw-index conversion costs O(M*N+n*(s+k)) for n real rows and s source axes.
The folded no-skip zerocheck uses linear table folding and agrees byte-for-byte
with the existing exhaustive A3 oracle. Source proving costs
O((M+k)*N+n*s+k*(D+s+1)), including emitted point/metadata work;
conditional verification costs O(D+s+k*(D+s+1)), excluding
actual openings. Direct reference consumption of q source claims costs
O(q*M*N*(D+1)); q is 2 or 2+k here, plus k selection claims when composed.

The prover caps conservative prepared payloads `(2M+2k+2)*N` at 2^18 K cells
before scanning source values. Caller-owned F, validity masks, plane slices and
range tables are counted; folding scratch, equality vectors, proof/context bytes
and Python objects are extra. This is not a total-memory bound. Proof payload is
`7D+4` K elements, plus `3a+2+k*(4a+3)` for the nontrivial range branch.

The prospective commitment message has M*N M31 symbols, or 4M*N bytes, before
code expansion, Merkle data and blinding. For k=17 and N=n this is 128n bytes,
versus 8n for u64 capture: 16-fold expansion. These are size formulas, not measured
benchmarks. Compact byte/limb sources need their actual authenticated decomposition;
this candidate does not resolve or waive RFC-0010's packing requirements.

## Evidence and recommendation

Run `uv run --locked --script research/stacked-gkr/check_selection_source.py`.
Per field, 64 seeded source proofs and eight composed stages pass with every
original, SC record, proof size, challenge label/order and continuation checked.
The corpus hash is `d1860cc03b528001e4655affb95715827e4581d85f2e0a0f2543ac7cd1683795`.
Another 5461 small-domain comparisons per field check the range polynomial
against integer comparison. Cases include 63-bit indices, distinct 60-bit planes
over six real rows, grid holes, zero-width axes, maximal frame/id blocks, exact
independent frame bytes, and overflow/scope/capacity rejection.

Actual false-bit, padding and range proofs reject; one unused source final fails
SourceClaimMismatch at the real reference consumer. Changed masks, range leaves
and source scopes reject explicitly. Substituting index 0 for an admitted p source
fails the source opening check; p itself fails range admission when C=p. Omitting
only Source before a scalar proof changes a real successor A1 final and rejects.
Legacy A3 vectors, private-stage and weighted-selection regressions remain intact.
These are research checks, not production NC-0203 or PCS controls.

Recommendation: retain this as a complete conditional bit-source baseline, compare
compact representations with real decomposition and opening costs, and resolve
private PCS/joint masking before choosing a format. A4 and E3-06 remain open.
See the [same-author review](../../agents/reviews/selection-source-study.md).

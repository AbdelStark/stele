# Weighted private selection composition (Q20)

Status: research. RFC-0006 A4 and E3-06 remain blocked; no private PCS or ZK
construction is admitted. All original task criteria remain required.

Question: can the private onehot reduction cover canonical multi-axis source
views, arbitrary category-axis placement, selected axes and broadcasting without
exposing the original index vector or allocating the category domain?
Security properties: exact MLE-of-Boolean-product semantics, expected source/view
identity, complete original consumption and transcript continuation. Cost terms:
c_sc/T_misc, source-view preparation and actual private consumers. Kill criterion:
any explicit-table mismatch, divide-by-zero exception on valid weights, omitted
original claim, source-layout alias or category-domain-sized candidate work.

## Relation and source coordinates

This extends the [one-row-axis study](PRIVATE-SELECTION.md), retaining its A1
product tree, conditional loss and complete original consumption. Public metadata
contains exactly layout, source_axes, category_axis, selectors and source_id.
The layout has t in 2..64 axes (b_i,n_i), 0<=b_i<=63, 1<=n_i<=2^b_i, with
m=sum b_i<=63. Source axes S are a nonempty, strictly increasing list of distinct
axis ordinals; the category axis c is distinct. All remaining axes broadcast.
Each selector is absent or contains exactly b_i canonical K values. Zero-width
axes retain their ordinal and an explicit absent/present selector flag.

For each bit j, form weights w_j=(1-q_j,q_j) from the full canonical query q.
If its axis is selected, multiply the pair entrywise by (1-z_j,z_j). These are
weights of the Boolean entries before extension. For example, I=1,q=2,z=3 gives
6, whereas multiplying the separately extended onehot and selector gives 16.
No factor is normalized: zero pairs, zero-sum pairs and zero broadcast factors
are valid, including at nonzero extension coordinates.

Let a=sum_(i in S)b_i, N=2^a, n=product_(i in S)n_i, k=b_c and C=n_c. The source
contains n integers I_z in [0,C), in real row-major order over the ordered source
axes. Its Boolean coordinates concatenate each source axis in MSB order. B_j(z)
is the j-th MSB index bit, zero on every padded grid cell. Padding can contain
holes: source axes (1,2),(2,3) have padded positions 3 and 7, not a trailing pair.

Define the public broadcast factor

`B = product_(i outside S and {c}) sum_(x_i<n_i) product_bits w_j(x_j)`.

The exact full-tensor coefficient MLE is

`v = B * sum_(valid z) product_sourcebits w_j(z_j)
     * product_(j<k) [w_cj(0)+(w_cj(1)-w_cj(0))*B_j(z)]`.

Expand the Boolean category indicator and sum the disjoint broadcast coordinates
to obtain this identity. The source validity mask is the Cartesian product of
the real prefixes; it is not a single prefix of length n. The public root
coefficient evaluates by multiplying bounded-prefix evaluations on disjoint
source axes, after combining each w pair with the A1 query basis. This does not
replace overlapping selected factors by a product of their separate MLEs.

Set M to the least power of two >=max(1,k). Use the existing degree-two root A1
and M-1 degree-three product-node A1 instances. Every real leaf exports its
original B_j claim at that node's exact source point, even with zero affine
slope or B=0. Every padded leaf equals one. No division or new commitment occurs.
The receipt scopes all k original claims by (source_id, ordered source layouts,
k,C); source_id is a u64 namespace value, not evidence of authentication. The
reference consumer independently reconstructs every original bit-plane MLE,
including padded cells. The production plan must authenticate the actual source
view and establish Booleanity, padding, integer packing and I_z<C.

## Candidate framing and loss

Before root A1, Weighted absorbs label `stele/v0.1/research/onehot/weighted` with:

1. u8(1), u8(d), u8(t), each axis as u8(bits),u64(real).
2. u8(s), the s source-axis ordinals as u8, u8(category_axis), u64(source_id).
3. For each full axis, u8(selector_present), then its b_i K values if present.
4. All m query K values in canonical full-axis order, then the claimed K value.

Integers are little-endian; K has d canonical M31 u32 limbs, d in {4,8}. Reject
unknown metadata keys, invalid layout/source/category/selector identities and
noncanonical elements before the absorb. The original Evaluation frame rejects
GridSpec rather than aliasing a grid to a single prefix with the same (a,n).
The descriptor selects neither an evaluator callback nor a proof schema.

The shared engine preserves A1 Instance, Round/Sumcheck and Final order, local
instance ids 0..M-1 and the Originals absorb from the original study. All root,
child and leaf claims have the same consumers. There are a*M existing-kind
Sumcheck draws, SC numerator a*(3M-1) over |K|, and no extra RLC draw. The union
bound is conditional on fixed, valid original bit planes and their real
consumers. Weighted replaces Evaluation for this wrapper; it adds an absorb,
not a random loss. Source/range/PCS, FS/H and joint ZK obligations are additional.
These research labels are not production registry or profile admission.

This Python object interface is not a production proof byte parser. Failure
after an absorb invalidates the attempt. The unmasked one-row proof still
reveals the index bits; the public original-source fixture supplies no private
authentication or zero knowledge. A returned receipt alone is not acceptance.

## Costs and evidence

Metadata derivation uses O(t+m) work and O(m) pair storage. The exact frame length
is 13+10t+s+4d*(m+u+1) bytes, where u<=m is the selected bit count: at most 4780.
Prepared tree/bit/mask payloads retain N*(2M+k) K cells, capped at 2^18 before
scanning or materializing the source. This is not a total-memory bound: preparation
also holds an N-cell row-weight vector, A1 uses O(N) scratch, pending points
and retained proofs use O(a*M+k), and Python objects, source indices and Cartesian
coordinate pools cost extra. Source position generation costs O(n*s).

Preparation/proving use O(N*M+n*s+t+m) work. Conditional verification uses
O(a*M+k+t+m), plus the real original consumers. The reference consumer uses
O(n*(1+k*(a+s))+s) word/field work, including source-domain validation and grid
coordinates; a private consumer must be charged separately. The proof contains
exactly a*(4M-1)+3M-1+k K elements. M<=64; neither candidate path allocates the
category or broadcast domain. These are formulas, not measured performance;
no c_sc/T_misc constant, weight-pass count or full stacked cost claim changes.

Run `uv run --locked --script research/stacked-gkr/check_weighted_private_selection.py`.
Seed 30624 checks 1000 explicit full-Boolean-table comparisons and 128 seeded
reductions per field in QM31 and OM31. It checks all original consumers, SC
records, exact proof sizes and transcript continuation. The seeded corpus hash is
`5e9c863cf5bafc30442186e9cd8403cce4d563d14b7528143a95fbfc717985a6`.
The legacy study remains byte-identical, with corpus hash
`0a2503f9a1298b61cc7e687ac6644cebfce7f8742bfc3c43781c3bad3cd946d1`.

Additional cases cover arbitrary category placement, multiple source axes,
irregular padding, all zero-width axes, a 63-bit category and a 62-bit broadcast
prefix checked against a separate LSB-borrow evaluator. Independent frame bytes
agree. Malformed scope/selectors/proof shape and preparation capacity reject.
With B=0 and a zero leaf slope, a changed original corresponding to a padding
hole passes conditional replay but fails the original consumer with
OriginalSourceMismatch; changed receipt scope fails with OriginalSourceScope.
An adversarial prover omits only Weighted in the first of two reductions: its
next proof changes one final, and unchanged verification rejects it with
FinalEvaluationMismatch. These checks receive no production NC credit.

Recommendation: continue Q20 by connecting this conditional obligation to the
actual stacked coefficient final and authenticated plan/view. Full source/proof
bytes, bit/range/PCS consumers, joint masking, native parity, controls and complete
stacked costs remain acceptance gates. See the [same-author review](../../agents/reviews/weighted-private-selection-study.md).

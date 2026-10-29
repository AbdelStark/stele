# Private selection coefficient question (Q20)

Status: research; RFC-0006 A4 and E3-06 remain blocked. No production behavior,
source authentication, zero-knowledge construction or catalog credit is added.

Question: can a onehot MLE claim reduce to original index-bit claims without
requiring the selection vector as verifier input or constructing its dense table?
Security properties: original-source binding, exact index range and privacy of
witness indices. Cost terms: c_sc/T_misc, original index-bit consumers and their
range/packing relations. Kill criterion: any mismatch with the explicit Boolean
onehot table, unchecked original bit claim, degree above four, or work/storage
proportional to the category domain rather than the index-bit data.

## Authority and privacy

RFC-0001 §3 lists selection indices as witness; RFC-0013 protects private tokens
and activations. An index already fixed by an authenticated public input can use
the public coefficient path. An auxiliary index derived from private activations
does not become public merely because a coefficient evaluator needs it. Opening
the entire vector authenticates its values but also reveals them. For example,
two rows (1,0) and (0,1) have the same maximum but different attaining indices.
This is a missing privacy obligation, not an attack on an implemented prover.

The candidate verifier below receives only a shape, two query points, the claimed
coefficient value and a proof. It exports original bit-plane claims for a separate
consumer. The executable reference consumer knows the actual original indices
and checks every bit evaluation independently. Its test context binds those
indices as actual public bytes; this is explicitly a public oracle fixture, not
private source authentication. A source digest or a caller-set flag cannot replace
the missing real consumer. Global source/view ids and production bytes remain open.

The prototype is unmasked and not ZK. In particular, a one-row instance reveals
its original bits directly. Even for larger rows, exposed linear evaluations
require the joint masking/PCS construction in RFC-0013 A1. Removing the need to
send all indices as verifier input does not prove that the proof hides them.

## Conditional relation and reduction

This concrete study has one row axis and one category axis. Multi-axis source
views, broadcasting and the full descriptor's selected-axis weighting still
require explicit composition; existing A4 requirements are not weakened.

Let a be the row bit width, N=2^a, n<=N the real rows, k the category bit width,
and 1<=C<=2^k the real category count. Indices I_i satisfy 0<=I_i<C. B_j(i) is
their j-th bit in MSB order for i<n, and zero on padded rows. For query (r,s),
the exact onehot MLE is

`v = sum_(i<n) eq(r,i) product_(j<k) ((1-s_j)+(2s_j-1) B_j(i))`.

The category table is one at (i,I_i) and zero elsewhere, including padding.
This equality follows by expanding its Boolean indicator, before multilinear
extension. Products of separately extended bit planes are not substituted for
the MLE of their rowwise product.

Set M to the least power of two >=max(1,k). The M leaves are the k affine factor
tables, then constant-one tables. Each internal table is its children's pointwise
product on the row cube. Padded rows of an affine leaf equal 1-s_j, not zero;
only the initial validity-weighted coefficient excludes those rows.

1. An A1 instance of degree two proves `v=sum_i A_r(i) T_root(i)`, where A_r is
   the MLE of the single Boolean table `valid(i)*eq(r,i)`. Check its final through
   a two-state MSB prefix evaluator with O(a) field work and constant DP state.
2. Consume the resulting root claim. In heap order, each internal node at point u
   uses degree-three A1 for `T_node(u)=sum_i eq(u,i) L(i) R(i)`. Independently
   check the equality final. Its two child claims have the same new row point;
   different nodes may have different points. Every child is consumed exactly once.
3. At original leaf j, receive a claimed B_j evaluation b at that leaf's point
   and check `leaf=(1-s_j)+(2s_j-1)b`. Retain b even if 2s_j-1=0. Padded leaves
   must equal one. Absorb every original b, then export all k original claims.

No new intermediate is committed. These are virtual tables fixed by the original
bit planes and the query. Every emitted original requires its actual source
consumer; a successful conditional receipt alone proves no coefficient provenance.
For k=0 the category is uniquely zero, the tree is constant one, and there are no
bit claims. Original source validity still belongs to the source's real consumer.

The source contract must establish Boolean bits, zero padded rows, canonical
packing into the original committed index representation and I_i<C. Bit width
alone admits padded categories: k=2,C=3 permits the bit pattern 11, whose factor
product at s=(1,1) is one even though the valid category table has no such entry.
A single M31 residue is also insufficient: indices 0 and p have the same residue
but select different columns. Full integer/source-range certificates and actual
consumers remain required; this study introduces no accepted packing schema.

## Transcript and conditional loss

The research-only Evaluation absorb uses label
`stele/v0.1/research/onehot/evaluation` and payload
`u8(1),u8(d),u8(a),u64(n),u8(k),u64(C),K[r],K[s],K(v)` with little-endian integers
and canonical M31 limbs in the existing K basis. Shape and point lengths are
checked first. The fixture context identifies its sole original source; these
local ids are not production plan identities or a complete stage descriptor.

A1 instance ids are 0 for the initial reduction and 1..M-1 for heap-order nodes.
Ordered local inputs are (A_r,root) or (eq,left,right); local ids are 0..1 or 0..2.
Their receipts stay inside this wrapper. Each instance uses unchanged A1 Instance,
Round/Sumcheck and Final order. After the leaf checks, Originals absorbs label
`stele/v0.1/research/onehot/originals` with u32(k) and all k canonical K values.
Its count and ordering come from the expected shape, not proof-selected metadata.
The prototype checks proof list lengths but does not define a production byte parser.
An error after an absorb invalidates the attempt; any retry starts fresh.

There are a*M existing-kind Sumcheck draws and no extra RLC draw. The conditional
SC records are (m=a,delta=2) and M-1 records (m=a,delta=3), giving numerator
`a*(3M-1)` over |K|. Every node's true table is fixed by the same original source
before its own challenges; A1 plus a union bound carries a false root to a false
original claim except for this loss. Exact public and affine/constant checks add
no random loss. The actual source/range/PCS, FS/H and ZK costs and losses are extra;
these research labels are not registered by production and certify no profile.

## Costs, evidence and recommendation

Prepared tree, bit-plane and mask payloads occupy N*(2M+k) K cells. The prototype
caps that term at 2^18 before materialization; this is not a total process-memory
limit. A1 scratch, equality vectors, pending points, Python objects and retained
proofs are additional. With fixed degree, preparation/proving use O(N*M) field
work; the verifier uses O(a*M+k) plus actual source consumption. The independent
reference consumer costs O(n*a*k), with scalar cases charged separately. A real
private consumer has its own cost. The proof contains exactly
`a*(4M-1)+3M-1+k` K elements. M<=64 even for 63-bit categories: no candidate phase
materializes 2^k categories. These are formulas, not measured performance results.
This does not establish the full stacked prover's sparse preparation or fuse an
inference weight opening; those costs remain separate acceptance requirements.

Run `uv run --locked --script research/stacked-gkr/check_private_selection.py`.
Per field, 1000 explicit-table/sparse/prefix comparisons and 128 seeded reductions
plus six width boundaries pass in QM31/OM31. Tests include nonzero extension limbs,
irregular padding, k=0, 63-bit categories, a 63-bit prefix partition, every original
claim/SC record and transcript continuation. The seeded proof/receipt checksum is
`0a2503f9a1298b61cc7e687ac6644cebfce7f8742bfc3c43781c3bad3cd946d1`.

One-value tests reject wrong originals (including zero coefficients), wrong public
coefficient finals, constant leaves and round messages. Bad lengths/limbs/shapes
reject; source preparation rejects out-of-range indices and over-capacity inputs.
That preparatory rejection does not implement a verifier range proof. An adversarial prover
that omits Originals changes one final of the next proof and the unchanged verifier
rejects it. These are research checks, not NC-0203 or private-consumer coverage.

Recommendation: continue Q20 with a distinct private coefficient obligation.
Do not implement the current public resolver by exposing private index vectors.
Acceptance still requires authenticated plan/view identities, actual bit/range/PCS
consumers, full source/proof bytes, masked composition, native protocol parity,
controls and the complete stacked cost contract. E3-06 and the full prover stay open.

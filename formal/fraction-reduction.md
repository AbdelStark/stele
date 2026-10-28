# Fraction-tree reduction and original-source obligations (Q31)

Candidate for Draft RFC-0008 A2 / RFC-0012 A8, not an admitted lookup protocol.
Question: can the grouped-unit tree reduce both root values to the actual leaf
arrays, including the selected-product denominator? Kill criterion: an unchecked
coefficient, child, selector or source claim, or a challenge sampled before its
inputs are fixed. Evidence: [executable study](../research/logup-characteristic/FRACTION.md).
This specializes the fraction-tree idea in Papini–Haböck,
[Improving logarithmic derivative lookups using GKR](https://eprint.iacr.org/2023/1284),
§3, to the Boolean cube, the grouped weights and the explicit schedule below.
The conditional argument here includes every draw; no theorem label substitutes
for source binding, private consumers, Fiat–Shamir composition or privacy.

## Descriptor, arithmetic and schedule

The verifier supplies tree id, m, b, ordered distinct leaf ids and theta of length
h=m-b. Coordinates are MSB first. There are N=2^m leaves; k=0 is the root and
k=m the leaves. At parent layer k<h set a=1-theta[k], z=theta[k]; otherwise
a=z=1. Children are adjacent: child index 2i or 2i+1. The actual relations are
P_k(i)=a*P0(i)*Q1(i)+z*P1(i)*Q0(i), Q_k(i)=Q0(i)*Q1(i).
This is an arithmetic reduction over K. Weighted lookup additionally needs the
static b<=30 bound and all hypotheses of [the unit construction](weighted-logup.md).

Bind the descriptor and both roots. Initially r is empty and (p,q) are the roots.
For k=0..m-1, bind (tree id,k,r,p,q), then draw fresh gamma. Run RFC-0006 A1 on
k variables, sum p+gamma*q, ordered inputs (P0,Q0,P1,Q1,Eq(r,·)), and terms
a*P0*Q1*Eq + z*P1*Q0*Eq + gamma*Q0*Q1*Eq. The per-variable degree is three,
including when a coefficient vanishes. All five final values are absorbed by A1.
At its point u check the fifth value against the verifier's exact Eq(r,u).
Only then draw fresh tau, set r=(u,tau), p=(1-tau)*p0+tau*p1 and
q=(1-tau)*q0+tau*q1. Appending tau restores the canonical last child coordinate;
prepending it proves claims at the wrong original point. The four local child
claims are consumed by this fold; local ids 0..4 never escape the tree reduction.

The output is exactly the two original leaf ids, r, p, q and accounting records.
Both original leaf claims need actual consumers. m=0 has no gamma, tau or rounds:
the supplied roots are direct original scalar claims. k=0 for m>0 still draws
gamma and tau and uses a scalar A1 final, so its two losses are not omitted.

## Conditional interactive soundness

Fix the original leaf arrays before the reduction and define their entire tree
by the stated arithmetic, without committing any intermediate. If either current
claim is false, their gamma combination is false except with probability <=1/|K|:
its difference is a nonzero polynomial of degree at most one. Conditional on a
false combined sum, A1 either rejects or emits a false child evaluation, except
with probability <=3k/|K|. The exact equality check excludes a false Eq claim.
After all children are fixed, at least one of the P or Q folding differences is
a nonzero degree-at-most-one polynomial in tau. Both propagated claims can
become true with probability at most 1/|K|. This reasoning is conditional on the
entire preceding interaction; gamma/tau can be zero and require no inversion.
Union over layers gives min(1,[3m(m-1)/2+2m]/|K|), conditional on true final
leaf evaluations. Each tree contributes its own term. This is not a standalone
Fiat–Shamir theorem and is not squared with the rational-identity error.

For lookup acceptance, separately check both **bound** root denominators nonzero
and P_lookup*Q_table=P_table*Q_lookup. A valid arithmetic proof can have Q=0:
it proves computation but cannot pass this root consumer. Honest poles abort;
there is no silent challenge retry. Any attempt/grinding policy still needs the
full protocol's explicit accounting. The table-side multiplicity claim must
reach the committed K-valued vector; arithmetic checks alone do not supply it.

## Selected-product leaf consumer

For fixed Boolean sigma and tuple columns x_j, beta powers start at j=0. The
actual leaves are P(i)=sigma_i and Q(i)=1-sigma_i+sigma_i*(alpha-sum_j beta^j*x_j(i)).
Inactive and padded leaves are (0,1), even if their unused value is a pole.
At an emitted point r, check p=sigma_tilde(r) and set
H=1+(alpha-1)*sigma_tilde(r)-q. Prove H by a degree-three A1 sumcheck on m variables
with inputs (Eq(r,·),sigma,x_0,...,x_{c-1}), terms beta^j*Eq*sigma*x_j.
Absorb a leaf frame binding the descriptor, ordered original source ids,
alpha,beta,r,p,q before this sumcheck. Check the final Eq and sigma evaluations
independently, then emit **every** original x_j claim at the same final point,
including zero-coefficient columns. The additional conditional loss is 3m/|K|.
The equation uses the MLE of the Boolean selected product. Replacing it with
sigma_tilde(r)*sum_j beta^j*x_j_tilde(r) is generally false, as the study demonstrates.
This prototype consumes all actual public source arrays; private reduction/PCS
consumers and the table-side public denominator consumer remain to be integrated.

## Candidate bytes and costs

All integers below are little endian; K elements are d canonical M31 u32 limbs,
d in {4,8}. Descriptor bytes are u8 version=1, u8 d, u64 tree id, u32 m, u32 b,
two u64 leaf ids, then h K theta values. Derive all counts from this descriptor;
0<=b<=m<=63. TREE absorbs descriptor then two roots. LAYER absorbs u64 tree id,
u32 k, k point elements then p,q. LEAF absorbs descriptor, u32 c, c u64 source ids
(distinct and >=2; 0,1 are local public inputs), then alpha,beta,r,p,q. This is a
research-local id convention; it does not establish the native plan namespace.

Candidate labels are stele/v0.1/lookup/{fraction,layer,gamma,fold,leaf}. Absorbs
use A1 tag 0 framing; gamma/fold use its tag 1 request and tag 2 ratchet, d and
consumed-word count, canonical field output and capped rejection sampler.
Existing A1 instance/round/final/challenge labels are reused for sumchecks; tree
sumcheck id is k, leaf sumcheck id is tree id, scoped by their preceding frame.
Every Final precedes the next challenge. Exhaustion rejects. The research
Transcript owns all draws; none uses a fixture RNG. Production labels unchanged.

The object representation uses tuples for K elements, excluding type aliases
that would give inconsistent zero/equality checks. The tree encoder validates exact keys, counts and canonical fields before
absorption. Encoded proof payload is roots followed, for each k, by k rows of
four A1 endpoints and five finals: 4d*(2+2m^2+3m) bytes. The leaf adds
4d*(4m+c+2) bytes. Descriptors, source commitments, public inputs, other trees
and framing are additional. There is no production byte parser or allocation cap
in this study; object validation is not native wire admission.

Dense tree retention is 2N-1 K pairs, before original sources, A1 copies and
equality tables. Direct equality-table materialization and public consumers use
O(N*m) field work in this prototype; no linear-time implementation or streaming
memory claim is made. Candidate c_lu/T_misc, proof bytes and peak memory need
complete native measurement. No cost-model constant, benchmark, GPU parity,
one-weight-pass receipt, NC catalog credit, ZK or profile admission is supplied.

# Complete lookup schedule and committed consumers (Q31)

Draft RFC-0008 A2 / RFC-0012 A8; [study and kill criteria](../research/logup-characteristic/LOOKUP.md).
This composes [grouped units](weighted-logup.md) and the
[fraction reduction](fraction-reduction.md). It closes the research computation
with actual Merkle commitments and full-vector openings. Revealing the complete
sources/multiplicities is not the private functional PCS or ZK protocol required
for inference. No alternative production mode, task completion or privacy claim
is introduced. Exact native plan, PCS, source-layout and wire contracts remain.

## Fixed statement and challenge schedule

The verifier supplies id, field degree d in {4,8}, m, b<=min(m,30), repetitions
r in {1,2}, c distinct original source ids, r distinct multiplicity ids, a unique
ordered table T of c-tuples in M31, N=2^m Boolean selectors and c source roots.
All source/multiplicity ids are mutually distinct. Table size t is in [1,2^16].
The plan's selector is fixed before units; authenticating this literal public
array does not establish an inference plan's CQIS mask or source-padding policy.

Source columns commit N canonical M31 values with RFC-0012 A3 kind-0 Merkle
trees, id=source id, count=N, width=4. Weighted multiplicities commit t canonical
K values with id=multiplicity id, count=t, width=4d. The statement fixes field,
roles, table order and dimensions. Merkle's absent-leaf padding is an encoding
rule; the consumer's zero padding of the polynomial is a separate semantic rule.

Start the A1 transcript with the entire statement, including original source
roots, actual table tuples and selectors. Draw all r vectors theta_j of length
h=m-b. Bind all r multiplicity roots before **any** beta or alpha. Then draw
beta_j followed by alpha_j for each j, completing all pairs before any tree proof.
Multiplicities may depend jointly on all theta vectors but cannot be chosen
after a denominator challenge. Distinct draws may coincide by chance; do not
resample or enforce inequality. The fixture only checks its deterministic values.

For each repetition in order: prove the weighted lookup tree; prove the ordinary
table tree; prove the selected-product source leaf reduction. Check both bound
root denominators nonzero and cross multiplication. No tree intermediate is
committed. The source leaf exports all c original source claims. For table depth
k=ceil(log2(t)), real leaves are (mu_i,alpha-z_beta(T_i)); padded leaves are (0,1).
Evaluate the public table denominator at the emitted point, including these
padded ones. Export the numerator as a claim on the same committed mu vector,
extended by zeros to length 2^k. A nonneutral padding denominator can preserve
the rational identity; the exact denominator consumer is still mandatory.

The revealing adapter reconstructs every original source and mu root from its
complete canonical payload. It then checks every claim against those originals
at the exact derived point, in expected source-id order followed by the mu id
for each repetition. Missing claims, substituted roots/ids, wrong dimensions,
noncanonical values or mismatched MLEs reject. All revealed payload bytes are
absorbed after successful consumption, before any following protocol challenge.
Sources are revealed once but consumed at r points; mu is distinct per repetition.

## Accounting and conditional composition

Let F(n)=3n(n-1)/2+2n. A conservative conditional interactive bound is

`min(1, e^r + r*(F(m)+F(k)+3m)/|K| + epsilon_binding)`,

where e=min(1,(h+N+c*t-1)/|K|). The identity theorem requires fixed sources and
binding of all mu before beta/alpha. Each fraction tree's two original leaves
must be consumed: exact table Q, original mu P, public sigma and all source
columns. Original MLE evaluation and nonzero/cross-product checks add no random
loss. The revealing adapter supplies exact evaluation conditional on actual
Merkle binding; it is not an uncharged private PCS opening. FS/H and quantum/query
composition still require Q12; epsilon_binding is not assigned a budget here.
The hash execution alone is not an extraction proof establishing the fixed-source
premise for an adaptive ROM/QROM adversary.
No standard/treaty admission follows from this conservative bound or its receipt.

The actual event inventory per invocation is r*h Unit draws, r Beta and r Alpha,
r*(m+k) Gamma and as many Fold draws, plus
r*[m(m-1)/2+k(k-1)/2+m] A1 Sumcheck draws. Every tree/leaf sumcheck has degree 3.
The Unit/Beta/Alpha failures are jointly charged to e^r under the unit theorem;
they are not independent per-coordinate SZ lines to add again. Gamma/Fold each
cost 1/|K|; the listed SC rounds each cost 3/|K|. GKR errors are added separately,
not automatically squared. Tests compare actual Transcript events with these
counts and enforce all-child Final before Fold and P/Q Layer before Gamma.

## Candidate representation and complete costs

Statement payload: little-endian u8 version=1, u8 d, u64 id<2^60, u32 m,b,c,
u8 r, u32 t, then c+r u64 original ids, N selector bytes, t*c row-major M31 u32
values, and c 32-byte source roots. The research public prefix is
Q31/lookup-study/v1. Existing A1 framing surrounds this complete public payload.

Additional labels under stele/v0.1/lookup/ are units, multiplicities, repetition,
openings (absorbs), unit, beta, alpha (draws). Units and Repetition absorb u64 id
and u32 repetition; Multiplicities absorbs u64 id, u32 r then (u64 mu id,32-byte
root) pairs. Openings absorbs c source columns in canonical order followed by
r mu vectors. All counts come from the statement. Draws reuse A1 capped sampling
and ratcheting; exhaustion/poles reject without retries. Production labels unchanged.

The two local tree ids are 4*id+2*j+side; their leaf ids are 8*id+4*j+2*side and
that value plus one. These are scoped research ids, not native tensor registration.
Source/PCS consumers always use the original verifier-supplied source/mu ids.
The proof object has mu_roots, rounds, sources, mus; each round has lookup,
table and leaf. There is no native byte parser or resource admission in this study.

With B(n)=4d*(2+2n^2+3n), the payload inventory is
32r + 4cN + 4d*r*t + r*[B(m)+B(k)+4d*(4m+c+2)] bytes, excluding the public statement
and native framing. Full-vector reveals alone cost 4cN+4d*r*t bytes. Merkle
construction/reconstruction, complete source reads, table/selector validation,
histograms, all proof work and final absorption are additional costs. Dense
retention includes sources, r mu vectors, Merkle levels, fraction trees, A1 copies
and coefficient arrays. Direct MLE consumers require O(r*(cN*m+2^k*k)) field work;
this is not a linear-time or one-weight-pass pipeline. No measured c_lu constant,
native control, GPU parity, private-opening efficiency or ZK result is supplied.

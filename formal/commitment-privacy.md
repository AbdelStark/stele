# Commitment privacy and mask lifetime (Q29)

Status: Draft, RFC-0013 A1 / RFC-0010 A7 / RFC-0011 A1. Question: which complete
view and mask lifecycle hide committed weights across all openings? Security
property: no disclosure beyond the public statement. Cost terms: randomization,
encoding, queries, row messages, registration, per-proof work and retained state.
Kill criterion: distinguish secret-dependent views after accounting for all
declared public outputs, or reuse a mask beyond its proved disclosure budget.
This is a privacy diagnosis and conditional linear lemma, not a complete ZK PCS.
Review: [same-author skill passes](../agents/reviews/commitment-privacy-study.md).

## 1. Appending a row does not hide opened columns

Let E be the row encoder and append a random row z to the secret matrix M.
An authenticated column c is `(E(M_0)[c], ..., E(M_{R-1})[c], E(z)[c])`.
The first R entries do not depend on z. Thus revealing this column still reveals
the original encoded secret entries. A nonzero coefficient on z in the separate
row-combination message cannot change that fact. Hashing authenticates the
revealed values; it does not erase them. A salt on a hash does not hide its opened
payload either. This applies even before combining any openings across proofs.

For the Accepted Circle encoder, an all-zero row encodes to all zeros and an
all-one row to all ones. Any queried column distinguishes them regardless of
the appended mask. This is a commitment confidentiality test with two candidate
messages, not a collision, false-proof acceptance or two witnesses for the same
Merkle root. It exposes an explicit secret-dependent value absent from the
intended disclosure; it does not claim a full ZK impossibility theorem for every
possible statement including those values as already-public information.

Replacing append with the same additive pad on every secret row also fails:
`(E(M_i)+E(z))-(E(M_j)+E(z))=E(M_i-M_j)`. Independent private inputs are not
hidden by a shared pad merely because each separate marginal is uniform.

## 2. Exact linear-view privacy test

Fix a finite field F and public coefficients. Let x be a secret vector and
r be uniform in F^h, independent of x. The complete algebraic view is
`V=A*x+B*r`. For fixed x it is uniform on the affine space A*x+im(B): every
element has the same number of preimages under B. Therefore views for x,x'
have identical distributions exactly when A*(x-x') belongs to im(B); otherwise
their supports are disjoint. For all x in F^n, privacy is equivalent to
`im(A) subset im(B)`, or `rank([B A])=rank(B)`.

If a public linear output H*x is allowed, compare only differences in ker(H).
Equivalently use A*N in place of A for any matrix N spanning ker(H). For a
restricted secret set S, test its actual difference set; the full-space rank
condition is sufficient but need not be necessary. These conditions concern
linear views with uniform field masks, not arbitrary nonlinear proof messages.

Include every revealed mask-related value in this same view. For example,
revealing both x+r and r has matrices A=(1,0)^T, B=(1,1)^T and leaks x, although
x+r alone is uniform. Public adaptive challenges may depend on earlier messages;
a fixed-coefficient rank check alone does not prove an adaptive transcript's
distribution. Its conditional simulation, commitments, authentication paths,
Fiat-Shamir and all allowed prior disclosures require a separate argument.

## 3. Base-field masks do not generally hide extension-field rows

RFC-0010's source matrix is over M31 while its row functional is over K. If the
extra row is sampled over M31, a single coordinate lambda*z occupies the
one-dimensional M31 subspace lambda*M31, not all of K. Secret shifts outside
that subspace remain distinguishable even in the row message alone. A mask that
hides one M31 coordinate is not automatically a mask for a QM31/OM31 coordinate.

For a concrete small-field analogue, use F_9=F_3[u]/(u^2+1), a=(1-u,u),
lambda=1 and z uniform in F_3. Source rows (0,0) and (0,1) give row-message
supports F_3 and u+F_3, which are disjoint. Both sources have valid small integer
entries and a is a tensor row functional. More generally expand all K elements
in the fixed base-field basis and apply §2 over M31, including all coefficient
and mask disclosures. Sampling an entire K mask instead changes entropy,
encoded leaf width, memory and source/code semantics and needs its own contract.

Even a full-K mask does not help on a zero mask coefficient. A uniformly sampled
coefficient including zero has an exceptional disclosure event. Fixing it to a
nonzero value may avoid that event but changes the soundness proof and does not
repair column leakage. A statistical privacy error is not silently a MASK
soundness loss; both require their actual definitions and composition.

Masking also changes the functional: for u'=B+lambda*z,
`dot(u',b)=v+lambda*dot(z,b)`, not the original v=dot(B,b). Retaining the old
check rejects honest masked openings in general. Publishing the shifted value
without binding its relation to the original claim instead proves a different
statement. A correct construction must specify that relation and include any
revealed correction in the joint privacy view. Precommitting z does not make it
orthogonal to every later b. This also prevents silently calling u' the original
sumcheck B; the actual fused object and hidden-claim consumer must be reconciled.

## 4. Reuse changes the joint view, even when proof bytes differ

For one retained mask z and two public coefficients lambda_1,lambda_2,
`lambda_2*(B_1+lambda_1*z)-lambda_1*(B_2+lambda_2*z)` equals
`lambda_2*B_1-lambda_1*B_2`. If B_1=B_2 and the coefficients differ, the
original B is recovered. Otherwise a new linear relation is exposed. Individual
masked views can each be uniform while their joint view reveals the secret.
Different challenges and transcript digests do not certify independent masks.

A passport fixes its weight root before inference. A mask row contained in that
root is fixed with it: it cannot become fresh merely because a later proof has
a different seed. Updating the committed mask changes the root unless a proved
rerandomization relation is provided. Its source identity, certificate reuse,
weight reads and cost must be specified. No such relation follows from hashing.
Distinguish independent per-proof masks, persistent encoded-mask entropy and
fresh public challenges; they have different lifetimes and responsibilities.

For any fixed N-coordinate oracle exposed by independent uniform raw-coordinate
queries, after t total draws the probability of having every coordinate is at
least `1-N*((N-1)/N)^t` (or zero if that expression is negative), by a union bound
on unseen coordinates. Once all coordinates of a decodable randomized codeword
are disclosed, its original message can be decoded too. Thus bounded-query
randomization alone cannot hide such a fixed passport oracle for unrestricted
reuse. A limit, a proved refresh, or hiding the queried values through another
proof must be part of the contract. This is separate from fresh soundness draws.

## 5. What a randomized row encoder can and cannot establish

For a fixed set Q of queried coordinates of `E(x;r)=G*x+H*r`, §2 gives the
exact conditional column criterion `im(G_Q) subset im(H_Q)`. Full row rank
of H_Q is a sufficient condition. Minimum code distance alone does not imply
it: the distance-two code `(x,r)->(x,x,r,r)` exposes x in its first coordinate.
Systematic source positions require particular care; querying a coordinate
where all mask columns vanish discloses its message component directly.

An ordinary polynomial example clarifies the missing requirement. Let f_x be
the degree-<m interpolant of x at m distinct message points Z. Put
`p(X)=f_x(X)+V_Z(X)*g(X)`, with V_Z vanishing exactly on Z and g a uniformly
random degree-<h polynomial. At any q<=h distinct query points disjoint from Z,
the mask evaluation map is a nonzero diagonal times a Vandermonde matrix of
rank q. Those q values are uniform independently of x. This proves only the
raw-coordinate claim. It does not hide an entire transmitted polynomial/row,
its original message evaluations, or additional equations revealing the masks.

For a fixed encoded row the relevant query set is the union across its lifetime,
including the certificate, later proofs and auxiliary disclosures. In the
one-message/one-mask example p(t)=x+r*t, any one nonzero query hides x but two
distinct queries recover it. Resetting a per-proof counter does not replenish
entropy in the same root. General adaptive use needs a jointly conditioned
simulator and a justified lifetime policy, not a per-proof rank assertion alone.

The ordinary polynomial example has degree <m+h and, at N distinct evaluation
points, distance at least N-m-h+1 when m+h<=N. It consumes h random field
symbols per independently masked row and changes message rate/encoding work.
This is not the Accepted Circle construction or expander construction. Their
actual mask subspaces and coordinate restrictions need separate proofs; an
ordinary Vandermonde argument cannot admit either one automatically.

## 6. Evidence, literature boundary and required replacement

[Ligero §4.6 and Lemma 4.13](https://acmccs.github.io/papers/p2087-amesA.pdf)
distinguish randomized codeword probes from masks for linear combinations;
its final protocol uses disjoint message/query points and randomized encodings.
Stele cannot inherit that protocol's ZK claim from an appended row alone.
[Jolt's BlindFold description](https://jolt.a16zcrypto.com/how/blindfold.html)
uses commitments to round coefficients and hidden PCS evaluations with another
proof checking their relations. Naming BlindFold does not instantiate those
relations in Stele's hash/code/M31 stack or establish its advertised overhead.
No group-based construction or security assumption is selected here.

Before admission, specify the entire joint view and simulator for private
weights, cuts, multiplicities and final claims; source/range/sumcheck/PCS binding;
exact mask field/distribution, zero coefficients, secret seed derivation and
domain separation; canonical bytes and committed randomized code; transcript
order and soundness/privacy losses; immutable passport/certificate and repeated
opening lifetimes; and all source reads, mask generation, encodings, retained
state and proof costs. The complete workload must meet the existing one-pass
and <=5% overhead requirements with native ledgers, or amend them explicitly.
Masks must not be derivable solely from public transcript data. Determinism for
an equal secret seed does not establish fresh entropy across different proofs;
the exact secret-seed lifecycle and any generator assumption must be explicit.

NC-0604 and NC-0900/0901 need actual protocol consumers after that contract is
accepted. A mask-presence bit, MASK ledger entry or different whole-proof digest
does not by itself prove privacy or nonreuse. This study supplies no NC credit,
profile admission, simulator, production commitment or measured constant.

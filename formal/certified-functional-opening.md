# Candidate certified arbitrary functional openings (Q27 / RFC-0010 A3)

Status: Draft. Question: can a proximity test for one fixed encoded-column oracle
support subsequent arbitrary and batched functionals, without another per-proof
weight pass? Security property: all accepted values refer to the same message
matrix. Cost terms: certification, opening queries and row-vector preparation.
Kill criterion: a false value escapes the stated finite bound, adaptive reuse
invalidates the argument, or a required weight reread is omitted from the cost.
This is an ideal interactive consistency argument, not a production PCS,
knowledge extractor, zero-knowledge protocol or Fiat–Shamir/profile certificate.

RFC-0010 A9 incorporates only §§1-2 and §3's final adaptive-reuse paragraph
for individual openings. The batching/grouping protocols remain Draft.

## 1. One fixed oracle and its certificate

Let Enc be a fixed injective K-linear [N,C,D] code, where D is a proved distance
lower bound. Fix W in K^(R by N), R=2^ell, before the certificate challenges.
Distance between matrices counts columns with any disagreement. Fix
e=floor((D-1)/3), h=e+1. All code/setup hypotheses in tensor-opening.md still apply.

The certificate draws ell independent uniform elements of K and forms the tensor
row functional a in tensor-opening.md's order. The prover fixes t in K^C before
q_c independent uniform column draws with replacement. At every draw c check
Enc(t)[c]=a^T W[:,c]. No scalar functional value is needed for certification.
For R=1 there are no row challenges and the exceptional term is zero.

Theorem 2 of [Diamond–Posen](https://cic.iacr.org/p/1/1/2/pdf), p.10, bounds the
exceptional tensor combinations when W is farther than e columns from the
interleaved code. Together with the query argument in tensor-opening.md, this gives

`Pr[certificate accepts AND W is far] <= epsilon_c`, where
`epsilon_c = 2*ell*h/|K| + ((N-h)/N)^q_c` (capped at one).

The rest of this note is our separate near-matrix/functional argument. It does
not import the paper's full extraction theorem or strengthen its radius.

An actual verifier must bind the certificate to the exact root, code identity,
field, layout, dimensions, oracle interpretation and parameter policy. Cache only
a result produced by that complete verifier, keyed by that entire context. A bool,
caller-supplied receipt or certificate for another root is insufficient. This note
assumes a fixed complete field-valued oracle; partial/missing Merkle leaves and
the actual authenticated certificate/cache interface remain production work.

## 2. Arbitrary functionals after certification

If W is within e columns of an interleaved codeword, its message matrix M* is
unique: two distinct candidate matrices differ in a row codeword of weight at
least D, whereas their distance through W is at most 2e<D. M* depends on W and
the code, not on the certificate transcript or a subsequent opening.

For any a in K^R, including a chosen using the certificate and earlier opening
transcripts, a^T W is within e symbols of Enc(a^T M*). For any u != a^T M*,
linearity, distance and the triangle inequality imply

`dist(Enc(u), a^T W) >= D-e = h_o`.

The opening fixes a,b,v and the entire u before q_o fresh independent uniform
column draws. Check dot(u,b)=v and all q_o equations Enc(u)[c]=a^T W[:,c].
A false v forces u != a^T M*, so its acceptance probability, for a near W and
every fixed pre-query history, is at most

`epsilon_o = ((N-D+e)/N)^q_o`.

This permits fixed, sparse, tensor and sum-of-tensors a; freshness of a is no
longer a premise. Freshness of the column draws and binding u beforehand remain
essential. The smaller miss base is justified by an actual certified-near mode;
it cannot replace the far-matrix miss base of the certificate itself.

## 3. General batches and adaptive reuse

A general batch is an ordered nonempty list (a_s,b_s,v_s) on the same W. When the
b_s differ, it cannot in general be replaced by one rank-one functional. Fix the
complete list before drawing gamma_0=1 and independent uniform gamma_1..gamma_(k-1).
The prover then fixes every unscaled u_s in K^C. Check

`sum_s gamma_s*(dot(u_s,b_s)-v_s)=0`

and, at each of one shared set of q_o fresh columns, check every ordered equation
Enc(u_s)[c]=a_s^T W[:,c]. Do not aggregate those column equations with the same
gamma: the u_s were chosen after gamma, and their discrepancies could cancel.
All u_s, counts and ordered statements must be fixed before the column draws.

If any v_s is wrong for M*, the affine expression obtained with all truthful u_s
vanishes with probability at most 1/|K| for k>1 (zero for k=1). Outside that event,
passing the scalar check requires some incorrect u_s. Choose the first such s
after all u_s are fixed; its disagreement set has size at least D-e. Shared fresh
queries miss the union of all disagreement sets with probability at most
epsilon_o. There is no factor k in this query term. Thus a false batch on a near
W accepts with probability at most 1/|K|+epsilon_o, or epsilon_o for k=1.
Zero gamma values and zero a or b require no retry or special exemption.

Equal b_s also permit a precise grouping optimization. Partition by exact equality
of their canonical K vectors, preserving first occurrence. After the same global
gamma draw, set A_g=sum_(s in g) gamma_s*a_s and V=sum_s gamma_s*v_s. Send one
U_g per group, check sum_g dot(U_g,b_g)=V, and separately check every group equation
Enc(U_g)[c]=A_g^T W[:,c] at the shared fresh queries. The same RLC/first-incorrect-row
proof applies, including zero aggregate rows. This reduces the number of sent and
encoded rows to the number of distinct b vectors; it does not collapse different
b vectors into one functional. Do not aggregate the remaining group equations
after the U_g have been chosen. With one claim, gamma_0=1 preserves the original
a, b and fused row. Canonical descriptor equality is not automatically semantic
vector equality; a native grouping API still needs its complete validated contract.

For a bounded adaptive sequence of openings/batches using this same fixed W,
the probability that the certificate accepts and any later value is false is
at most epsilon_c plus the sum of their epsilon_o and applicable RLC terms.
The near-W query argument holds for each fixed prior history; use a union bound
over the first false acceptance. Do not condition on certificate acceptance and
declare epsilon_c gone: an accepted far oracle is precisely its bad event, and
may support arbitrarily many false values. Replaying the same certificate does
not create independent trials or multiply failure probabilities. New interactive
certificate attempts, including new adaptively chosen roots, each require their
own conditional bound and a union over the allowed attempts. Fiat–Shamir grinding
and cross-session reuse require their actual Q12 composition argument.

## 4. Costs, fused rows and remaining scope

For each ungrouped batch, producing k row vectors costs O(k*R*C) field work,
k*C retained row elements and k encodings. Encoder/Merkle workspace, sampled
columns, source descriptors and certificate/transcript buffers are additional.
A single traversal can accumulate all k vectors; that
does not make its arithmetic cost equal to one functional. Shared columns cost
q_o*R authenticated oracle elements plus q_o*k*R combination work, before any
path reuse/compression. Scalar checks cost O(k*C). No compact proof-size claim.
For g groups, charge O(k*(R+C)) statement/group processing and O(g*R*C) row work,
g encodings, g*C row elements and g*R aggregate coefficients, plus the retained
original statements and encoder/consumer storage. Query combination work becomes
O(q_o*g*R). These are algorithmic bounds, not measured native costs.

A weight certificate belongs to RFC-0011's one-time registration, with its full
row pass/encoding/query costs charged there. For inference, the one-term fused
opening borrows the existing B object as u and must not recompute it. Its prior
certificate changes no B identity or matmul weight-pass rule. Per-proof residual,
multiplicity and auxiliary commitments need their own certification work unless
an Accepted mode provides the fresh-tensor argument; charge all such work in
c_c/T_misc and memory. No additional committed intermediate is introduced here.

This resolves a candidate algebraic route for arbitrary/batched queries. It does
not prove knowledge extraction, bind packed integers or checkpoint data, define
native bytes/unbiased index sampling, or hide the row vectors/columns. The plain
messages reveal data; ZK and Ligerito must supply their separate complete
contracts. A3/E4-03, A1 registry/setup admission, all original NC-0600..0605 and
passport-consumer requirements remain open. No production ledger or proven flag
changes. Conditional exact query counts are not measured performance evidence.

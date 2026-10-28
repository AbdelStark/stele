# Conditional random-tensor opening bound (Q27 / RFC-0010 A3)

Status: Draft. This is a finite interactive consistency/proximity lemma with exact
parameter arithmetic. It is not an implemented PCS, a knowledge extractor, an
arbitrary-functional opening theorem or a Fiat-Shamir/profile certificate.

## 1. Imported theorem and its hypotheses

[Diamond and Posen, Theorem 2](https://cic.iacr.org/p/1/1/2/pdf) applies to any
linear [N,C,D]-code over a finite field and R=2^ell fixed rows. For integer
0<=e<=floor((D-1)/3), if the matrix is farther than e columns from the interleaved
code, then its row combination with coefficients tensor_i(1-r_i,r_i), for
independent uniform r_i, is within e symbols of the code with probability at most
2*ell*(e+1)/|K|. Distance between matrices counts columns with any disagreement,
not the sum or maximum of individual row distances. The source is the published
CIC 1(1) paper, DOI 10.62056/aksdkp10, p.10. No conjectural unique-decoding-radius
extension is used here. Our query/consistency application below is a separate
argument; it is not a claim to implement that paper's full PCS/extraction theorem.

## 2. Fixed statement and order

Use the exact code identity and field selected by [code-identity.md](code-identity.md).
Assume its asserted distance D holds. For v2 this is conditional on the good-setup
event; Circle has its deterministic bound. The map extended to K is linear and
injective. Let W in K^(R by N) be the fixed encoded-column oracle, before any row
challenge. R is exactly a power of two; no implicit padding convention is supplied.
A real commitment consumer must justify this fixed field-valued oracle, including
canonical leaf interpretation and authenticated dimensions, rather than assuming
that a Merkle root alone proves codeword validity.

Draw independent uniform r_0,...,r_(ell-1) in K. For row i, define
`a_i=product_j (r_j if bit_j(i)=1 else 1-r_j)` with low row bit first. The row
ordering is fixed. This coordinate ordering is a permutation of the source's
tensor notation and preserves its uniform distribution over the fixed row list.
For R=1 use a=(1), with no row draw and zero exceptional-combination term.

The prover then fixes u in K^C. The verifier-computable column functional b in K^C,
claimed v and full u are fixed/bound before column queries; check dot(u,b)=v.
Only then sample q independent uniform columns in [0,N), with replacement, and
check `Enc(u)[c]=sum_i a_i*W[i,c]` at each authenticated column. Repeated columns
are allowed. Native draws must come from Transcript, with unbiased column sampling
and registered labels; this research implements neither that schedule nor Merkle
opening verification. Its exact probabilities use ideal fresh verifier randomness.

## 3. Query and near-matrix argument

Set e=floor((D-1)/3), h=e+1 and beta=(N-h)/N. A word farther than e from the
code disagrees with every Enc(u) in at least h positions. Once u is fixed, q fresh
queries miss those positions with probability at most beta^q, even if u was chosen
adaptively after seeing r. In the far-matrix case, the imported theorem adds the
exceptional mass at most 2*ell*h/|K|. For R=1 the oracle is already one word, so
no exceptional event is needed.

If W is within e columns of an interleaved codeword Enc(M*), that M* is unique:
two such matrices would differ in at most 2e<D columns, contradicting code distance
in any differing row. Linearity gives Enc(a^T M*)=a^T Enc(M*). The word a^T W
differs from it in at most e columns for every a. If u!=a^T M*, code distance and
the triangle inequality give at least D-e>=e+1 disagreements between Enc(u) and
a^T W. The same beta^q bound therefore applies, without requiring random a in
this near-matrix case. Since dot(u,b)=v is checked, a false functional value for
M* requires u!=a^T M*.

Thus the probability of accepting a far matrix, or accepting an inconsistent u
for its unique near matrix, is bounded by:

```
epsilon_tensor = 2*ell*(e+1)/|K|
epsilon_query  = ((N-e-1)/N)^q
Pr[bad acceptance] <= min(1, epsilon_tensor + epsilon_query).
```

This is a column-metric statement. It does not show M* equals an external model,
CQIS input, packed integer tensor or separately committed source; those bindings
remain required. If W is base-field valued, any nonbase component of Enc(M*)
vanishes outside at most e columns. Its weight is below D, so it is zero, and
injectivity forces the corresponding message component to zero. This establishes
base-field membership in that case, not integer range, packing or CQIS semantics.

## 4. Exact parameters and boundaries

The research calculator derives N,D and setup loss from the checked code ID,
accepts challenge degrees 4/8 and a nonnegative integer ell, and fixes the miss
target at RFC-0010 §6's 2^-130. It finds the least q>=1 satisfying:

```
2^130 * (N-e-1)^q <= N^q.
```

Only integer powers/comparisons are used. The search is bounded at 16384 draws;
if that is insufficient, return UnsupportedParameters rather than understate q.
All 72 currently supported code sizes meet this search limit. The returned gap
may exceed a profile budget; the helper is not an admission decision. It does not
claim row challenges came from a transcript merely because a caller supplies ell.

| Code/message length | N | e | h | Minimum q |
|---|---:|---:|---:|---:|
| Circle, 1024, rate 1/2 | 2048 | 341 | 342 | 494 |
| Circle, 1024, rate 1/4 | 4096 | 1023 | 1024 | 314 |
| Expander v2, 256 | 512 | 3 | 4 | 11489 |
| Expander v2, 2^30 | 2^31 | 14316557 | 14316558 | 13472 |

These are exact query counts, not runtime/proof-size measurements. Draws are not
necessarily distinct leaves; no canonical leaf-reuse compression is implemented.
At the largest expander size and ell=20, the QM31 tensor term alone exceeds
2^-100. The OM31 setup+tensor+query subtotal is below 2^-128, but this omits FS/H,
other openings/reductions, zero knowledge and the full native statement. It does
not admit either profile. The all-seed setup event is charged once over its
specified entire version/seed universe, not assumed independent at each opening.

## 5. Counterexamples, scope and required continuation

The checker uses repetition [4,1,4] codes over F7/F17 with e=1. A matrix can have
each row within one symbol of a codeword yet be two columns from the interleaved
code. Another matrix has a valid first row and a far second row: the fixed tensor
point r=0 always passes for the first row. Its acceptance probability is one,
above the random-tensor bound. Being public, verifier-computable, or syntactically
a tensor is not sufficient; the required distribution/order must be established.

For one far row (0,1,2,3), fix b=v=0 before queries. Choosing only u to equal the
queried coordinate after seeing that query always passes a one-column repetition
check, defeating beta=1/2.
These are counterexamples to misapplying the lemma, not full Stele forgeries or
production NC credit. The query tests preserve u before sampling in honest cases.

The prototype checks 298 fixed toy matrices, enumerates every tensor point for
each, and computes the worst proposed row chosen before the queries. It independently
enumerates query sequences in small cases and checks exact minima via repeated
multiplication. Finite enumeration supports implementation checks, not the general
proof. It does not test actual Merkle authentication, transcript bytes or controls.

RFC-0010 §2's arbitrary and batched functionals still require a complete mode:
justify their sampling distribution, or supply an actually verified prior proximity
relation and its binding/accounting. This draft does not remove those supported
functionals or silently add a second weight pass. Preserve the fused u=B binding.
E4-03 remains blocked on A3, including native byte/challenge contracts, extraction/
multi-opening semantics and controls. Query work affects verifier/proof bytes;
any extra proximity work must be charged in T_misc/c_c without violating RFC-0007.
No measured constant or production registry/ledger changes here. Q12 stays open.

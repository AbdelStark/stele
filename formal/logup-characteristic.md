# LogUp characteristic, poles and partition obligations (Q31)

Status: Draft, RFC-0008 A2 / RFC-0012 A8. Question: which count and denominator
contract makes the proposed lookup valid at the specified inference sizes?
Kill criterion: an out-of-table value satisfies the claimed rational identity,
or cross multiplication erases a pole. This is an algebra study, not a native
LogUp protocol, complete ZK construction or profile admission.

## 1. Characteristic is not extension size

Let F have prime characteristic p and K be any extension. Put p copies of a
value z outside table T into the selected lookup positions and choose all table
multiplicities zero. As a rational function over K,

`sum_{i=1}^p 1/(X-z) = p/(X-z) = 0`.

This is exactly the table-side zero function, although every lookup is invalid.
At any challenge outside the poles both denominators are nonzero. Enlarging K,
using a second independent challenge pair, or a stronger commitment does not
repair an identity that already holds. QM31 and OM31 both have characteristic
2^31-1. The N≈2^37 example of RFC-0012 §5 therefore exceeds the sufficient count
limit of ordinary LogUp. This is a specification counterexample; stele-lookup
is still a scaffold, and no existing implemented lookup forgery is claimed.

This condition is explicit in Papini–Haböck,
[LogUp-GKR, Proposition 2 and §2 footnote 1](https://www.researchgate.net/publication/373444175_Improving_logarithmic_derivative_lookups_using_GKR)
(author-uploaded September 18, 2023 revision of
[ePrint 2023/1284](https://eprint.iacr.org/2023/1284)):
the total looked-up count is strictly below the characteristic. Their statement
also includes the GKR error. The paper's notation/variant is not automatically
the exact selector/tuple/byte protocol of RFC-0008.

## 2. A sufficient bounded-count lemma

Fix selected source values, table values and table coefficients before the
evaluation challenge. Selectors are authenticated Boolean values. Let the total
selected count N satisfy N<p. For each distinct value z let a_z be its natural
lookup count, b_z the sum of supplied table coefficients at z, and r_z=a_z-b_z.
If a selected z is outside the table, then r_z=a_z is nonzero in K, because
1<=a_z<=N<p. No range assumption on table coefficients is needed for this
membership implication; a separate use as integer counts would need its own proof.

Let U be the union of lookup/table support and D(X)=product_{z in U}(X-z).
The cleared numerator of the difference of the two fractional sums is

`F(X) = sum_{z in U} r_z * product_{y in U, y!=z}(X-y)`.

For a bad z, F(z)=r_z*product_{y!=z}(z-y) is nonzero. Thus F is a nonzero
polynomial of degree at most |U|-1, irrespective of the prover's table
coefficients. Uniform alpha in K hits a nonpole root with probability at most
(|U|-1)/|K| <= (N+|T|-1)/|K|. Pole challenges must reject under the candidate
policy below; no conditioning on secret-dependent resampling is used here.
This lemma is about the fractional identity only, before GKR/PCS/FS/ZK errors.

For a concrete candidate c-column compression
`compress_beta(x)=sum_{j=0}^{c-1} beta^j*x_j`, fix one bad original tuple x.
Each table tuple differs from x, so collision with any table tuple occurs for
at most (c-1)|T| values of beta, by the polynomial root/union bounds. When no
such collision occurs, its compressed lookup count remains in [1,N], even if
other lookup tuples collide with it; it cannot vanish modulo p. With independent
uniform beta then alpha, the identity error is therefore at most

`min(1, ((c-1)|T| + N+|T|-1)/|K|)`.

This explicitly chosen power compression is a candidate, not an interpretation
silently imposed on RFC-0008's unspecified inner-product notation. It names
the compression contribution that a bare (N+|T|)/|K| line can omit. A tighter or
different compression scheme requires its exact theorem and bytes.

## 3. Denominator and padding policy

For fraction pairs (P,Q), the parent is
`(P0*Q1 + P1*Q0, Q0*Q1)`. Its meaning as a rational sum requires Q!=0.
Two leaves (1,0) produce root (0,0); cross multiplication with any other root
then gives zero on both sides. Likewise a masked leaf (0,0) can erase the
whole sum. An equality between cross products alone is insufficient.

The candidate contract uses the neutral pair (0,1) at every inactive/padded
leaf and proves that choice against the actual Boolean selector. Active leaves
remain (1,alpha-compress_beta(x)); table leaves use their fixed coefficient and
table denominator. Require both root denominators nonzero and bind their full
GKR reductions to the original selected leaves/table. In a field, the nonzero
root product enforces every leaf denominator nonzero. A check of a supplied
unbound root proves nothing about original leaves.

An honest pole causes rejection in this candidate, with probability at most
(N+|T|)/|K| per uniform draw before any tighter support bound. Specify the full
attempt/seed/retry policy; silently skipping challenges changes the transcript
and its distribution. Do not label this completeness event as a new arbitrary
soundness allowance or permit a verifier to accept a pole.

## 4. Two candidate directions, neither admitted

Static partitions: fix public source-position partitions with selected capacity
at most p-1, and prove each partition's lookup separately with its own table
multiplicities. All positions must belong to exactly one partition; authenticated
selectors exclude padding. Bound the capacity from public shapes, not runtime
observations. Keep separate equality checks or use a separately analyzed fresh
batching reduction. Summing the partition equations restores the original flaw:
counts p-1 and 1 each give a nonzero invalid residue but add to zero.

An exact 2^37-position domain needs at least 65 partitions of capacity p-1.
A uniform power-of-two capacity 2^30 gives 128 partitions. With 2^16 table slots
per partition, this candidate has 8,388,608 table-multiplicity slots. These are
shape counts, not timings, measured bytes, optimal choices or a performance
claim. Commitment, table evaluation, tree, claim and memory work must all be
charged. The stacked multiplicity layout and its root/claim ownership need an
explicit amendment; partition metadata is not a substitute for proving coverage.

Weighted multiplicities: Eagen–Haböck,
[ePrint 2024/2067](https://eprint.iacr.org/2024/2067), describes units that avoid
vanishing subset sums, including multilinear and bounded-repetition variants
([author-uploaded text](https://www.researchgate.net/publication/387601320_Bypassing_the_characteristic_bound_in_logUp),
§§2–3). This is a substantive alternative to partitioning. It changes numerator
weights, multiplicities and challenge/commitment order; selecting it requires the
exact version, units, field, selector treatment, theorem and complete consumer.
Merely using an extension field while leaving every unit equal to one is not
that protocol. The current study does not implement or admit the weighted mode.

Two independent identity tests can square a fixed-witness identity error only
under their full joint schedule and hypotheses. They do not square an already
zero rational function, cure missing count bounds, or automatically square GKR,
commitment or shared preliminary errors. Account for those events separately.
All original source/table/multiplicity bindings, NC-0400..0405, privacy, degree,
one-pass, native cost and Q12 obligations remain.

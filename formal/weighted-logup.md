# Candidate grouped equality units for LogUp (Q31)

Status: Draft, RFC-0008 A2 / RFC-0012 A8. Question: can bounded repetition of
public units repair the characteristic failure with one table-sized multiplicity
vector per repetition and bounded preparation state? Kill criteria: a fixed bad
source has an identically zero residue polynomial, a challenge-order attack,
incorrect virtual-tree identity or uncharged source/table work. No native mode,
ZK construction, profile or complete inference is admitted by this study.

Eagen–Haböck [2024/2067](https://eprint.iacr.org/2024/2067) motivates polynomial
units and their bounded repetition. The inspected
[author-uploaded version](https://www.researchgate.net/publication/387601320_Bypassing_the_characteristic_bound_in_logUp)
is dated December 17, 2024 (§§2–3); the ePrint page lists a subsequent revision.
Below is a self-contained candidate derivation for Boolean equality units,
public selectors and tuple compression, not an assertion that an unspecified
upstream mode already implements Stele's protocol.

## 1. Fixed source and units

Fix the authenticated ordered source tuples x_i in F^c, public Boolean selectors
sigma_i, unique ordered table tuples T, shapes and padding before any unit
challenge. N=2^m counts the entire padded position domain, across every batched
column/layer in this lookup. Canonical position i has MSB-first bits. Choose a
public b<=min(m,30), B=2^b<p, G=N/B=2^h, h=m-b. Group g=floor(i/B) consists of
contiguous positions; do not count only each layer when a unit spans layers.
The proposed default is b=min(m,30), with any different choice bound by the plan.

For theta in K^h define U_g(theta)=eq(bits(g),theta). Every position in group g
uses that unit. For any fixed nonempty selected-position subset S,

`R_S(Y) = sum_g n_{S,g} * eq(bits(g),Y)`,

where 0<=n_{S,g}<=B<p and at least one count is positive. Evaluation at Boolean
group g returns n_{S,g}; hence R_S is a nonzero multilinear polynomial of total
degree at most h. Uniform independent theta gives Pr[R_S(theta)=0]<=h/|K|.
This remains true when S has at least p members. No division by theta or a unit
is used; zero/one challenge coordinates and zero individual units are allowed.

For honest sources define weighted table entries
`mu_t(theta)=sum_{i: sigma_i=1 and x_i=T_t} U_floor(i/B)(theta)` in K.
They replace ordinary F-valued multiplicities in this candidate. Their exact
K field, repetition identity, table order, padding, commitment layout and final
opening consumers need explicit authenticated descriptors. They are not integer
counts, range-checked base limbs or ZK masks. No lookup-value commitment is added.

## 2. Interactive schedule and single-test bound

For r in {1,2} candidate repetitions:
1. Bind the fixed sources, selectors, table/plan identities, field, m,b,c and r.
2. Draw all r independent vectors theta_j in K^h (r*h unit challenges).
3. Commit all r weighted multiplicity vectors, each allowed to depend on every
   theta_j. Their binding must fix them before every alpha/beta below.
4. Draw independent beta_j then alpha_j per repetition; bind/prove the fraction
   roots and complete source/table/multiplicity consumers for each j.

The existing requirement that multiplicities precede alpha/beta is preserved.
Actual labels, bytes, sampler behavior, transcript frames and admission require
an Accepted contract. This is an ideal interactive argument; no code draws a
new production challenge, and Q12 must justify any Fiat-Shamir composition.

Define z_beta(x)=sum_{k=0}^{c-1} beta^k*x_k. The target identity is
`sum_i sigma_i*U_floor(i/B)(theta)/(X-z_beta(x_i)) = sum_t mu_t/(X-z_beta(T_t))`.
Fix one selected bad tuple x before the challenges. Collision of z_beta(x) with
some table tuple has probability at most (c-1)|T|/|K|. Otherwise its compressed
fiber S_beta among selected source positions is nonempty and disjoint from the
table. Even if other lookup tuples collide with x, each group count is <=B<p.
For each fixed beta, R_S_beta is therefore nonzero of degree at most h.

The raw verifier coins beta and theta are independent even though beta is drawn
after the commitment chosen using theta. Analyze these coins before conditioning
on an adversary's decision to abort. Thus the union of table collision and zero
bad-fiber weight has probability at most u=min(1,(h+(c-1)|T|)/|K|). Outside that union,
the rational difference has a nonzero pole absent from the table, regardless of
the committed mu. Clearing distinct poles gives degree <=N+|T|-1. A fresh uniform
alpha hits a nonpole root with probability at most a=min(1,(N+|T|-1)/|K|). Consequently
the false rational identity test has probability at most

`e = min(1, (h+N+c*|T|-1)/|K|)`.

This excludes all failures of source binding, polynomial evaluation, fraction
reductions, PCS, hashing, FS and privacy. Pole rejection remains mandatory.

## 3. Independent repetitions versus shared units

With all independent theta_j drawn before all mu commitments, the preceding
bad-fiber events E_j depend only on (theta_j,beta_j) and the fixed sources. They
are independent across j and unaffected by joint adaptive choices of mu. Given
all those coins and fixed mu, the alpha_j are independent; outside E_j each
equation has at most the stated number of roots. Therefore

`Pr[all r false identity tests pass] <= (u+(1-u)*a)^r <= e^r`,

using capped u,a when either raw bound exceeds one. This conclusion applies
only to the rational-identity events under this exact schedule. It does not
square shared source/commitment failures or the separate GKR/PCS/FS errors.

Reusing theta does not justify e^2. Already over F_3, group counts (2,1) give
bad residue 2*(1-theta)+theta, which vanishes at theta=2. Every subsequent
nonpole alpha test then agrees with zero table coefficients, however many times
it is repeated. The shared event has probability 1/3, not 1/9. For c-column
compression a sufficient conservative shared-theta bound is
`h/|K| + (c*(N+|T|-1)/|K|)^2`, capped at one: first keep one exact bad-tuple
weight nonzero, then exclude its collisions with all other source/table tuples
in each independent test. A small error bound remains a requirement, not a claim
that this candidate or either field meets the complete treaty budget.

Late choices also break the hypotheses: after theta in F_p, counts
(theta,theta-1 mod p) fit two groups of capacity p-1 and always cancel, while
remaining nonempty. If mu is chosen after alpha, it can fit one evaluated
equation for an invalid value. Sources must precede theta and mu must precede
all denominator challenges, with actual binding rather than metadata assertions.

## 4. Virtual fraction tree and original leaf claims

Keep lookup leaves (sigma_i, 1-sigma_i+sigma_i*(alpha-z_beta(x_i))): inactive
leaves are (0,1). Within each B-position group use the ordinary fraction parent.
At the h levels above those groups use

`P=(1-theta_k)*P0*Q1 + theta_k*P1*Q0; Q=Q0*Q1`.

Bottom-up level l>=b uses k=m-1-l. Induction gives exactly the weighted rational
sum without multiplying every leaf by its unit. The upper G-1 parents add two
K multiplications each in this direct expression. For fixed theta, parent
relations remain degree two in child values; an equality-weighted sumcheck has
individual degree at most three. This is an algebraic degree statement, not an
implemented GKR schedule or its ledger. The table tree is ordinary with mu_t leaves.
Neither tree nor its intermediate values is newly committed.

Both bound root denominators must be nonzero. Every virtual leaf claim must
reach the same original x, public selector and committed mu. In particular,
the MLE of the Boolean denominator expression is not generally the expression
of separately evaluated MLEs. Its selector/source product requires its real
reduction. Do not replace that consumer by an off-Boolean self-comparison.

## 5. Preparation and full costs

For contiguous groups, maintain |T| base-field integer histogram slots and
r*|T| K accumulators. Visit each position once, update its group's count, then
scan all table slots and add count*U_g(theta_j) to each accumulator. Clear the
histogram before the next group. Shared counts prepare both repetitions from
the same logical source visit, including unselected records. All counts are
statically bounded by B; no runtime assumption that they happened not to wrap.

Preparation charges table indexing/validation, N tuple/selector lookups, selected
integer increments, r*G*h K products for the direct unit evaluator, r*G*|T|
base-times-K accumulator updates, and G*|T| histogram clearing. The prototype's
Python dictionary lookup is not a proved constant-cost native table-index scheme.
Retained histogram/accumulator slots exclude source/table/selector storage, index
metadata, point vectors, transient copies, allocator overhead and all proof work.
The prototype retains its supplied source; its virtual tree uses O(N) arrays.

At N=2^37,b=30, G=128 and h=7. Two repetitions require 14 unit coordinates and
2*|T| K multiplicities, rather than 128 independent F multiplicity vectors.
For |T|=2^16 those are 131,072 K slots; their limb cost depends on d=4 or 8.
This compares exact shapes only. It excludes encoding, commitment privacy,
tree/proof/table consumption, source regeneration and full process/device memory.
No native speed, overhead, c_lu fit or one-weight-pass result follows. Preserve
all original E3-07 controls/cost gates, E3-06 consumers and Q12/Q29 obligations.

# Certified exponential candidates (Q25)

Research for Draft RFC-0004 A2, not an Accepted CQIS/table definition. The
reference real function is exp(t/2^F), with integer output units 2^-E. B=14,
F=10,E=12 is an example, not a selected model/score-scale default. Model scale
alignment, fidelity, all other activations, normalization and canonical table
registry/passport bytes remain A2/Q25 obligations.

The analytical starting points are the exponential power series and reciprocal
identity in [NIST DLMF 4.2.19–21](https://dlmf.nist.gov/4.2#iii). Everything below
uses integers and rational intervals; no finite-precision float is an authority
for a rounded table entry.

## 1. Endpoint-safe decomposition and candidate definitions

The initial grid uses integers 7<=B<=15, 0<=F<=30, 0<=E<=14 and split=7.
The [wider-domain continuation](cqis-wide-exp.md) generalizes the explicit split
and product domain, preserving every output below. Set Q=2^E.
For -2^B<=t<=0, set u=-t=128h+l, 0<=l<128. Thus 0<=h<=2^(B-7), and the last
high index is legal only with l=0. The complete domain has 2^B+1 entries.
Parameter/domain/type errors reject; Boolean values are not integer encodings.

Let R(x)=floor(x+1/2) for nonnegative x, including exact half ties. Define
H[h]=R(Q exp(-128h/2^F)) and L[l]=R(Q exp(-l/2^F)). Their lengths are
2^(B-7)+1 and 128. Both contain Q at index zero and lie in [0,Q]. The extra
high endpoint is real data, not padding. The uncorrected product candidate is
P(t)=floor(H[h]L[l]/Q), so P(0)=Q and 0<=P(t)<=Q.

This is an explicit replacement candidate for the underdefined signed-index
formula, not a claim that the old text already chooses these entries. Despite
monotone sub-tables, resetting the low index can make P nonmonotone. The example
has 29 decreases as t increases. All are retained in the evidence.
For example, P(-9216)=1 while P(-9215)=0, although the real exponential increases.

For a canonical correctly rounded candidate, define D(t)=R(Q exp(t/2^F)) and
C(t)=D(t)-P(t). Direct evaluation uses D; decomposed evaluation uses H,L,C and
returns P+C. They agree exactly and D is monotone. The uncorrected P and D are
different functions and cannot share a table identity. A verifier cannot accept
the H/L-only representation under D's identity.

## 2. Certified rounding

For x>=b+1, exp(1)>2 gives the strict enclosure (0,2^-(b+1)); the continuation
uses it without treating the real tail as zero. Otherwise repeatedly halve x
until y=x/2^s<=1/2. Adjacent odd/even alternating
Taylor partial sums bracket exp(-y), since term magnitudes decrease. Set the
dyadic precision p=b+s+4 for requested interval width 2^-b. Continue until the
rational interval width is at most 2^-p, then round its lower/upper endpoints
outwards onto denominator 2^p. The initial width is less than 3*2^-p.

Square each interval s times, flooring the lower squared numerator and ceiling
the upper. Endpoints remain in [0,1]. If the current width is w, the next width
is at most 2w+2*2^-p. Hence the final width is less than
5*2^s*2^-p=(5/16)*2^-b, strictly below 2^-b. At x=0 the exact singleton is used.
The Taylor branch has x<b+1<=257, hence s<=10. The implemented 512-term cap
suffices for the inner width at all b<=256: its last term is smaller than
2^-512, while p<=270. The original x<=32768 path also met this cap with s<=16.

Multiply the enclosure by Q and apply exact R to both endpoints. Equal results
certify the integer entry. Otherwise repeat at b=32,64,128,256; unresolved rounding
rejects `Precision`, never guesses an entry. This is not a uniform separation
theorem for every possible parameter tuple. Production admission would require
successful certification of every configured entry and its bounded verifier.
Stored research certificates contain the first successful b and exact dyadic
endpoints/precision/value; verification recomputes and compares every field.

An independent oracle sums the positive Taylor series for exp(x). After n terms,
the remaining tail is at most a_(n+1)/(1-x/(n+2)) when x/(n+2)<1. Reciprocal
intervals enclose exp(-x). For floor(x)>=E+2, exp(1)>2 proves Q exp(-x)<1/2,
so the oracle certifies zero directly. This oracle uses neither alternating
partial sums nor dyadic squaring. It checks every example D entry as well as
all sub-table entries in the boundary grid.

## 3. Absolute error and correction bounds

Put a=exp(-128h/2^F), b=exp(-l/2^F). Because H,L are nearest integers and
0<=a,b,L/Q<=1,

    |H L/Q - Q a b| = |(H-Qa)L/Q + a(L-Qb)| <= 1.

Flooring subtracts a number in [0,1), so -2<P(t)-Qab<=1. Consequently the
uncorrected absolute error is strictly below 2 integer output units, or 2/Q in
real units. D has absolute error at most 1/2 output unit, or 1/(2Q). Combining
these inequalities gives -3/2<=D-P<5/2, hence C is one of {-1,0,1,2}.
This bound is uniform; the evidence also encloses the example's actual maximum.

The [exact artifact](../research/cqis-tables/exp-candidate.json) retains rational
error bounds, all 27 parameter-case digests and correction counts. In the example,
the correction changes 5,517 of 16,385 entries, including three negative and
thirteen +2 corrections. Decomposed and direct outputs agree on every entry.
Correct rounding is not a model-fidelity result or a serving-scale choice.

## 4. Integer obligations and explicit cost

A future decomposed reduction must enforce t=-u, u=128h+l, the complete u
domain, all three canonical table memberships, and

    H L = Q (Y-C) + r,  0<=r<Q,  Y in [0,Q], C in [-1,2].

H/L index ranges alone do not exclude h=2^(B-7), l>0; a full-domain check is
mandatory. The product has degree two; the other displayed identities are
linear. All ranges need real consumers. With E<=14, H L<=Q^2 and the RHS is
between -2Q and Q^2+2Q-1, strictly within the M31 centered half-bound. Those
static bounds must enter actual RFC-0004 §6 certificates; this note is not their
production verifier. No challenge or lookup error term is silently waived.

Corrected decomposition requires 2^B+1 correction entries in addition to the
high/low tables and three lookup consumers plus the product relation. The
research API rejects corrected construction/evaluation for B>15 before allocation;
the wider product has no such full table. Direct D
requires 2^B+1 entries and one lookup consumer. For B<=15 each full table pads to
at most 2^16 rows. The correction's four values do not eliminate its input-index
binding or turn it into a four-row table. This is not an O(256)-storage repair.
Table generation/storage and verifier evaluation affect c_a/c_lu/T_misc; no
benchmark, fitted constant, extra weight pass or private intermediate commitment
is asserted. Choosing a representation and its authenticated bytes remains part
of the complete A2/registry review.

## 5. Delivery limits

Run `python3 research/cqis-tables/check_exp.py`. The study compares 6,948
sub-table entries with the independent oracle, traverses all 27 candidate
domains and checks every corrected example entry and full-domain error enclosure.
One-value certificate/correction, omitted-row, parameter and out-of-domain
mutations must reject for their stated reasons. These are research checks,
not native NC-0104/0404/0405, lookup membership, static-certificate verification,
canonical table identity, complete CQIS, model fidelity or GPU parity.

# Q23: rational interval certificates for the finite expander schedule

This is the derivation checked by `research/code-provenance/check_expander.py`.
It bounds a uniformly sampled ensemble, not a fixed seed or chosen matrix.
Setup/identity, grinding/reuse, proximity and profile admission remain unresolved.

## Schedule and induction

Let p=2^31-1. Start with a length-64 input/length-128 output base map whose
minimum distance is at least 3. At each n=4^j, j=4..15, encode
`x -> (x,z,zB)`, where `z=E_previous(xA)`, A has dimensions n by n/4 and B
has dimensions n/2 by n/2. The output length is 2n.
Set D=floor(n/25)+1 and D_inner=floor(n/100)+1.

Require A to have nonzero image for every input of weight 1..D-1. Require B
to have image weight at least D-k for every input of weight
D_inner<=k<D. Then each nonzero outer codeword has weight at least D:
the systematic part suffices when wt(x)>=D; otherwise z is nonzero with
wt(z)>=D_inner, and either z alone or z together with zB suffices.

Each graph row independently selects d distinct uniform neighbors. Each edge
entry is then independently uniform in F_p, **including zero**. For an input
support size k, expansion >b, and required image weight t, the exact union bounds
are those in the study. They charge graph failure and conditional entry failure
separately. All arithmetic in the checker is rational/integer.

## Elementary coefficient bound

For positive integers m,k, `(1+k/m)^m <= ((1+1/m)^m)^k < 3^k`.
The first inequality is the binomial theorem; the second follows from
`sum_(j>=0) 1/j! < 3`. Comparing a single binomial coefficient gives
`C(m,k) <= (3m/k)^k`. More generally,
`C(m,s) <= 3^k (m/k)^s`. These require no numerical logarithms or entropy estimates.

For distinct-neighbor sampling, `C(b,d)/C(m,d) <= (b/m)^d` when d<=b;
if d>b, the bad-graph probability is zero. For b=c*k the graph bound is at most
`[3^(c+1) c^(d-c) (n/m) (k/m)^(d-c-1)]^k`.

## A intervals, k>=128

Choose b=2k. Here n/m=4 and k/m<=4/25. For d>=3 the graph bound is at most
`G_A(d)^k`, with `G_A(d)=108*2^(d-2)*(4/25)^(d-3)`.
The entry bound is at most `[3*n/(k*p)]^k`, hence at most `E_A^k`, where
`E_A=3*2^30/(128*p)` over the entire supported schedule.

## B intervals, k>=128

Write n for the outer message size, so B has m=n/2 rows and columns.
Choose t=D-k and b=D+k. Since k>=D_inner>n/100, D<=4k, b<=5k and
`s=t-1=floor(n/25)-k<3k`. Also k/m<=2/25 and 5k<=m/2.
Thus `C(m,b)<=C(m,5k)` and the graph bound is at most `G_B(d)^k`, with
`G_B(d)=729*5^(d-5)*(2/25)^(d-6)` for d>=6.

The conditional entry denominator is p^(2k+2). Bound the input supports by
`150^k`, their nonzero values by p^k, and permitted output supports by
`3^k*50^(3k)` using the elementary bound above. Dropping the extra p^-2 factor
gives `E_B^k`, where `E_B=56,250,000/p`.

## Exact certification and its limit

The checker verifies `0<G_A(10),G_B(17),E_A,E_B<1` and their 128th powers
are at most 2^-288. Therefore each event at every larger support is bounded
by 2^-288. It checks all supports below 128 exactly, raises the degree where
needed, and checks monotonicity by rejecting the preceding degree. It also
compares the interval inequalities to exact combinatorics for every large
support at n=4096. The total event count is computed over all twelve steps;
the union bound is verified to be below 2^-260.

The 288-bit per-event budget leaves arithmetic headroom for RFC-0002's stated
grinding allowance: even multiplying this union by 2^100 stays below 2^-160.
That check is not a theorem composing setup sampling with Fiat-Shamir or a
profile certificate. Q12's FS/H obligations remain unchanged.

These bounds cover only powers of four from 256 through 2^30, with a valid
base map and the stated sampling distribution. They do not certify a PRNG,
a fixed seed, an adversarially selected setup or arbitrary intermediate lengths.
No production encoder or PCS parameter is admitted by this derivation.

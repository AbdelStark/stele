# Strict activation rounding (Q25)

Research candidates for Draft RFC-0004 A2. They specify numerical functions and
certificates; they do not admit a native table, model scale, architecture or
profile. A2/E5-02 still require GeLU variants, total RMSNorm/rsqrt, canonical
registry/passport bytes, scale alignment, production parity/controls and fidelity.

## 1. Closed forms and parameters

Let t be a signed int16, x=t/2^F, Q=2^E, with integer 0<=F<=30 and 0<=E<=14.
The candidate output is signed round-half-away of Q f(x), with rejection unless
it lies in [-32768,32767]. There is no saturation, wrap, hidden rescaling or
clipping of the real function. These fractional-input scales are a study domain,
not a claim to cover every wide-path scale or select any serving defaults.

| Candidate | Reference real function |
|---|---|
| sigmoid | 1/(1+exp(-x)) |
| SiLU | x/(1+exp(-x)) |
| softcap | c tanh(x/c), c>0 |

The SiLU definition follows [Elfwing, Uchibe and Doya](https://arxiv.org/abs/1702.03118).
The softcap form is the one in the [Gemma 2 paper, §2](https://openreview.net/pdf/6c8e3fd1fc8f63c89f22071ab13df828cfe8ecf9.pdf).
The tanh exponential identity follows from [NIST DLMF 4.28.1–4](https://dlmf.nist.gov/4.28).
No fidelity property or paper's model parameters are adopted by this study.

Represent c=m/2^C with integers 1<=m<=65535 and 0<=C<=30, requiring m odd
when C>0. This removes powers-of-two aliases. Non-softcap kinds require both cap
fields zero. Every parameter and input has an exact type; Boolean values reject.
Metadata is the ordered research tuple (kind,F,E,m,C), not a protocol encoding.

A direct table has 65,536 rows, ordered t=-32768,...,32767, with no padding or
omitted endpoints. Generation rejects the entire configuration if any entry
overflows or cannot be certified. A single successful entry does not admit a
configuration. F>=E is a sufficient full-domain SiLU range condition because
|Q SiLU(x)|<=Q|x|<=|t|; F<E is not silently clamped. Softcap and sigmoid have
their own finite bounds, but actual rounded entries must still fit the output.

## 2. Why strict endpoints matter

For F=1,E=0,t=32767, x=32767/2. SiLU(x) is strictly less than x and greater
than 16383: x-SiLU(x)=x exp(-x)/(1+exp(-x))<1/2, using exp(1)>2.
It therefore rounds to 16383, while the exact limit x rounds to 16384.
Setting a small exponential to zero changes the integer function. Merely
increasing precision on a closed interval whose upper endpoint is x does not
resolve the round-away disagreement at this half-integer.

For c=1/2,E=0 and any finite positive x, 0<c tanh(x/c)<1/2, so the output is
zero. Rounding the limiting c gives one. Negative inputs similarly approach
-1/2 from above and round to zero. This is a rounding issue, not underflow
permission or a negligible-error justification.

For a positive rational a, the exponential enclosure is strict on both sides:
L<exp(-a)<U. Alternating Taylor partial sums are strict for nonzero reduced
arguments; outward rounding and monotone squaring preserve strictness. When
a>=b, use 0<exp(-a)<2^-b from exp(1)>2. This handles arbitrarily large
softcap ratios without constructing huge powers or substituting zero. At a=0,
use the exact singleton [1,1]. All arithmetic is rational/integer.

## 3. Enclosure transformations and certified rounding

Write z=exp(-|x|) for sigmoid/SiLU. For x>=0, sigmoid is 1/(1+z); for x<0,
it is z/(1+z). Multiply by x for SiLU, reversing endpoints for negative x.
For softcap, take z=exp(-2|x|/c) and magnitude c(1-z)/(1+z); restore the
sign. Denominators are positive. Each transformed interval at x!=0 is strict
at both endpoints, since these maps are strictly monotone on the interval.
For x=0 the exact value is 1/2 for sigmoid and zero for the other candidates.

Let R be signed half-away rounding. For a strict interval (l,u), determine the
smallest possible rounded value using R(l+) and the largest using R(u-).
At a positive half-integer, R(v-)=R(v)-1; at a negative half-integer,
R(v+)=R(v)+1. All other one-sided values equal R(v). Exact singleton intervals
use ordinary R. Equal extremes certify the entry; unequal extremes trigger
the next precision in b=32,64,128,256, then reject `Precision` if unresolved.
An unproven uniform distance from half-boundaries is never assumed.

The research certificate contains the first successful precision, reduced
rational lower/upper endpoints, strictness and integer output. Verification
recomputes and compares every field and exact type, plus parameters, lengths
and row order. Mutable Python dictionaries are neither authenticated registry
objects nor production acceptance objects. A malformed or stale certificate
cannot select a different numerical rule under these checks.

For every certified entry y, |y-Q f(x)|<=1/2 output unit, equivalently
|y/Q-f(x)|<=1/(2Q) in real units. This includes exact ties and needs no
additional approximation term: intervals certify the exact closed form.
It is an upper bound, not a measured claim that a particular finite table
attains one half. No hi/lo approximation or correction representation is
admitted here; any decomposition must reproduce these same integer entries.

## 4. Independent evidence and cost boundary

Run `python3 research/cqis-tables/check_activations.py`. The independent oracle
uses a positive exponential Taylor series with a geometric tail bound and
reciprocal intervals, rather than alternating series and dyadic squaring.
It selects a candidate by rounding the interval midpoint and checks containment
inside that integer's half-unit cell, retaining open endpoints. The large-ratio
bound derives directly from exp(1)>2. Zero inputs use exact signed half-away.

All entries of three signed-int16 tables are compared (196,608 entries):
sigmoid (F,E)=(8,12), SiLU (8,8), and softcap (8,8,c=30). The test also covers
30,000 seeded inputs with varied scales and cap parameters, parameter/domain
boundaries, positive/negative/zero inputs, exact ties and overflow rejection.
Sigmoid/softcap are monotone; softcap is odd. SiLU is intentionally not asserted
monotone. The [artifact](../research/cqis-tables/activation-candidates.json)
records exact extrema, research little-endian signed-i16 digests and the two
strict-endpoint counterexamples. No performance measurement is claimed.

Certificate value, precision, interval, strictness, metadata and row-shape
mutations reject for their stated reason. These are research checks, not native
NC-0404/0405, lookup membership, authenticated table identity, static field
certificates, Rust/NumPy inference parity or model-fidelity evidence.

Each direct table contains 65,536 signed-i16 outputs (131,072 payload bytes,
before framing/certificates) and requires one membership consumer per use.
Generation, verifier MLE evaluation and registry storage retain their costs in
c_a/c_lu/T_misc. No fitted constant, extra weight pass, random challenge or
new committed intermediate is introduced. Complete A2/registry review must
choose authenticated bytes and range consumers before native implementation.

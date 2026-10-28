# Circle encoder: deterministic interpolation and a distance lower bound

Scope: RFC-0010 A2's linear map only. No PCS proximity, authentication, setup
randomness, Fiat–Shamir or profile theorem is established here.

Let p=2^31-1 and g=(-3/5,4/5) in the group x^2+y^2=1. Multiplication is
`(x,y)*(u,v)=(xu-yv,xv+yu)` over M31. The norm is multiplicative. Exact repeated
squaring checks `g^(2^30)=(-1,0)` and `g^(2^31)=(1,0)`, so g has order 2^31.
These two identities are reproducible in the [study](../research/circle-code/check_circle.py),
not probabilistic order estimates.

For 0<=n<=30, define ordered D_n[j]=g^((2j+1)*2^(30-n)), 0<=j<2^n.
Distinct exponents give distinct points. For n>=1, inverse points have indices
j and 2^n-1-j and equal x/opposite y. No such y is zero: the exponent cannot be
0 or 2^30 modulo 2^31. Their first-half x coordinates pair similarly under
negation. For n>=2 those x coordinates are nonzero; the zero-x order-four points
arise only at the last constant quotient, where no division is performed.
The map `pi(x)=2*x*x-1` sends first-quarter x coordinates to the first-half x
coordinates for D_(n-1), in the same order. This follows by squaring the group
element and its exponent. D_0={(-1,0)} is the explicit constant-only base case.

Define v_1(x)=x, v_(h+1)(x)=2*v_h(x)^2-1. For j with least-significant-first
bits j_h, define `b_j(x,y)=y^j_0 * product_(h>=1) v_h(x)^j_h`. The first 2^n
basis functions do not depend on a larger containing basis. Their even indices
are polynomials in x with distinct degrees 0..2^(n-1)-1 and nonzero leading
coefficients; odd indices are y times those polynomials. Thus the span is
`A(x)+y*B(x)` with deg(A),deg(B)<2^(n-1), of dimension 2^n.

For any pair (x,y),(x,-y), uniquely split values into
`even=(f_plus+f_minus)/2`, `odd=(f_plus-f_minus)/(2*y)`.
For a quotient pair x,-x use the same formulas with x in place of y. The
resulting functions live on pi(x). The identity
`v_(h+1)(x)=v_h(pi(x))` makes each recursive split correspond exactly to separating
even/odd coefficient indices. All divisors above are nonzero. Induction from a
single constant proves that interpolation is the inverse of basis evaluation,
including the factor 1/2 at each level. Evaluation reverses each split by
`even +/- twiddle*odd`. No random challenge or assumption enters this argument.

Given k=2^m row values, interpolation on D_m selects exactly one element of the
k-dimensional FFT span. Zero-padding the coefficients and evaluating on D_n,
n=m+b, b in {1,2}, defines the encoder. Invertibility on D_m proves injectivity;
all operations are linear over M31 and over every extension of M31. In particular
QM31/OM31 row combinations commute with encoding. Input/output domains differ:
this map is not systematic and it must not be interpreted as raw data followed by
parity bytes.

For k>=2, write a nonzero encoded polynomial as A(x)+y*B(x) with degrees <k/2.
Parametrize the circle by x=(1-t^2)/(1+t^2), y=2t/(1+t^2). M31 has no square root
of -1, so the denominator is nonzero for every base-field t. D_n, n>=1, avoids
(-1,0), hence all evaluation points have distinct finite parameters t=y/(1+x).
Multiplication by `(1+t^2)^(k/2)` gives a nonzero polynomial of degree at most k
over the coefficient field. It is nonzero because the parametrization has a
rational inverse; equivalently, 1-x^2 is not a square in K(x), since its two roots
are simple in odd characteristic. The univariate root bound therefore gives at
most k zero evaluations and code distance at least N-k, N=2^n. For k=1 all
nonzero codewords are constant and have distance N. This is a deterministic lower
bound, not an assertion of exact distance at every size.

Do not substitute N-k+1: at k=2,N=4, f=y-y_0, where y_0 is the first D_2
y coordinate, has exactly two zero evaluations. The study checks this example.
Do not interpolate the full total-degree space instead: v_m(x) has degree k/2,
vanishes on all D_m, and is not in the selected FFT span. Adding it preserves the
input evaluations but can change the expanded codeword. The extra dimension must
remain excluded by the canonical basis convention.

The transform uses O(N log N) field operations with base-field twiddles; domain
and twiddle preparation, inversions, allocation and encoding must all be counted.
An O(N) space implementation is possible by reusing butterfly storage; the Python
study's temporary lists are not evidence for a production peak-memory constant.

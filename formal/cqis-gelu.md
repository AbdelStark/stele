# Certified GeLU variants (Q25)

Research for Draft RFC-0004 A2, not native/table/profile admission. Use the
signed-int16 input domain, scales 0<=F<=30 and 0<=E<=14, exact signed half-away,
overflow rejection, row order and certificates from
[strict activation rounding](cqis-activations.md). All 65,536 rows must certify
and fit before a configuration succeeds. Model scale selection remains open.

## 1. Distinct real definitions

With x=t/2^F and Q=2^E, round Q times one of the following functions:

    gelu:      x Phi(x)
    gelu_tanh: x/2 * (1+tanh(sqrt(2/pi)*(x+(8943/200000)*x^3)))

Phi is the standard normal CDF, and 8943/200000 is exactly the decimal
coefficient 0.044715. These are the two distinct definitions in
[Hendrycks and Gimpel, §2](https://arxiv.org/html/1606.08415v5#S2).
The variant is explicit metadata. It is not a backend optimization that can be
silently substituted under the other definition's identity. The sigmoid
approximation in that paper is not an additional candidate here.

Every certified entry has error at most 1/2 output unit relative to its **own**
real function, or 1/(2Q) in real units. The tanh variant's bound is not a claim
of half-unit agreement with exact GeLU. Approximation and model-fidelity costs
of selecting that variant remain separate. The F=E=8 tables differ at 108
entries, by one integer unit each. Their complete example digests are distinct.

## 2. Certifying pi and its square root

Alternating arctangent partial sums give strict rational bounds for positive
arguments below one, using [DLMF 4.24.3](https://dlmf.nist.gov/4.24#E3).
Machin's identity is pi=16 atan(1/5)-4 atan(1/239). For completeness,
tan(2 atan(1/5))=5/12, tan(4 atan(1/5))=120/119 and subtracting atan(1/239)
gives tangent one. The angle is in (0,pi/2), hence equals pi/4.
Subtracting intervals reverses the endpoints of the subtracted term.

For c=1/sqrt(2*pi), use outward dyadic root bounds on the reciprocal pi
interval. For rational N/D>0 and dyadic unit U, integer sqrt gives k with
k²D<=NU²<(k+1)²D; this inequality is checked. Thus k/U and (k+1)/U bracket
the root. Strict underlying pi bounds make the resulting bounds on c strict.
No decimal pi, floating-point square root or guessed constant is used.

## 3. Exact GeLU and Gaussian tails

For a=|x|>0, let q=Phi(-a), so the positive result is a(1-q) and the negative
result is -a q. At x=0 the exact result is zero. For a<8, integrate the
exponential power series (equivalently [DLMF 7.6.1](https://dlmf.nist.gov/7.6#E1)):

    I(a) = integral_0^a exp(-t²/2) dt
         = sum_n (-1)^n a^(2n+1)/(2^n n! (2n+1)),
    q = 1/2 - c I(a).

After n>=a²/2, every subsequent term magnitude decreases. Odd/even partial
sums then enclose I strictly. The known bounds 0<I<a are valid throughout.
Outward interval multiplication with c encloses q. Intersect with the strict
mathematical range 0<q<1/2; this does not round a small q to zero.

For a>=8, bound the tail by replacing 1 with t/a inside the positive integral:

    0 < q < c exp(-a²/2)/a < exp(-a²/2)/(2a).

Certified strict exponential bounds suffice even when the dyadic lower
endpoint becomes zero. The upper endpoint zero is never substituted for q.
Both branches yield strict rational intervals, so one-sided rounding from the
activation study applies at half-unit boundaries. For F=1,E=0,t=32767, both
variants round to 16383, whereas replacing their tails by zero gives 16384.

## 4. Tanh variant

For a>0, set v=sqrt(2/pi)*(a+(8943/200000)*a³). All factors are positive and
sqrt(2/pi)=2c. With z=exp(-2v), (1-tanh(v))/2=z/(1+z). Evaluate the decreasing
exponential at the reversed rational argument endpoints and then the increasing
map z/(1+z). Restore the sign using the same a(1-q), -a q formulas. The factor
in the exponential argument is 4c, not 2c. Strictness survives every map.

The precision schedule is 32,64,128,256 bits; constants and integral intervals
use the stated extra guard bits in the implementation. Series have explicit
512-step caps, and uncertified rounding raises `Precision`. No uniform distance
of all configured outputs from half-boundaries is assumed. Certificates are
recomputed field by field, including the variant, intervals and strictness.

## 5. Independent evidence and remaining obligations

`check_gelu.py` uses pi/4=atan(1/2)+atan(1/3), with tangent (1/2+1/3)/(1-1/6)=1,
and an independent paired arctangent series and integer root bisection. For the
Gaussian integral it uses the positive series

    I(a)=exp(-a²/2)*(a+a³/3+a⁵/15+...),

whose coefficients follow from J'-aJ=1, J(0)=0. Its decreasing successive ratios
give a geometric tail bound. Exponentials use positive-series reciprocals rather
than the generator's alternating series and dyadic squaring. Large tails use the
same explicitly proved integral inequality, not an unacknowledged second theorem.
The oracle rounds a midpoint and independently checks the entire strict interval
against the candidate's half-unit cell.

Both complete example tables (131,072 entries) and 20,000 seeded scale cases
agree. Boundary scales, overflow of entire configurations, strict tail witnesses,
constant-cache type aliases, certificate changes and variant substitutions are
checked. The [artifact](../research/cqis-tables/gelu-candidates.json) records exact
extrema, row digests and differences. Neither function is assumed monotone.

Direct tables retain 65,536 signed-i16 outputs and one membership consumer per
use. No decomposition, benchmark constant, weight pass, challenge or intermediate
commitment changes. These research checks do not satisfy native lookup/identity
controls, bound-certificate verification, Rust/NumPy inference parity or fidelity.
Total RMSNorm/rsqrt, authenticated registry/passport bytes, complete scale
alignment and production delivery remain required; A2/E5-02 stay Draft/blocked.

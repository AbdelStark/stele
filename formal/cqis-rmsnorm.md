# Total RMSNorm candidate (Q25)

Research for Draft RFC-0004 A2, not native/table/profile admission. The real
reference is y_i=g_i x_i/sqrt(mean_j(x_j²)+epsilon): dimension is essential
([RMSNorm, §4](https://arxiv.org/html/1910.07467v1#S4)); epsilon is inside the
root ([explicit form](https://docs.pytorch.org/docs/2.14/generated/torch.nn.RMSNorm.html)).
No host dtype default, epsilon value or serving scale is adopted from these sources.

## 1. Parameters and checked output

Study parameters (d,F,G,E,en,ed) are strict integers: 1<=d<=2^14, 0<=F,G<=30,
0<=E<=14, 1<=en,ed<2^32 and gcd(en,ed)=1. Epsilon=en/ed is strictly positive.
Inputs X_i and gains H_i are signed int16 representing x_i=X_i/2^F and
g_i=H_i/2^G. These gain/scaling choices are explicit proposals, not existing law.
The output Y_i represents y_i in units 2^-E and must fit signed int16. This
is the wide norm output; any subsequent int8 conversion is a separate operation.
All-zero input produces all-zero output. Zero/negative/noncanonical epsilon
rejects; out-of-range output rejects without saturation or wrapping.

Normalization is total on its supported statistic domain. Checked output may
still reject overflow; the algorithm does not pretend every scale/gain choice
admits every row. Static output admission and model-scale selection remain A3
and quantiser obligations. The full native scalar Requant API is not used here:
norm products can exceed int32, and the derived shift can be negative.

## 2. Unique normalization with exact remainder

Set S=sum X_i², N=ed*S+en*d*2^(2F), P=ed*d*2^(2F), so q=N/P is the positive
mean-square-plus-epsilon. Uniformly 2^-32<q<2^33. Choose the unique a in [-23,9]
such that 2^14<=q/4^a<2^16. Compute M=floor(q/4^a) and preserve the remainder:

    a<0:   A=N*4^(-a), D=P;       A=M*D+R, 0<=R<D;
    a>=0:  A=N,        D=P*4^a;   A=M*D+R, 0<=R<D.

M is in [16384,65536). These half-open intervals tile the positive axis because
their ratio is four, so exponent parity causes no hole or ambiguous endpoint.
The integer algorithm starts at floor((bit_length(N)-bit_length(P)-14)/2).
The difference of bit lengths overestimates floor(log2(N/P)) by at most one;
therefore at most one decrement is needed when A<16384D. No logarithm is computed.
The quotient/remainder identity and all ranges determine the same unique pair.

S is recomputed from the entire input row. A proof must separately enforce its
limb sums, epsilon/dimension/scales, exponent and mantissa ranges, the identity,
and the remainder bound. A bit-length hint or witness-only division is insufficient.
The original counterexamples S=0,1,65536,131073 all normalize under this rule.

## 3. Certified rsqrt table and output rounding

Let K=2^21 and J(M)=round_half_away(K/sqrt(M)). The 49,152 rows are ordered by
M=16384,...,65535; J lies in [8192,16384], fits int16 and is nonincreasing.
Padding to 65,536 rows requires canonical bytes and exclusion from membership;
padding is not a valid extra mantissa. The conceptual inverse is J/(K*2^a).

Generate k=floor(sqrt(floor(K²/M))) using integer sqrt, then increment k iff
4K²>=M(2k+1)². A supplied J is independently certified by

    M(2J-1)² <= 4K² < M(2J+1)².

The lower endpoint includes a half-away tie; the upper excludes it. Research
certificates retain both nonnegative lower and strictly positive upper gaps.
No approximate square root or host floating-point rounding is authoritative.

Set T_i=X_i H_i J and e=F+G+21+a-E, where -16<=e<=90. If e<0, Y_i=T_i*2^-e
exactly. Otherwise Y_i=sign(T_i)*floor((|T_i|+h)/2^e), with h=2^(e-1) for e>0
and h=0 for e=0. Apply the int16 range check. All arithmetic precedes range
rejection; no pre-round truncation of products or double rounding is allowed.

## 4. Error accounting

Write q=4^a(M+r), 0<=r<1. Mantissa truncation biases the exact normalized
inverse upward by sqrt(1+r/M)<1+2^-15. Table rounding has relative error
at most sqrt(M)/(2K)<2^-14. Consequently, for inverse I=J/(K*2^a),

    1-2^-14 <= I*sqrt(q) < 1+delta,
    delta=2^-15+2^-14+2^-29=49153/536870912.

Every table row checks the squared endpoints J²M/K² and J²(M+1)/K², so this
bound covers every possible remainder, not just sampled statistics. Also
|x_i|/sqrt(q)<=sqrt(d). Final output error is at most
2^E*(32768/2^G)*ceil(sqrt(d))*delta+1/2 output units, uniformly over admitted
input/gain integers. Normalization, table rounding and final rounding are thus
separate terms. This candidate is not correctly rounded exact real RMSNorm.
The artifact records sampled differences; those samples are not a global error bound.

## 5. Static integer obligations and cost

`bounds(p)` derives every magnitude from shapes/formats/parameters, never runtime
fit. S<=d*2^30; the three signed-byte statistic sums have bounds d*128²,
d*128*255 and d*255², each strictly below M31's centered half-bound. Recomposition
and normalization require wide limbs: conservatively N<2^107, P<2^106,
A<2^153 and D<2^124. |T_i|<=2^44, shifted products can reach the conservative
bound 2^60, and biased right-shift magnitudes are below 2^90. They cannot be
embedded as single M31 equalities or passed to the existing int32 scalar API.

The research base-256 multiplication validator covers up to 20 bytes per input.
For each output column k, sum_(i+j=k) a_i b_j+c_k=z_k+256c_(k+1), with bytes
in [0,256), carries in [0,8192), and both boundary carries zero. The left side
is at most 20*255²+8191=1308691; the right at most 2097151. Both are strictly
below p/2, statically. This validates integer identities, not cryptographic
bindings. Native sign, addition, comparison, shift, range and carry consumers,
their schemas and soundness accounting remain mandatory under A3/INV-5.

The sum is O(d); normalization and one rsqrt lookup are O(1) per row, with
bounded limb work, followed by O(d) output work. No weight-pass change or new
committed intermediate. All limb/lookup work remains in c_a/c_lu/T_misc; no
benchmark or fitted constant is claimed. Authenticated table/parameter bytes,
native controls/parity and model fidelity remain open; A2/E5-02 stay Draft/blocked.

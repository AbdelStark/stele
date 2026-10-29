# Q26 closed RMSNorm arithmetic bounds

Question: which closed static schemas account for every wide integer identity
in Accepted RFC-0021 §2.3, including the exact normalization remainder and both
final shift branches? INV-5 is the security property; c_a/c_lu are the cost terms.
Kill criteria: a supported parameter set exceeds a column side's strict p/2
bound, a valid native row violates the certificate, or coherent altered facts
pass the modeled bindings with a false numerical result.

Bounds must cover all a in [-23,9] and all allowed output shifts using only
the expected parameters (d,F,G,E,en,ed). No witness-selected exponent may tighten
them. Actual source/sign/range/table/branch consumers are still required: this
research under RFC-0004 A3 is not a proof or NC-0109. No new cut or weight pass.

## Static schemas

Let U=d*2^(2F), Smax=d*2^30, Nmax=ed*Smax+en*U and P=ed*U. All are exact
functions of the expected canonical parameters. Use Amax=Nmax*2^46,
Dmax=P*2^18, MDmax=65535*Dmax. The output shift lies in
[F+G-2-E,F+G+30-E], a subset of [-16,90]. Let B be its largest nonnegative
power-of-two divisor, hmax its largest rounding bias, and L its largest
left-shift factor. These bounds cover every permitted normalization exponent.

Eleven fixed radix-256 column schemas use the [nonnegative lemma](LIMBS.md):

| Role | Count | Left magnitude bound | Right magnitude bound |
|---|---:|---:|---:|
| statistic | d | 32768 | 32768 |
| numerator | 2 | max(Smax,U) | max(ed,en) |
| scaled | 1 | Nmax | 2^46 |
| normal_product | 1 | 65535 | Dmax |
| normal_sum | 2 | MDmax | 1 |
| xy | 1 | 32768 | 32768 |
| product | 1 | 2^30 | 16384 |
| bias | 2 | max(2^44,hmax) | 1 |
| quotient_product | 1 | 32768 | B |
| division | 2 | 32768*B | 1 |
| left | 1 | 2^44 | L |

Nmax<2^107, P<2^106, Amax<2^153, Dmax<2^124 and MDmax<2^140, so the
160-bit operand domain suffices. Except for statistic, each count is at most
two with at most twenty byte digits. Its raw coefficient is at most 2,601,000,
carry at most 10,200, and either side at most 2,611,455, strictly below p/2.
Statistic uses the tight leading magnitude digit 128: at d=16384 its largest
side is 1,073,709,311, also strictly below p/2. The implementation rederives
all tighter column bounds and compares every supplied field/type. The signed
source/output relations have sides bounded by 131071 and 65536.

## Relations and required bindings

Each signed-int16 source has a magnitude and canonical input sign. Its offset
relation is `(x+32768)+2*b*mag=32768+mag`; both sides satisfy the small static
bounds above. The statistic sums the same input magnitudes squared. The five
row-wide relations bind S, N=ed*S+en*U, A=N*4^-min(a,0), MD=M*D and A=MD+R,
where D=P*4^max(a,0). Require -23<=a<=9, 16384<=M<=65535 and 0<=R<D.
These intervals select the unique normalization exponent and mantissa, including
S=0; the remainder is preserved. P, U and the factors selected by bounded a
are recomputed from the expected parameters, not accepted as independent facts.

The same J(M) is used for every output element. The plaintext checker evaluates
the accepted integer table formula; an actual proof must bind the configured
public table and prove membership. It cannot replace lookup with witness
generation. Each element binds xy=abs(X)*abs(H) and product=xy*J. Its product
sign is the input-sign XOR when both magnitudes are nonzero, and zero otherwise.
The exact signed sources, canonical zero signs and zero predicates remain
actual range/sign-consumer obligations.

For e<0, bind q=product*2^-e and require unused remainder/scaled-quotient fields
to be zero. For e>=0, bind qd=q*2^e and product+h=qd+r, with 0<=r<2^e.
In both cases q<=32768 and `(y+32768)+2*b*q=32768+q` with y in signed int16.
Negative nonzero products may round to output zero without changing their sign.
Whole-row output overflow rejects. The selected branch and all factor values
are determined by a and the expected parameters; none changes a static bound.

Every column result is checked and bound to its consuming value by canonical
digits, with zero extension only after range/length validation. There is no
wide equality checked merely modulo M31. This is a conditional integer argument:
real source, range, table, branch and shared-claim consumers must enforce each
modeled check. No floating-point arithmetic, new proof acceptance or new cut.

## Reproduction and recommendation

Run `uv run --locked --script research/cqis-bounds/check_norm_bounds.py`.
It builds the native `norm_arithmetic` example, an adapter around the existing
accepted numerical API. All returned wide intermediates and output rows are
compared. NumPy int64 handles only bounded signed products/rounding; an independent
exact-rational oracle enumerates exponent intervals and uses integer bisection
for the root. Static columns match the packed-polynomial/prefix oracle.

The 11,004 rows include at least 10,000 accepted varied inputs, maximum dimension,
zero statistics, parameter extremes and an exact negative shift. There are
10,895 accepted rows and 109 matching overflow rejections. Checksum:
`b53e90c76d4d0e911697bf4507314f563c1a48fbeda5a5ced00beb36f974531b`.
Local attacks alter static fields, substitute observed bounds, preserve a residue
by adding p, regenerate coherent false statistic/normalization/product/quotient
columns, change signs/table entries and violate branch/remainder conditions.
They are research checks, not catalog controls or NC-0105/0109.

Continue Q26 under RFC-0004 A3. This supplies a closed arithmetic schema; canonical
certificate/plan bytes, authenticated sources, actual consumers and native
fallible validation remain open, along with the other operation schemas. Larger
dimensions/chunking still need an amendment. No performance number or cost
constant is changed; full inference/fidelity and private proving are unfinished.

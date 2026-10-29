# Q26 scalar Requant certificate schema

Question: can a closed schema for Accepted RFC-0004 A1 account for its signed
int32 input, positive u16 mantissa, biased magnitude, quotient/remainder and
signed int8/int16 output using statically faithful M31 columns? The security
property is INV-5; cost terms are c_a/c_lu. Kill criteria: any admitted column
side reaches p/2, an in-domain native Requant decision differs, or a one-value
change passes all stated bindings/ranges with a false integer result.

This research is under Draft RFC-0004 A3. It models source authentication and
range consumers as plaintext checks; it is not a proof, native certificate API
or NC-0109. No new commitment, challenge or weight pass is proposed.

## Closed static derivation

The expected Spec has only `(mantissa,shift,bits)`: 1<=mantissa<=65535,
0<=shift<=62, bits in {8,16}. This is the existing native `Requant` domain,
not the wider RMSNorm final shift or candidate checkpoint scale fusion. Source
formats and column counts are fixed by the schema; there is no arbitrary
operator tag, supplied field modulus or caller-selected magnitude bound.
The expected parameters must eventually come from the authenticated plan.

Let V=2^31, H=2^(bits-1), D=2^shift, h=D/2 for nonzero shift and zero otherwise.
Derive A=V*mantissa and Q=min(H,floor((A+h)/D)). Use six fixed radix-256
sum-of-products certificates from [the column lemma](LIMBS.md):

| Relation | Input pairs | Static common left bound | Right bound |
|---|---|---:|---:|
| input_lhs | (U,1),(v,2b) | 2^32-1 | 2 |
| input_rhs | (V,1),(v,1) | V | 1 |
| product | (v,mantissa) | V | mantissa |
| bias | (a,1),(h,1) | max(A,h) | 1 |
| quotient_product | (q,D) | Q | D |
| division | (qd,1),(r,1) | max(QD,D-1) | 1 |

Count is exactly one or two as shown. These parameters depend only on Spec
and the fixed signed-int32 input/full signed-int8 or int16 target formats.
All operand bounds have at most eight radix-256 digits: A<2^47, h<=2^61,
Q*D<=A+h<2^62 and D<=2^62. A conservative coefficient bound is
2*8*255^2=1,040,400. Interior carry caps are at most 4,080 by induction, giving
L<=1,044,480 and R<=1,044,735, both below 2^20 and hence strictly below p/2.
The implementation derives tighter per-column bounds and checks every supplied
certificate field/type against that derivation. No runtime value tightens them.

## Integer equivalence and range consumers

The input is represented by U=acc+V in [0,2^32), with four canonical bytes.
Require b in {0,1}, v in [0,V], and b=0 when v=0. Equality of input_lhs and
input_rhs gives U+2bv=V+v, hence acc=(1-2b)v. The certified product equals
a=v*mantissa in [0,A]. Positive mantissa therefore preserves the sign of the
wide product; a separate committed signed product is unnecessary.

Require q in [0,Q], qd in [0,QD], r in [0,D). Bind quotient_product to qd and
product to a by canonical digits. Equality of bias and division gives
a+h=qD+r, so the quotient and biased remainder are unique. Different-width
results are compared digitwise after zero extension, never as one wide M31
residue. Each column's inputs reuse the same named witness values; actual
consumers must preserve these bindings, not accept independent copies.

Require y in [-H,H), then Uy=y+H lies in [0,2H). The small relation
Uy+2bq=H+q has sides at most 4H-1 and 2H. Both satisfy the strict p/2 bound,
so it enforces y=(1-2b)q. This correctly permits -H and rejects +H. A negative
nonzero input can round to y=0 while b remains one: canonical zero sign applies
to the input magnitude, not the rounded quotient. Output overflow rejects;
the static column certificate does not promise every input fits the target.

Whole-input authentication is indispensable. Valid int32 values 0 and p have
the same M31 residue but different U digits and different Requant outputs for
mantissa=1,shift=31. The plaintext test rejects that substitution. A future
proof must bind the offset digits to the actual source reduction using its
static ranges; accepting only one unbounded M31 source value is insufficient.
Every source/sign/digit/range and inter-column link remains an actual proof
obligation. Witness generation or this exact checker does not supply it.

## Reproduction and result

Run `uv run --locked --script research/cqis-bounds/check_requant.py`.
The script respects Cargo's configured target directory, builds the existing
native arithmetic example offline, and compares every decision. NumPy 2.3.4
uses int64 quotient/remainder arithmetic; the second oracle rounds exact
rationals. Six column certificates per case also match the independent
packed-polynomial/prefix oracle. No floating-point arithmetic is used.

There are 10,000 seeded inputs per target plus 420 endpoint cases: 20,420 total.
4,020 int8 and 5,484 int16 results are accepted; 10,916 overflow decisions reject
identically in Rust and both oracles. Checksum:
`e8e39c8213f439dc1cf70d4277002073a79b727df27a97094454b2f64847f0bd`.
The local attacks cover all supplied certificate fields, boolean/type aliases,
noncanonical zero sign, source residue aliases, changed values/digits, residue-
preserving substitutions, target asymmetry and forbidden remainder r=D.
Coherently regenerated local columns with a false sign, product, quotient or
remainder still reject at their inter-column equality. Target endpoints and
halfway cases at the output boundary are included in native parity. These tests
earn no catalog control credit.

## Recommendation

Continue Q26 with this closed scalar schema as evidence for RFC-0004 A3.
Certificate serialization/identity, authenticated parameter/source derivation,
fallible native validation and actual reduction/range/PCS consumers still need
the complete contract. Signed dot products, residual/scale fusion, RMSNorm's
wide arithmetic and other per-reduction schemas remain required. This does not
complete E5-03, NC-0109, a reference inference pass or private proving. There is
no performance number, fitted cost constant, extra weight pass or new cut.

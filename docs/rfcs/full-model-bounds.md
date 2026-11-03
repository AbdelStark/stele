# RFC-0025 static arithmetic appendix

Status: Draft. Part of [RFC-0025](RFC-0025-full-model-cqis.md), Q26/E5-03b.
Expected parameters come from the independently authenticated Model, Scales and
Registry. All bounds below use exact integers, p=2^31-1 and radix 256. Supplied
records, runtime maxima and self-selected fields never choose expected bounds.
The native proof consumers, complete record-set bytes and remaining families
must close before this appendix can be Accepted.

## 1. Word relations and source obligations

For M>=0 define w(M)=max(1,ceil(bit_length(M)/8)) and
u_i(M)=min(255,floor(M/256^i)). Every nonnegative word v has exactly w(M) bytes,
0<=v<=M, and byte i<=u_i(M). Enforce the whole bound as well as the digit bounds:
the latter alone allow values above M. Every wider source view retains all of
its high bytes; zero extension is a checked relation, not silent truncation.

For each closed role below, a term (n,A,C) means n products with nonnegative
operands bounded by A,C. Terms are fixed by that role's derivation; arbitrary
term lists are not a public certificate API. Let

    Z=sum_terms n*A*C,
    K=max(w(Z), max_terms(w(A)+w(C)-1)),
    t_k=sum_terms n*sum_(i+j=k) u_i(A)*u_j(C),
    carry_0=0, carry_(k+1)=floor((t_k+carry_k)/256) for k<K-1,
    carry_K=0,
    left_k=t_k+carry_k, right_k=u_k(Z)+256*carry_(k+1).

Record every digit cap, both zero boundary carries and every side bound. Reject
unless 2*left_k<p and 2*right_k<p for all columns. Actual consumers enforce the
original operand bytes, whole ranges, all interior carries and final zero. The
integer column argument is RFC-0022 §5: equality modulo p then implies equality
over integers, and radix-weighted summation cancels interior carries. A smaller
semantic result bound remains an additional check, never a replacement for the
role's full digit/source geometry. New roles do not alter RFC-0022's old schemas.

The formula does not automatically certify an unbounded sum. If a family needs
chunked products/sums, its fixed partition, partial ranges and carry consumers
must be specified; a FieldBound failure cannot select an implicit chunk or DPA
path. No bound formula authorizes a new commitment to a virtual tensor.

For signed x in [-A,A], use offset o=x+A, magnitude a and sign s with
`o+2*s*a=A+a`, 0<=o<=2A, 0<=a<=A, s Boolean and s=0 when a=0. The original
source may have a stricter positive endpoint (int16: x<=32767); enforce it.
An offset, sign or magnitude does not authenticate the original source. Source
joins remain mandatory even when a multiplier or an entire product is zero.

## 2. Signed rounding shared by the new affine relations

For a signed numerator U, |U|<=Umax, and the configured positive D, require

    |U|=q*D+r, 0<=r<D, h=[2*r>=D], magnitude=q+h,
    y=(1-2*sign(U))*magnitude, -32768<=y<=32767.

Enforce q<=min(32768,floor(Umax/D)). Its factor-product and sum are separately
bound words, including the q=0 case. The strict remainder has a nonnegative gap
D-r-1. For h=0, D-2r-1>=0; for h=1, 2r-D>=0. These integer inequalities, h's
Boolean range and their common r/D sources establish the exact half-away branch.
All quotient/remainder/rounding/target ranges remain checked when U=0 or D=1.
A negative U may round to y=0; do not require its input sign to become zero.

Use g0=D-2r-1 in branch h=0 and g1=2r-D in branch h=1. The inactive gap is
exactly zero. Both gaps have static bound D-1; the selected branch equality and
nonnegative range, not a free gap witness or branch label, justify the comparison.

For static accounting, r and the strict gap are bounded by D-1, 2r by 2D-2,
qD by min(32768,floor(Umax/D))*D, and the selected comparison gap by D-1.
The output-offset equality `(y+32768)+2*sign(U)*magnitude=32768+magnitude`
has both sources and the complete int16 range. Bounds alone do not enforce any
of these relations. The new operation's actual wide-round consumer must own all
of them; the int32/shift<=62 Requant proof is not a substitute.

## 3. Closed affine-projection record

Parameters: inner dimension d in 1..16384; weight bits b in {4,8}; authenticated
tensor exponent e in [-1099,1024]; maximum of that tensor's public channel
mantissas Mw in 1..65535; source kind wide or gated; source fraction f in 0..30
(wide) or 0..44 (gated); output fraction fo in 0..30; row policy; bias presence
and, if present, fraction fb in 0..30. Absent bias has fb=0 and no bias source.
These fields are derived from the corresponding model operation, never adopted
from a supplied record. Each channel still binds its own original mantissa.

The wide source magnitude is 32768; gated is 2^30. Dynamic scale bound is
ceil(source_magnitude/127), namely 259 or 8454661. Static scale is the explicit
positive configured value, capped at 65535 or 8454661 respectively. Both produce
codes in [-127,127], including all required static-failure and zero-row checks.

Derive the following ordered values:

    W=2^(b-1)-1, S=the policy's scale bound,
    A=127*W*d, P=A*Mw, T=P*S,
    l=e-f+fo, r=fo-fb if biased else 0,
    k=max(0,-l,-r) if biased else max(0,-l), D=2^k,
    L=2^(l+k), B=2^(r+k) if biased else 0,
    Umax=T*L+32768*B.

Require 2A<p. This bound uses enforced symmetric code ranges, not the full signed
int8/int4 endpoints. Original code dot, dot-result range and both source claims
must be consumed before the dot is used as an integer. The scaled product obeys
|acc*m*s|<=T; bias is added before §2's one rounding. A zero dynamic scale still
binds the zero codes/dot and keeps the learned bias.

The ordered nonnegative column roles are:

| Id | Relation role | Fixed terms (n,A,C) |
|---|---|---|
| 1 | magnitude times channel mantissa | (1,A,Mw) |
| 2 | scaled magnitude | (1,P,S) |
| 3 | scaled-product sign left | (1,2T,1), (1,T,2) |
| 4 | scaled-product sign right | (1,T,1), (1,T,1) |
| 5 | aligned offset numerator | (1,2T,L), and (1,65535,B) iff biased |
| 6 | numerator sign left | (1,2Umax,1), (1,Umax,2) |
| 7 | numerator sign right | (1,Umax,1), (1,Umax,1) |
| 8 | quotient product | (1,min(32768,floor(Umax/D)),D) |
| 9 | division sum | (1,min(32768,floor(Umax/D))*D,1), (1,D-1,1) |
| 10 | strict remainder sum | (1,D-1,1), (1,D-1,1), (1,1,1) |
| 11 | doubled remainder | (1,D-1,2) |
| 12 | lower-half comparison | (1,2D-2,1), (1,D-1,1), (1,1,1) |
| 13 | upper-half comparison | (1,D,1), (1,D-1,1) |

The dot sign/magnitude relation has sides bounded by 4A and 2A, both strictly
below p/2 in this dimension domain. Roles 3/4 bind the same product magnitude
to its offset and sign: the dot sign when s>0 and acc!=0, zero otherwise.
The zero test/Boolean branch and its original acc/scale sources are mandatory.
Role 5 uses the signed product's offset `acc*m*s+T` and the original bias offset
`bias+32768`; it equals U+Umax. It must not independently choose a sign or use
a separately rounded matmul output. Roles 6/7 bind its original offset to |U|
and sign(U); roles 8–13 and the small Boolean/output relations implement §2.
The strict remainder sum is r+(D-r-1)+1=D; all high zero slots survive the join.
Role 12 binds 2r+g0+1=D when h=0; role 13 binds D+g1=2r when h=1.

Consumer dependencies: configured signed MatmulW/MatmulA sources and ranges,
row conversion, authenticated scale/gain/bias sources, then wide affine rounding
under E5-03/E6/E7-01, with E7-02's weight phase and E7-09's dynamic attainment.
The acceptance DAG must explicitly include the new biased/wide consumers;
their names are not completion of an existing narrower task.
RFC-0024's standalone centered linear/Requant cut
does not authorize an extended shift, bias source, arbitrary wide operation or
new cut. Those actual protocol consumers need their own Accepted schedules.

## 4. Closed embedding/position record

Token parameters are b_t in {4,8}, e_t in [-1099,1024], M_t in 1..65535; M_t is
the maximum public row mantissa, not a measured code bound. GPT-2 also supplies
the same fields b_p,e_p,M_p for its actual position source. Llama has no position
entry. Output fraction fo is in 0..30. Derive

    A_t=(2^(b_t-1)-1)*M_t, l_t=e_t+fo,
    A_p=(2^(b_p-1)-1)*M_p, l_p=e_p+fo  (when present),
    k=max(0,-l_t,-l_p) or max(0,-l_t) when absent,
    D=2^k, L_t=2^(l_t+k), L_p=2^(l_p+k) when present,
    Umax=A_t*L_t+[position]*A_p*L_p.

The selected original code, mantissa and row indices are obligations, for token
and position independently. The token must be in [0,v), absolute position in
[0,n); a valid different row or learned-position source must not be substituted.
There is one rounding of the aligned sum, with §2's complete relations. No
int16 token rounding occurs before the position addition.

The ordered roles are token-code magnitude times mantissa, then position-code
magnitude times mantissa when present, followed by aligned offset numerator,
numerator sign left/right, quotient product, division sum, strict remainder sum
and doubled remainder, in that order. The first one/two use (1,2^(b-1)-1,M).
Aligned numerator uses (1,2A_t,L_t) and, if present, (1,2A_p,L_p); its operands
are the two original signed products offset by their respective static A values.
Each code's original sign binds the product offset; its magnitude/source sign
relations have side bounds 4A_t/2A_t or 4A_p/2A_p, strictly below p/2. Zero codes
have canonical zero signs; positive mantissas cannot erase those source joins.
The remaining roles are exactly §3 ids 6–13 with this Umax,D. Position absence
removes its role/term; no inactive source or arbitrary zero placeholder is legal.

Here the exponent difference can be 2123. Thus a legal aligned numerator can
exceed 2^2145 even though its final int16 output may reject. The proposed static
record must retain those exact high bits; RFC-0022's u160 is insufficient. A
byte-word implementation can use a 2304-bit bounded arithmetic container for
these closed derivations: every scalar/product is below 2^2150 and every column
has at most 269 operand/result bytes. Intermediate capacity is checked before
shifting; neither truncation nor observed cancellation is a bound certificate.

Consumer dependencies: original input-token and public-position source, both
authenticated physical gathers and row scales, optional tied-head alias, then
wide aligned rounding under E5-03/E6/E7-08. The two functional uses of a tied
token/head must preserve RFC-0007's single physical source pass. This arithmetic
record alone does not supply that source schedule or a private gather proof.

## 5. Canonical records for §§3–4

These new records use ASCII `stele/v0.1/cqis/model-arithmetic`, u32 version 1,
u8 schema (1: affine, 2: embedding), u16 parameter byte length and the parameter
bytes below. They are distinct from RFC-0022's existing version-1 schemas.
All integers are little-endian, with signed i16 shifts/exponents and no padding.

Affine parameters are `u16(d) || u8(b) || i16(e) || u16(Mw) || u8(kind,f,fo)
|| u8(policy) || u32(scale) || u8(biased) || [u8(fb) iff biased=1]`.
kind 0/1 means wide/gated; policy 0/1 means dynamic/static. Dynamic configured
scale is exactly zero; biased is 0/1. There is no unused fb byte for absence.
Embedding parameters are `u32(v,n) || u8(fo,b_t) || i16(e_t) || u16(M_t)
|| u8(position) || [u8(b_p) || i16(e_p) || u16(M_p) iff position=1]`.
v,n have the model's domains; presence is fixed by the family/role at the caller.
The derived token/position index maxima v-1,n-1 are retained as scalar fields.

Next encode u32(p), u8(radix_bits=8), u8(scalar_count), ordered u2304 scalars,
u8(shift_count), ordered i16 shifts, u8(role_count), and ordered role records.
u2304 is exactly 288 bytes, not a field element. Affine scalars are
W,S,A,P,T,D,L,B,Umax,qmax,32768,4A,2A,131071,65536; shifts are l,r,k (r=0 when unbiased).
Embedding scalars are v-1,n-1,A_t,[A_p],D,L_t,[L_p],Umax,qmax,32768,
4A_t,2A_t,[4A_p,2A_p],131071,65536; shifts are l_t,[l_p],k. Bracketed fields exist only
when position is present. Counts/order must match the schema, not supplied tags.

A role contains u8(id), u8(term_count), followed by each term's
u32(n), u2304(A), u2304(C), u16(w(A)), u16(w(C)), left/right u8 cap arrays;
then u2304(Z), u16(K), K result caps as u8, K+1 carry caps as u32, K left-side
bounds as u32 and K right-side bounds as u32. Every high zero and final zero
carry is explicit. Role ids are consecutive from 1 in the specified order.
Each has at most three terms and K<=269. These two complete schemas fit within
128 KiB per record; this is a separate domain/capacity from RFC-0022's 8192 bytes.
Compute exact values with checked arithmetic before any conversion or allocation.

Validation derives the full expected record from independently checked parameters
and compares its exact length and every byte. Supplied schema/parameters/counts/
modulus/radix/caps do not select authority. Unknowns, mismatched valid parameters,
noncanonical encodings, omitted high zeros, truncations and trailing bytes reject.
The complete model collection must authenticate each record's role and expected
parameters; a standalone record does not do that. No production use is admitted
until this entire RFC's acceptance requirements close.

The capacity bound follows from the parameter domains, independently of tests.
For affine, A<2^28, P<2^44, T<2^68, k<=1143, l+k<=1054 and r+k<=1143.
Thus Umax<2^1159, and all sign-side/products are below 2^1161. For embedding,
k<=1099. If k>0 the largest aligned shift is at most max(e)-min(e)<=2123;
otherwise it is at most 1054. Since each A<2^23, Umax<2^2147 and the largest
sign-side bound is below 2^2149. All remaining division/comparison roles are
smaller, so 2304 bits and K<=269 cover both complete schemas.

Each role has at most three terms of count one. Raw columns are at most
3*269*255^2; the carry recurrence is bounded by 3*269*255. Each side is at most
3*269*255*256+255=52681215, whose double is strictly below p. At most sixteen
u2304 scalars, three shifts and thirteen roles are encoded. Even allowing both
operands of every term and the result to have 269 bytes, each role has at most
7159 bytes and the whole frame fewer than 100000 bytes, below the 128 KiB cap.
These are mathematical encoding/workspace bounds, not measured performance.

## 6. LayerNorm and complete-model closure

RFC-0025 §2.3/§2.8 and the checked numerical study already give the LayerNorm
whole-value bounds. Their closed offset/statistic/centered-square/variance/
normalization/affine-output column roles still require explicit expansion here,
with the same original X/S/Q/C/V/gain/bias sources and all 33 exponent branches.
RMSNorm retains RFC-0022 without changing its original bytes or authority.

The complete model additionally requires closed rows for conversion, rotary,
residual, attention score/max/exp/block/global normalization, activation/gated
product, greedy/sample/stop and every source/index/range/branch obligation.
The existing twelve-family numerical collection supplies evidence only; its
scoped membership is not the final collection or proof plan. None of those
families may disappear when the new affine/LN/position relations are added.

Full canonical record/collection bytes, per-operation expansion, resource bounds
and the consumer dependency table remain acceptance items. No ready-made proof
receipt, challenge, loss, profile or committed tensor is introduced by this
appendix. Static derivation is T_misc; actual byte/source/range/rounding work is
charged to T_witness/c_a/c_lu at the consuming reductions. No benchmark is claimed.

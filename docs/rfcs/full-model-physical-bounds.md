# RFC-0025 physical record bounds

Status: Draft. Part of [RFC-0025](RFC-0025-full-model-cqis.md), Q26/E5-03b.
Schema 19 covers canonical physical tensor coordinates, packed payload addresses,
signed codes and matrix scale words. It complements the arithmetic schemas; it
does not authenticate a source or replace the complete Bounds collection.

## 1. Expected parameters and addresses

Parameters are the encoding appendix's exact 21-byte Shape followed by the
physical C_i. Shape derives the mandatory role, ordinal, rank and dimensions.
Model fixes the format and vector fraction; a standalone bound record cannot
select them. Matrices have bits b in {4,8}, parameter zero. Vectors have b=16
and fraction in 0..30. GPT-2's tied head reuses token record zero and its bounds.

For a matrix let R,C be its output/input dimensions. For a vector set R=1 and
C to its length, with inactive row coordinate r=0. Let N=R*C,
L=ceil(N*b/8), and index k=r*C+c, with 0<=r<R, 0<=c<C and 0<=k<N.
The first payload byte is a=floor(k/2) for int4, a=k for int8, or a=2*k
for int16. Int4 has lane l=k mod 2 and enforces 2*a+l=k with l Boolean;
other formats have no lane. The last source byte is a+t, where t=1 for int16
and zero otherwise. Derive A=floor((N-1)*b/8), the maximum first-byte address.

Let S=22+4+byte_length(C_i), the position immediately after the tensor prefix
and framed C_i. Matrix scales occupy 2+2R bytes; vectors have no scales.
The payload begins at H=S+[matrix]*(2+2R)+8, after the exact u64 payload length.
The complete R_i length is H+L. Every payload byte address j in [0,L) maps to
record byte H+j. Record-relative positions must later join the original Artifact
record slice and its authenticated source; equality modulo p is insufficient.
Artifact-global offsets and original source-container transforms remain separate
preparation/consumer obligations, not fields inferred from this record.

For matrices, exponent bytes are at S,S+1. Row r's mantissa bytes are
S+2+2r,S+3+2r. The last mantissa ends at H-9, immediately before the length
field. Both original mantissa bytes and the same shared exponent must reach the
corresponding projection/gather and Scales consumers. A valid different row's
mantissa is not an acceptable replacement.

## 2. Packed and signed source words

Int4 has byte=lo+16*hi with lo,hi in [0,15], and selected word
u=(1-l)*lo+l*hi. There is no row padding. When N is odd, the final high nibble
is zero and is never a real element. The whole k<N check excludes that lane.
Int8 has u equal to its original byte. Int16 has u=lo+256*hi, with both bytes
in [0,255]. Every byte, nibble and lane retains its original source.

Put Q=2^b, h=Q/2, D=h-1 for matrix codes or D=h for vector words, and O=D+h-1.
Use u=z+h*s, 0<=z<h and s Boolean, then u+D=o+Q*s with 0<=o<=O.
The signed value is x=o-D. This retains [-7,7]/[-127,127] for matrices and
[-32768,32767] for vectors, rejecting the excluded -8/-128 matrix codes.
Signed zero has s=0. These source ranges must be proved or established by the
actual dominating source validator, not asserted by a certificate alone.

Matrix mantissas reconstruct from their two original bytes and satisfy m=g+1,
0<=g<=65534. Exponent bytes reconstruct unsigned u_e, with
u_e=z_e+32768*s_e, 0<=z_e<=32767, s_e Boolean, and
u_e+1099=o_e+65536*s_e, 0<=o_e<=2123. Thus e=o_e-1099 lies in [-1099,1024].
These checks do not establish source-dependent quantisation minimality; that
requires the complete original source/conversion relation.

## 3. Closed scalar and column records

Use the [common arithmetic frame](full-model-bounds.md), schema 19, radix 256,
p=2^31-1 and no shifts. The first 17 ordered scalars are

    R,C,N,N-1,L,L-1,A,H,H+L,H+L-1,Q-1,h,D,O,[b=4],[b=16],[b=4 and N odd].

For matrices append these 13 scalars, with M=S+2 and T=M+2(R-1):

    S,S+1,M,T,T+1,H-8,65535,65534,1099,1024,2123,65536,32768.

A pair (A,C) below denotes one term (1,A,C) under the common column derivation.
The first eight roles are:

| Role | Terms and required relation |
|---|---|
| 1 | (R-1,C),(C-1,1): r*C+c=k |
| 2 | int4: (A,2),(1,1), enforcing 2*a+l=k; otherwise (N-1,b/8), enforcing k*(b/8)=a |
| 3 | (A,1),([b=16],1): last source byte a+t |
| 4 | (L-1,1),(H,1): original record address H+j |
| 5 | int4: (15,1),(15,16); int8: (255,1); int16: (255,1),(255,256), reconstructing the complete source byte/word |
| 6 | (h-1,1),(1,h): z+h*s=u |
| 7 | (Q-1,1),(D,1): u+D |
| 8 | (O,1),(1,Q): o+Q*s, equal to role 7 |

Int4 then appends (1,15),(1,15), enforcing (1-l)*lo+l*hi=u. Both Boolean
coefficients must use the same l from role 2. Matrix formats append eight roles:

| Relative role | Terms and required relation |
|---|---|
| 1 | (R-1,2),(M,1): first mantissa address 2*r+M |
| 2 | (T,1),(1,1): second byte of that same mantissa |
| 3 | (255,1),(255,256): m from its original bytes |
| 4 | (65534,1),(1,1): g+1=m |
| 5 | (255,1),(255,256): u_e from its original bytes |
| 6 | (32767,1),(1,32768): z_e+32768*s_e=u_e |
| 7 | (65535,1),(1099,1): u_e+1099 |
| 8 | (2123,1),(1,65536): o_e+65536*s_e, equal to the preceding role |

Every equality retains whole-word bounds, all bytes, carries and final zero.
The common whole-bound and zero-predicate checks apply. Coordinate, source-word,
lane and sign ownership cannot be replaced by a field-congruent value or copied
metadata. Vector absence removes all matrix scale roles and scalar fields.

## 4. Capacity and consumer boundary

N<=2^34 and H+L<2^35 over the complete declared shapes; vector records are
smaller. All scalar/operand words fit five bytes. There are at most 30 scalars,
17 roles and two count-one terms per role, with K<=5. A conservative raw column
bound is 2*5*255^2=650250, an interior carry bound is 2550, and both sides are
at most 653055, strictly below p/2. The complete record is below 36000 bytes.
Capacities follow from domains, not measurements or runtime sparsity.

Model/Scales/Artifact consumers must select these expected parameters and retain
all required physical records. E6 source/view derivation, E7-02's single weight
pass, E7-08 gathers/head, E4/E12-05/E14-02 commitment/passport/hash joins and
actual byte/range consumers remain required. This record supplies their static
arithmetic bounds, not a protocol schedule, ownership handle or proof result.

# RFC-0025 rotary and attention-input bounds

Status: Draft. Part of [RFC-0025](RFC-0025-full-model-cqis.md), Q26/E5-03b.
These records use the [static appendix](full-model-bounds.md) §1's exact words,
columns, whole ranges and zero predicates and §5's frame, with schema ids 7–9.
They retain its fixed p=2^31-1, radix 256, u2304 words and 128 KiB cap. Actual
Model/Scales/Registry and request roles determine all expected parameters and
source identities. A record or coefficient envelope does not authenticate them.

## 1. Schema 7 — rotary application and source indices

Parameters: h in 1..128 heads/groups in this Q or K row; per-head width w with
1<=h*w<=16384; even rotary width r in [2,w]; context n in 1..2^20; layout
0:adjacent or 1:split; source fraction f in 0..30. Absence has no record, not a
record with r=0. Bytes are `u16(h,w,r) || u32(n) || u8(layout,f)` (twelve bytes).
The same original rotation_id supplies coefficients for the expected operation.
There is no research materialization cap on n*r/2 in this semantic domain.

Set H=32768, U=16384, E=floor(sqrt(2*U^2))+1=23171, Nmax=H*E,
T=n*r/2. Ordered scalars are

    h*w,h*r/2,h*(w-r),n-1,r/2-1,h-1,T-1,4*(T-1),4*T-1,
    H,U,E,H*U,Nmax,U,U/2,Nmax+U/2,H,U-1,H*U+U-1,H,2U,
    2*max(n,h*w)-1.

There are no shifts. The three consecutive column roles are

| Role | Terms (count,A,C) |
|---|---|
| coefficient pair index | (1,n-1,r/2), (1,r/2-1,1) |
| coefficient payload byte offset | (1,T-1,4) |
| coefficient payload byte index | (1,4*(T-1),1), (1,3,1) |

They bind idx=position*(r/2)+pair, off=4*idx and byte=off+lane for lane 0..3
in the canonical rotation-data payload after its fixed header. Position and
pair have their original ranges; coefficients C,S are exactly the two i16
values at that source, not a different valid table or position. All coordinates,
header/rotation identity and selected bytes remain source-consumer obligations.
T can reach 2^33 and payload size 2^35 bytes, so these indices cannot generally
be compared as one M31 value. Fixed capacities and all actual allocations must
use checked sufficiently wide integers; native fallible/streaming delivery is
still required. The bound does not claim that those data are materialized here.

For head/group t and pair j, adjacent input coordinates are t*w+2j,t*w+2j+1;
split coordinates are t*w+j,t*w+j+r/2. Channels r..w-1 are copied unchanged.
These row/position/selector comparisons have sides <=2*max(n,h*w)-1. Head
repetition does not change the shared coefficient pair index or source owner.

Exact canonical Q14 generation gives |C|,|S|<=U and |C|+|S|<=E: nearest
rounding contributes at most one to the sum, and |cos|+|sin|<=sqrt(2). Both
coefficient ranges and the coupled envelope concern the actual canonical source;
an arbitrary pair inside this envelope is not the configured rotation.
For original int16 x,y, bind z0=x*C-y*S and z1=x*S+y*C. Each product is bounded
by H*U and each signed sum by Nmax. The coupled envelope is essential: the
loose independent-product sum reaches 2^30 and fails the strict p/2 criterion.

For each original z, let a=abs(z), b=sign(z) with canonical zero, and require
`a+U/2=q*U+rem`, 0<=rem<U, q<=32768, output=(1-2b)*q in signed int16.
This is one exact half-away rounding; positive output 32768 rejects. Both
rounded coordinates and all copied channels retain their original complete row.
The signed numerator/sign identities have each side bounded by Nmax; rounding
sides by Nmax+U/2 and H*U+U-1; output sides by H. Twice every bound is <p.
The common word predicates establish strict remainder and zero branches. The
whole operation rejects on any output overflow, without partial cache update.

All index roles have K<=5, and the 23-scalar, three-role record is below 16000
bytes. Consumer dependencies: E7-04, E6 original head/pair/position and public
coefficient MLE/source/selector joins, canonical generation/registry and the
same complete rotated row at conversion. NC-0106 and native/full-model parity
remain delivery gates. No coefficient generation or public-MLE proof is supplied
by this arithmetic record.

## 2. Schema 8 — scaled QK score

Parameters h,g,w,n satisfy 1<=g<=h<=128, g divides h, h*w<=16384 and
1<=n<=2^20. Fractions fq,fk,F are in 0..30. Each Q/K policy is dynamic=0 with
configured scale zero, or static=1 with scale in 1..65535. Multiplier m is in
1..65535 and exponent e in [-62,30]. Parameter bytes are
`u16(h,g,w) || u32(n) || u8(fq,fk,F,q_policy) || u16(q_scale)
|| u8(k_policy) || u16(k_scale,m) || i8(e)` (22 bytes).

For each policy derive code bound C=127 and scale bounds [0,259] when dynamic;
when static s is configured, derive C=min(127,floor((65536+s)/(2s))) and scale
bounds [s,s]. This is the full int16 source and successful symmetric conversion
bound, not an observed value. The actual complete-row conversion must consume
that input range and policy; a per-head rescale or arbitrary code bound is invalid.
Write the bounds Cq,Ck,sq_min,Sq,sk_min,Sk, then derive

    A=w*Cq*Ck, Pq=A*Sq, Pk=Pq*Sk, Pm=Pk*m,
    shift=e-fq-fk+F, L=2^max(shift,0), D=2^max(-shift,0), bias=floor(D/2),
    Nmax=Pm*L, B=floor((Nmax+bias)/D).

Require B<2^31 before execution, including when actual inputs would be zero.
This retains RFC-0004 A6's static score admissibility; an actual small score
cannot rescue an inadmissible configuration. B is the expected symmetric score
bound consumed by schema 9. It is never independently supplied by the prover.
Require 2*(A+1)<p. All supported shape/policy combinations satisfy this dot bound.

Ordered scalars are

    h-1,g-1,w-1,n-1,h*w,g*w,h/g,Cq,Ck,sq_min,Sq,sk_min,Sk,
    A,A+1,Pq,Pk,Pm,L,D,bias,Nmax,B,B*D,D-1,2B,2*max(n,h*w)-1.

The only shift is shift. The ten consecutive roles are

| Role | Terms (count,A,C) |
|---|---|
| original query scale | (1,A,Sq) |
| original key scale | (1,Pq,Sk) |
| configured multiplier | (1,Pk,m) |
| numerator factor | (1,Pm,L) |
| positive rounding bias | (1,Nmax,1), (1,bias,1) |
| quotient product | (1,B,D) |
| division sum | (1,B*D,1), (1,D-1,1) |
| strict remainder | (1,D-1,1), (1,D-1,1), (1,1,1) |
| signed score left | (1,2B,1), (1,B,2) |
| signed score right | (1,B,1), (1,B,1) |

Head t uses original KV group floor(t/(h/g)); all h/g/width/position views and
coordinate comparisons retain the same request and source owners. Original
Q/K codes have ranges [-Cq,Cq],[-Ck,Ck] and inherited whole-row scales sq,sk.
The original dot z=sum q_k*k_k has |z|<=A. Direct centered-field dot and sign
identities are faithful since 2A<p; canonical zero sign also retains the bounded
gap abs(z)-sign(z), with side bound A+1. Zero scale still requires the original
zero code row and the other complete source; multiplication by zero loses no join.

The first four roles multiply abs(z) by the same sq,sk,m,L to obtain numerator
a. Roles 5–8 bind `a+bias=q*D+rem`, q<=B, 0<=rem<D. Since D is one or an
even power of two, this is exact half-away rounding. Bind signed score y by
`(y+B)+2*sign(z)*q=B+q`, with -B<=y<=B and original offset bytes. A negative
dot can round to zero. Score/output comparisons use full words; coherent values
differing by p must not pass as the same score. Masked scores undergo the same
arithmetic and source checks as unmasked scores.

Static policy restored bounds are <=65535; dynamic bounds are 127*259.
Consequently Pm<2^62, Nmax<2^122, D<=2^122 and B*D<2^153. All column
terms/results are below 2^154 and K<=20. Ten roles and 27 scalars fit below
40000 bytes. Dependencies: E7-06 scaled score, E7-01 conversion, E7-09 dynamic
attainment and E6 GQA/position/whole-row/source joins. This does not instantiate
the actual MatmulA, range, scale or output proof consumers.

## 3. Schema 9 — causal first maximum and exponential index

Parameters: n in 1..2^20, independently derived score bound B in [0,2^31),
selected exp domain bits b in 7..31 and fraction F in 0..30. Bytes are
`u32(n,B) || u8(b,F)` (ten bytes). Set O=2B, U=2^b, delta_max=min(O,U).
Ordered scalars are n-1,O,U,delta_max,1,2n-1,U; there are no shifts. The six
consecutive roles are

| Role | Terms (count,A,C) |
|---|---|
| original maximum offset | (1,O,1) |
| masked source plus difference | (1,O,1), (1,delta_max,1) |
| masked maximum offset | (1,O,1) |
| first-maximum gap | (1,delta_max,1), (1,1,1) |
| complete exponential index | (1,delta_max,1), (1,U,1) |
| masked domain endpoint | (1,U,1) |

The authenticated request supplies real count N<=n. Every real query i in
[0,N) retains every real key j in [0,N), with verifier-owned causal allow_j=[j<=i].
Each query has its own allowed key. Padded query rows are excluded and padded
keys cannot enter lookup or selection. The selected k is an allowed original
index with M=score_k, -B<=M<=B; j/k/i comparisons have sides <=2n-1.
Use original offset words x_j=score_j+B and m=M+B and require

    allow_j*x_j+delta_j=allow_j*m,
    gap_j+allow_j*[j<k]=delta_j,
    delta_j+index_j=allow_j*U,
    0<=delta_j,gap_j<=delta_max, 0<=index_j<=U.

Together with actual attainment these give the first allowed maximum, exact
differences in the entire inclusive exp domain, and index_j=U+score_j-M on
allowed keys. Masked delta/gap/index values are canonically zero. Every role
binds the same allow bit and original score/maximum words. Masking does not
remove the original masked score computation/range/source checks.

The actual selected exp function/representation consumes this whole index and
its original difference. Here index is the ascending signed-domain coordinate;
RFC-0021's product hi/lo split uses delta. In particular b=31 admits index 2^31, and field-only
input/index equality aliases values. The endpoint is not dropped or narrowed;
masked entries have probability zero and no neural exp membership. All hi/lo
splits, table memberships, corrections and recombinations remain required
downstream. No numerical index or table id supplies lookup/source admission.

Every term/result is below 2^33, K<=5; seven scalars and six roles fit below
18000 bytes. Dependencies: E7-06 maximum/mask and source consumers, E3-07/E3-08
actual selected exp/index lookup, and E6 request/padding/causal/public-MLE joins.
No arbitrary sparse key set or self-selected mask replaces the dense targets.

## 4. Capacity and acceptance

All these roles have at most three count-one terms and K<=20. Each column
side is <=3*20*255*256+255=3917055<p/2. At K=20 each role is at most 2428
bytes, establishing the score frame cap; K=5 roles are at most 2143 bytes,
establishing the rotary and maximum caps. These are static capacity bounds,
not benchmark results or claims of full coefficient-table materialization.

Full exp/weighted/block/global normalization, activation/decoding, collection
identity and actual proof-plan closure remain acceptance work. Charge source,
index/range, arithmetic and lookup work to T_witness/c_a/c_lu; generation and
static derivation are T_misc. No challenge, loss, cut, weight-pass change,
native negative-control credit or profile admission is introduced here.

# RFC-0025 RMSNorm bound record

Status: Accepted. This appendix belongs to [RFC-0025](RFC-0025-full-model-cqis.md)
§2.8. Schema 14 integrates the existing RFC-0021 §2.3 RMSNorm requirements
into the [static arithmetic frame](full-model-bounds.md), with radix 256,
p=2^31-1 and unchanged complete word predicates. It changes no RMSNorm
definition, FunctionId, representation, table, epsilon rule or output rounding.

The question is whether the complete original RMSNorm chain fits one closed
record, including the full statistic, the same exponent in every factor and
all source/sign/lookup/division obligations. Reject the proposal if a legal
shape escapes a bound or if an independently selected factor can replace the
original shared exponent. No challenge, cut or performance result is introduced.

## 1. Parameters, factors and static constants

Parameters d,F,G,E,en,ed are precisely RFC-0021 §2.3's: d in 1..16384,
F/G in 0..30, E in 0..14, positive u32 en/ed with gcd(en,ed)=1. Bytes are
u16(d)||u8(F,G,E)||u32(en,ed), exactly thirteen bytes. They come from the
independently expected rmsnorm_q/version 1/mode 3 descriptor and original
input/gain roles. LayerNorm mean subtraction or learned bias cannot substitute.

Let H=32768, O=65535 and derive

    unit=d*2^(2F), Smax=d*H^2, Nmax=ed*Smax+en*unit, P=ed*unit,
    fa_max=2^46, fd_max=2^18, Amax=Nmax*fa_max, Dmax=P*fd_max,
    MDmax=65535*Dmax, XYmax=H^2, Tmax=XYmax*16384,
    emin=F+G-2-E, emax=F+G+30-E,
    Lmax=2^max(-emin,0), Drmax=2^max(emax,0), biasmax=floor(Drmax/2),
    Umax=Tmax*Lmax, biasedmax=Umax+biasmax, qmax=32768, qDmax=qmax*Drmax,
    padded=2^ceil(log2(d)).

At the actual original exponent a in [-23,9], the **joint** tuple is

    fa=2^(2*max(-a,0)), fd=2^(2*max(a,0)),
    e=F+G+21+a-E, L=2^max(-e,0), Dr=2^max(e,0), bias=floor(Dr/2).

All five factors fa,fd,L,Dr,bias derive from the same a. Independent membership
in their separate sets is insufficient. The bounded index is a+23 in 0..32;
33..63 are inactive padding in the existing 64-position selection domain.
Any public factor layout used by E6/E7 must retain that same selection/source
and its actual byte relations. No witness power, arbitrary grid or table digest
can supply its own authority. The actual e equals emin+(a+23), not a separately
chosen shift. Dr=1,bias=0 when e<=0, so the unified rounding below also covers
the exact left shift required when e<0.

The 38 ordered scalars are

    H,O,unit,Smax,Nmax,P,fa_max,fd_max,Amax,Dmax,MDmax,8192,16384,
    XYmax,Tmax,Lmax,Drmax,biasmax,Umax,biasedmax,qmax,qDmax,
    d-1,padded,2d-1,131071,65536,32,33,64,
    16384,65535,49152,65536,49151,524288,524350,3.

The two i16 shifts are emin,emax. Each column term below is (count, operand
maximum, multiplier maximum); scalar constants are not proof-supplied values.

## 2. Complete source, statistic and output roles

Both original X_i and original physical gain H_i are signed int16. For each
source x, retain its same bytes, offset o=x+32768, sign s and magnitude v:
o+2*s*v=32768+v. Require 0<=o<=65535, 0<=v<=32768, Boolean s and canonical
s=0 at v=0. The complete word/zero consumers, including the positive int16
endpoint, are mandatory. Roles 1/2 apply separately to both original sources.

The statistic uses every original X, with S=sum abs(X_i)^2. Then
N=ed*S+en*unit, A=N*fa, D=P*fd, A=M*D+R, R+gap+1=D.
Require 16384<=M<=65535 and R,gap in 0..Dmax-1. These complete identities,
positive N/P/D and the shared tuple fix the unique exponent. S=0 and nonzero
R remain legal; neither zero input nor an output zero erases the gain/source
or normalization obligations.

The exact configured rsqrt_q lookup supplies the same J(M), 8192<=J<=16384.
Let XY=abs(X_i)*abs(H_i), Tmag=XY*J, U=Tmag*L. With the same Dr,bias, require

    U+bias=q*Dr+rem, rem+gap_out+1=Dr,
    0<=q<=32768, 0<=rem,gap_out<=Drmax-1.

q is the rounded magnitude, including exact half-away ties. The original
product sign sT is specified below. Original int16 Y must satisfy
(Y+32768)+2*sT*q=32768+q. A negative product may round to Y=0; its product
sign remains bound. If Y is outside int16, reject the complete operation.
The subsequent int8 row conversion is a separate original consumer.

| Id | Terms | Required result |
|---|---|---|
| 1 | (1,O,1),(1,H,2) | source offset+2*sign*magnitude |
| 2 | (1,H,1),(1,H,1) | H+magnitude, equal to role 1 |
| 3 | (d,H,H) | original S=sum abs(X_i)^2 |
| 4 | (1,Smax,ed),(1,unit,en) | N |
| 5 | (1,Nmax,fa_max) | A=N*fa |
| 6 | (1,P,fd_max) | D=P*fd |
| 7 | (1,65535,Dmax) | M*D |
| 8 | (1,MDmax,1),(1,Dmax-1,1) | M*D+R=A |
| 9 | (1,Dmax-1,1),(1,Dmax-1,1),(1,1,1) | R+gap+1=D |
| 10 | (1,H,H) | XY from the original magnitudes |
| 11 | (1,XYmax,16384) | Tmag=XY*J |
| 12 | (1,Tmax,Lmax) | U |
| 13 | (1,Umax,1),(1,biasmax,1) | U+bias |
| 14 | (1,32768,Drmax) | q*Dr |
| 15 | (1,qDmax,1),(1,Drmax-1,1) | q*Dr+rem, equal to role 13 |
| 16 | (1,Drmax-1,1),(1,Drmax-1,1),(1,1,1) | rem+gap_out+1=Dr |
| 17 | (1,O,1),(1,H,2) | output offset+2*sT*q |
| 18 | (1,H,1),(1,H,1) | H+q, equal to role 17 |
| 19 | (1,49151,1),(1,16384,1) | original rsqrt row+16384=M |
| 20 | (1,32,1) | original a+23 index |
| 21 | (1,65535,8) | off=8*table row |
| 22 | (1,524280,1),(1,7,1),(1,62,1) | absolute canonical table byte address |
| 23 | (1,1,1) | bit=sX*sH |
| 24 | (1,1,1),(1,1,1) | sX+sH |
| 25 | (1,1,1),(1,1,2) | xor+2*bit, equal to role 24 |
| 26 | (1,1,1) | sT=xor*(1-zero(XY)) |

In roles 23–26 all bits are Boolean and zero(XY) is the complete-word zero
predicate on that same product. Thus sT is canonical even if one original
source is zero and the other negative. Since J>0, XY=0 iff Tmag=0. An arbitrary
zero flag, product sign or second copy of either source is insufficient.

## 3. Lookup, padding and full-domain bounds

The rsqrt table has N=49152 real rows, L=65536 padded rows and two i32 columns.
Its canonical header is 62 bytes under RFC-0021 §4; payload/total sizes are
524288/524350 bytes. A real query's row is M-16384<=49151. Role 22 uses
address=62+off+lane, lane=4*column+byte with column in {0,1} and byte in 0..3.
All regenerated padding bytes remain zero, but rows 49152..65535 are never
valid mantissas. Original M, row, J, FunctionId/RepresentationId and canonical
table columns must join at the actual lookup; a correct range or digest is not
membership. This record leaves RFC-0021's exact isqrt definition unchanged.

For operation coordinates d..padded-1, original input/gain/output words and
their magnitudes/signs/products are zero, and original source selectors are
inactive. Their signed offsets are 32768. The statistic counts exactly d real
positions. The row-wide M/J and joint factor selection are shared values,
not additional padded function queries. Padding cannot add another statistic
term or authorize a real source/lookup at an inactive coordinate.

Static bounds give Nmax<2^107, P<2^106, Amax<2^153, Dmax<2^124 and
MDmax<2^140. XYmax=2^30, Tmax=2^44, Lmax<=2^16, Drmax<=2^90,
Umax<=2^60, biasedmax<2^90 and qDmax<=2^105. Every column count is at most
20. Role 3 is exactly RFC-0022's full squared statistic, whose maximum side
is 1073709311<p/2 at d=16384. Every other role has at most three count-one
terms and side <=3*20*255*256+255=3917055<p/2. The independent Boolean,
source, index and selector side bounds are also strictly faithful in M31.

With 38 u2304 scalars, two shifts and 26 roles, at most 2428 bytes per role
gives a record smaller than 76000 bytes, within the unchanged 128-KiB cap.
These are domain-wide analytic limits; observed record sizes do not set them.
The actual full-statistic/native source and lookup consumers remain required
under E3/E6/E7-03/E8, alongside the separate LayerNorm dependency. Existing
conditional proof capacities, revealed intermediate roots or metadata do not
complete those tasks or grant a new cut. Derivation is T_misc; actual work
retains T_witness/c_a/c_lu and the original online weight pass count.

# RFC-0025 weighted attention bounds

Status: Draft. This appendix belongs to [RFC-0025](RFC-0025-full-model-cqis.md)
§2.8. It uses the complete [word predicates and frame](full-model-bounds.md),
with fixed radix **16** (header radix_bits=4) for schemas 12/13. Schemas 1–11
retain radix 256 and unchanged bytes. Source bytes split as byte=lo+16*hi,
0<=lo,hi<=15, with side at most 255. Every nibble is joined to that same
original byte; a second unbound representation is not a source. Whole-word
ranges, zero predicates, widths and final-zero carries remain mandatory.

The question is whether complete dense weighted attention, fixed absolute
blocks and variable normalization admit static records at context 2^20. Reject
the proposal if any permitted shape escapes the column/capacity bounds or loses
a source, block, sign or divisor join. No challenge, cut or performance result
is introduced. These records do not instantiate actual proof consumers.

## 1. Parameters and statically derived constants

Weighted parameters are h,g,w,n,f,E,policy,scale,mode,drop. Require 1<=h<=128,
1<=g<=h, g divides h, 1<=w<=floor(16384/h), 1<=n<=2^20, 0<=f<=30,
0<=E<=14. Policy is 0 (dynamic, configured scale zero) or 1 (static scale
1..65535). Mode is 0 (exact, drop=0) or 1 (block1024, 0<=drop<=62).
Bytes are u16(h,g,w)||u32(n)||u8(f,E,policy)||u16(scale)||u8(mode,drop),
exactly 17 bytes. f is the original V projection's fraction, E the selected
exp output's fraction. The complete model supplies those expectations.

Dynamic policy has C=127, smin=0, smax=259. Static policy has
C=min(127,floor((65536+scale)/(2*scale))) and smin=smax=scale. Put

    S=C*smax, Q=2^E, m=(n for exact, 1024 for block),
    Zlocal=m*Q, H=Zlocal*S, Zmax=n*Q,
    b=(0 for exact, ceil(n/1024) for block), Dblock=2^drop,
    bias=floor(Dblock/2), B=(0 for exact, floor((H+bias)/Dblock)),
    G=(H for exact, b*B).

Require B<=32767 before execution. In block mode H uses **1024 even if n<1024**,
preserving RFC-0004 A6's full-block admission rule. Actual zeros or a short
request never rescue an inadmissible drop. S<=65535: for static scale,
C*scale<=32768+scale/2<=65535.5 and the product is integral; dynamic S=32893.
No observed maximum chooses these bounds.

An actual request has N<=n real keys and query i<N. All original real V rows,
including masked keys j>i, retain their complete int16-to-int8 producer, scale,
units and physical coordinates. Query head t uses KV group floor(t/(h/g))
and original row coordinate group*w+channel. Real scales lie in smin..smax;
dynamic scale zero forces the complete original row/codes zero. Inactive
source padding has zero codes/scales. No per-head conversion or compacted key
list replaces the original g*w row and absolute j.

P_j is the exact selected exp output at that same query/key, 0<=P_j<=Q,
zero when masked/padded. At an allowed attained maximum it equals Q, so the
same full sum Z satisfies Q<=Z<=Zmax. A supplied nonzero flag or arbitrary
in-range P_j vector does not discharge that source obligation.

## 2. Schema 12: weighted sums, blocks and global source

The 28 scalars, in order, are

    h-1,g-1,w-1,n-1,h*w,g*w,h/g,C,smin,smax,S,2S,Q,m,Zlocal,H,2H,
    Zmax,b,(b-1 if block else 0),Dblock,bias,B,B*Dblock,Dblock-1,G,2G,
    2*max(n,h*w,1024*b)-1.

There are no shifts. A term below is (count, operand maximum, multiplier
maximum) in the fixed radix-16 column algorithm. It is the arithmetic appendix's
algorithm with 15/16/4 replacing 255/256/8; fixed u2304 words and u32 carry/side
fields are unchanged. Counts come from parameters, never observed nonzero terms.

For every original V code v and scale s, a=abs(v)*s and offset=S+s*v.
Let sv be the original code's canonical sign; require
offset+2*sv*a=S+a, 0<=offset<=2S. Source scale/code checks survive P_j=0.
For each complete m-slot local sum, define Zlocal_actual=sum P_j,
base=S*Zlocal_actual, A=sum P_j*offset_j and signed raw total T=A-base.
Canonical raw sign r and magnitude M satisfy A+2*r*M=base+M and gap+r=M.
All these are complete words; gap>=0 forces r=0 when M=0. Roles 1–3 repeat
at every original source coordinate and roles 4–9 at every sum coordinate:

| Id | Terms | Required result |
|---|---|---|
| 1 | (1,C,smax) | a=abs(v)*s |
| 2 | (1,2S,1),(1,S,2) | offset+2*sv*a |
| 3 | (1,S,1),(1,S,1) | S+a, equal to role 2 |
| 4 | (m,Q,1) | Zlocal_actual |
| 5 | (1,Zlocal,S) | base from the same actual probability sum |
| 6 | (m,Q,2S) | A from the same P_j and original offsets |
| 7 | (1,2H,1),(1,H,2) | A+2*r*M |
| 8 | (1,H,1),(1,H,1) | base+M, equal to role 7 |
| 9 | (1,H,1),(1,1,1) | gap+r=M |

Exact mode has these nine roles only, with n original slots. It returns this
same Z, T, M, r. In particular base is S*Z, **not** the static H=n*Q*S.
Replacing it with H changes zero/masked sums. Every unused slot N..n-1 has
zero source/probability words and offset S; it is not a real V lookup.

Block mode uses all b absolute blocks, with slots j=1024*block+local, local
in 0..1023. Slots j>=N have zero probability/source words and offset S.
The last partial capacity block is padded to 1024. For every block, using its
same raw M,r, require M+bias=q*Dblock+rem, 0<=q<=B, 0<=rem<Dblock,
rem+gap+1=Dblock. The signed rounded result is Rblock=(1-2*r)*q, with
offset Oblock=B+Rblock in 0..2B. Raw negative values may round to zero;
their raw sign is retained, while the later global sign is canonical anew.

| Id | Terms | Required result |
|---|---|---|
| 10 | (1,H,1),(1,bias,1) | M+bias |
| 11 | (1,B,Dblock) | q*Dblock |
| 12 | (1,B*Dblock,1),(1,Dblock-1,1) | q*Dblock+rem, equal to role 10 |
| 13 | (1,Dblock-1,1),(1,Dblock-1,1),(1,1,1) | rem+gap+1=Dblock |
| 14 | (1,2B,1),(1,B,2) | Oblock+2*r*q |
| 15 | (1,B,1),(1,B,1) | B+q, equal to role 14 |
| 16 | (b,2B,1) | Oglobal=sum Oblock=G+Tglobal |
| 17 | (b,Zlocal,1) | Z=sum original block probability sums, also bounded by Zmax |
| 18 | (1,2G,1),(1,G,2) | Oglobal+2*rglobal*Mglobal |
| 19 | (1,G,1),(1,G,1) | G+Mglobal, equal to role 18 |
| 20 | (1,G,1),(1,1,1) | gap+rglobal=Mglobal |
| 21 | (1,b-1,1024),(1,1023,1) | absolute j=1024*block+local |

Every block, including a zero block, reaches roles 16/17. B=0 is legal: it
forces rounded/global totals zero, but does not discard raw products, scales,
signs, probabilities, remainders or source checks. All b block ids are derived;
the prover cannot supply a subset or a runtime-dependent block count. The
global probability sum's tighter Zmax range and its positive source chain are
separate from role 17's possibly larger endpoint sum bound.

## 3. Schema 13: variable normalization

Parameters are the exact 17 weighted bytes followed by u8(fo), fo in 0..30.
They refer to the same weighted operation, not independently chosen metadata.
Consume its actual canonical signed total T, magnitude M, sign r and Z. Set

    e=fo-f+drop, L=2^max(e,0), R=2^max(-e,0),
    Umax=G*L, Dmin=Q*R, Dmax=Zmax*R,
    qmax=min(32768,floor(Umax/Dmin)).

The 21 scalars are G,2G,Q,Zmax,L,R,Umax,Dmin,Dmax,qmax,qmax*Dmax,Dmax-1,
2Dmax-2,32768,65535,131071,65536,h*w,h*w-1,g*w,2*max(n,h*w)-1.
The sole signed shift is e. Actual U=M*L, D=Z*R are joined to those original
sources, with Dmin<=D<=Dmax. Dividing Umax by Dmax would incorrectly bound
the quotient for smaller actual divisors and is forbidden.

Require U=qD+rem, rem+gap+1=D, q<=qmax, rem,gap<=Dmax-1. Boolean half
satisfies half=[2rem>=D]: when half=0, 2rem+g0+1=D; when half=1,
2rem=D+g1. Require g0,g1 in 0..Dmax-1 and the inactive gap zero. Gate the
complete column equalities by that same Boolean; no independent branch or
unbound remainder is allowed. Then mag=q+half<=32768 and int16 Y obeys
(Y+32768)+2*r*mag=32768+mag. Y may be zero for a negative original T.

| Id | Terms | Required result |
|---|---|---|
| 1 | (1,G,L) | U |
| 2 | (1,Zmax,R) | D |
| 3 | (1,qmax,Dmax) | qD |
| 4 | (1,qmax*Dmax,1),(1,Dmax-1,1) | qD+rem=U |
| 5 | (1,Dmax-1,1),(1,Dmax-1,1),(1,1,1) | rem+gap+1=D |
| 6 | (1,Dmax-1,2) | 2rem |
| 7 | (1,2Dmax-2,1),(1,Dmax-1,1),(1,1,1) | selected lower-half side |
| 8 | (1,Dmax,1),(1,Dmax-1,1) | selected upper-half side |
| 9 | (1,qmax,1),(1,1,1) | mag=q+half |
| 10 | (1,65535,1),(1,32768,2) | output offset+2*r*mag |
| 11 | (1,32768,1),(1,32768,1) | 32768+mag, equal to role 10 |

Output range failure rejects the complete operation. Every original head/channel
result assembles in head order before the one whole-row conversion for O.
Static f/fo/E parameters alone do not authenticate those units or row views.

## 4. Full-domain bounds and consumers

For role 6, Q<=2^14 has nibble caps (15,15,15,4), and 2S<=131070 has
(15,15,15,15,1). Their largest convolution coefficient is 735. For any
m<=2^20, raw column<=735m, carry<=49m and either field side<=784m+15
<=822083599<p/2. Probability sums have sides<=16m+15; the other multi-term
accumulations have count b<=1024 and multiply by one. No chunking or smaller
context limit is needed. Each remaining role has at most three count-one terms.

Weighted H<2^50, block H<2^40, B*Dblock<=H+bias<2^62 and G<2^25 in
block mode. All schema-12 operand/result words are <2^64, so widths<=16
nibbles and convolution count<=31 (using the looser limit 33 also suffices).
Count-one sides are <=23775 under that looser limit. With 28 scalars and at
most 21 roles, encoding is <64000 bytes using at most 17 nibbles per operand
and 33 columns. Source/index fields and inactive zeros remain explicit.

For normalization, L<=2^92, R<=2^30, Dmax<=2^64; Umax<2^80 in exact
mode and <2^117 in block mode. Every nonzero product in its roles is <2^119,
so operand widths<=30 and convolution count<=31, including zero-product
cases with retained factor widths. Count-one field sides are <=22335<p/2.
With 21 scalars and eleven roles, encoding is <36000 bytes. Both schemas
fit the unchanged 128-KiB frame cap. Whole-word/nibble range joins and final
zero carries prevent congruent alternative integers from passing.

E7-06/07 must consume these exact probability/value/block/normalization chains;
E7-09 supplies original row conversion, E3 supplies range/lookup consumers,
and E6/E8 supply masks, absolute positions, owned sources and head assembly.
Every edge retains its original point and privacy obligations. The complete
collection must expand all heads/channels/blocks and preserve RMS and the other
original families. Derivation is T_misc, actual work T_witness/c_a/c_lu; no
benchmark constant, online weight pass, native control or proof credit changes.

# RFC-0025 row and residual flow bounds

Status: Accepted. Part of [RFC-0025](RFC-0025-full-model-cqis.md), Q26/E5-03b.
These closed records use the [static appendix](full-model-bounds.md) §1's exact
radix-256 columns, whole ranges, signs, zero predicates and original-source
obligations, and §5's canonical frame. They introduce schema ids 4, 5 and 6
under the same prefix/version, with u2304 scalar/operand words and 128 KiB cap.
Independently expected Model/Scales/Registry roles select all parameters.
They do not add native proof consumers, advice cuts or protocol admission.

## 1. Schema 4 — complete row conversion

Parameters: row dimension d in 1..16384, kind 0 (wide int16) or 1 (gated
product), fraction f in 0..30 or 0..44 respectively, policy 0 (dynamic) or 1
(static), and configured scale. Parameter bytes are
`u16(d) || u8(kind,f,policy) || u32(scale)`, exactly nine bytes. Dynamic scale
is zero in configuration. Static scale is in 1..65535 for kind 0 or
1..8454661 for kind 1. The incoming source and complete row shape must match
the original operation; kind 1 is not a general int32 converter.

Derive H=32768 for wide or 2^30 for gated; positive endpoint H-1 for wide or
H for gated; offset maximum O=H+positive_endpoint. Let S be ceil(H/127) in
dynamic mode, otherwise the configured scale. Ordered scalars are

    H,positive_endpoint,O,S,S-1,d-1,127,254S,2S-1,
    4S-1,2S,254,127,508,254,2d-1,[126 iff dynamic].

There are no shift fields. The source fraction is an identity parameter even
though it does not change the integer conversion. Dynamic mode has these three
roles first; static mode omits them entirely, including their witness fields:

| Role | Terms (n,A,C) |
|---|---|
| scale ceiling product | (1,S,127) |
| maximum plus ceiling slack | (1,H,1), (1,126,1) |
| first attained maximum | (1,H,1), (1,H,1), (1,1,1) |

Both modes then append these five roles, with consecutive ids starting at one:

| Role | Terms (n,A,C) |
|---|---|
| original input sign left | (1,O,1), (1,H,2) |
| original input sign right | (1,H,1), (1,H,1) |
| doubled magnitude plus scale | (1,H,2), (1,S,1) |
| doubled quotient product | (1,127,2S) |
| division sum | (1,254S,1), (1,2S-1,1) |

For each original source x_i, let a_i=abs(x_i), b_i=sign(x_i), with canonical
zero sign and the original stricter positive endpoint. The sign roles enforce
`(x_i+H)+2*b_i*a_i=H+a_i`. In dynamic mode bind M and selected index j by

    0<=j<d, a_j=M, a_i+gap_i+[i<j]=M for every original index i,
    0<=gap_i<=H, M+slack=127*s, 0<=slack<=126, 0<=M<=H.

The original coordinates and comparison [i<j] have actual bounded consumers,
with sides <=2d-1. Thus j is the first attained maximum; a later tied index
cannot be substituted. The all-zero row requires j=0, M=0 and slack=0.
Static mode binds s to the configured positive value and has no maximum,
selected-index, gap or slack witness. It cannot silently choose a dynamic scale.

Both modes bind Boolean n and predecessor t by
`s=n*(t+1)`, `0<=t<=S-1`, `(1-n)*t=0`. This fixes n=[s>0]. For each source
the exact rounding and zero branch are the following uniform relations:

    2*a_i+s=2*q_i*s+r_i,
    r_i+g_i+n=2*s, 0<=r_i,g_i<=2S-1,
    q_i+z_i=127*n, 0<=q_i,z_i<=127,
    (code_i+127)+2*b_i*q_i=127+q_i, -127<=code_i<=127.

For n=1 this is q_i=floor((2*a_i+s)/(2*s)), with r_i<2s: exact half-away
rounding. For n=0 the equalities force a_i=q_i=r_i=g_i=z_i=0, with no division
by zero. A nonzero negative source may round to code zero; its source sign
does not change. Any unrepresentable static result rejects the complete row.

The product 2s and scale/zero/output equalities have small integer side bounds:
S, 2S, (4S-1,2S) for the remainder, (254,127) for zero code and (508,254) for
output. Require twice each bound below p; this holds through S=8454661. All
operands, including 2s in the quotient role, bind the same original scale.
All wide terms/results are below 2^33 and K<=5. The eight-role frame is below
25000 bytes. Consumer dependencies are E7-09's attained maximum, E7-01's
conversion and E6's original complete-row/scale views, including the new gated
static range. The old research u16 scale frame cannot encode this full domain.

## 2. Schema 5 — one-round residual alignment

Parameters d in 1..16384 and fx,fy,fo in 0..30 have bytes
`u16(d) || u8(fx,fy,fo)`. Let c=max(fx,fy,fo), L=2^(c-fx), R=2^(c-fy),
D=2^(c-fo), H=32768 and Umax=H*(L+R). Ordered scalars are

    d-1,H,65535,L,R,D,Umax,min(32768,floor(Umax/D)),32768,131071,65536.

Ordered shifts are c,c-fx,c-fy,c-fo. Role 1 has terms
`(1,65535,L),(1,65535,R)` and binds `(X+H)*L+(Y+H)*R=U+Umax` to the two
original int16 sources. Roles 2–9 are the static appendix §3's roles 6–13,
using this Umax,D: numerator sign left/right, quotient product, division sum,
strict remainder sum, doubled remainder, and both half comparisons. The
source sign side bounds are 131071 and 65536; all word-zero/high-byte checks
remain, including exact cancellation and a negative numerator rounding to zero.

Return R(U/D) once and require int16. There is no separately rounded input or
addition after rounding. No virtual middle residual becomes a new cut. Width,
units, both incoming sources and the next norm's source/units must agree.
Umax<=2^46 and all role terms/results are below 2^49, with K<=7; the complete
nine-role frame is below 27000 bytes. Dependencies are E7-10 residual/RLC glue,
new aligned arithmetic, and E6/E8 original residual, virtual-source and cut joins.

## 3. Schema 6 — exact gated product

Parameters d in 1..16384, up fraction fu in 0..30 and activation fraction E
in 0..14 have bytes `u16(d) || u8(fu,E)`. Ordered scalars are

    fu+E,32768,65535,65535^2,2^30,2^31,d-1,131071,65536.

There are no shift fields. The three consecutive roles are

| Role | Terms (n,A,C) |
|---|---|
| original offset product | (1,65535,65535) |
| restored product left | (1,65535^2,1), (1,2^31,1) |
| restored product right | (1,2^31,1), (1,65535,32768), (1,65535,32768) |

For original int16 up X and configured SiLU result Y, let u=X+32768, v=Y+32768.
Bind P=u*v and `P+2^31=(T+2^30)+32768*u+32768*v`, with |T|<=2^30. This gives
exactly T=X*Y, with units 2^-(fu+E); no int16 narrowing or rounding occurs.
The positive endpoint 2^30 is legal. All terms/results are below 2^33, K<=5,
and this frame is below 11000 bytes. The int16 source signs have the recorded
small side bounds if materialized; both original source ranges remain required.
Zero up/activation cannot erase the other source or its configured lookup.

Dependencies: E7-05's exact product, E3-07/E3-08's original selected SiLU
membership, E6 FFN/source/units binding and the same T in schema 4's complete
gated row. This record cannot authorize the GPT-2 FFN, which uses tanh-GeLU
without a gate or product. That activation's actual lookup/source consumer
remains separately required.

## 4. Capacity, authority and remaining work

Every role above has at most three count-one terms and K<=7. Thus the static
appendix §5 argument bounds either column side by 3*7*255*256+255=1371135<p/2.
For schema 4's tighter K<=5 each role is at most 2143 bytes; seventeen scalars
and eight roles give less than 25000 bytes. Schema 5's K<=7 gives at most 2181
bytes per role; eleven scalars and nine roles give less than 27000 bytes.
Schema 6 has at most nine scalars and three K<=5 roles, below 11000 bytes.
These are checked-domain capacity proofs, not sampled-fit or benchmark claims.

Validation rederives parameters, counts, scalars, shifts, roles and every byte;
supplied record fields never choose expected authority. Model collection/source
association, rotary, attention, activation, decoding and full-model identity
are fixed by the complete RFC-0025 appendices; actual proof consumers remain
mandatory before native admission. No challenge, ledger loss,
native negative-control completion or profile admission is added. Static work
is T_misc; actual source/range/branch/arithmetic consumption remains charged to
T_witness/c_a/c_lu at its required reductions.

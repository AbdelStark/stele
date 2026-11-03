# RFC-0025 decoding static records

Status: Accepted. Part of [RFC-0025](RFC-0025-full-model-cqis.md), Q26/E5-03b.
The [sampling policy](full-model-decoding.md) fixes the numerical semantics.
These records use the [complete arithmetic frame and word predicates](full-model-bounds.md),
fixed p=2^31-1 and radix 256. Every source, whole-word range, zero/Boolean/index
predicate and boundary carry remains a consuming obligation. Supplied records
or observed logits never determine an expected bound. There are no new cuts.
All equations below apply on their stated real index ranges. Padded layouts
gate entire relations, including constant bias/divisor/one terms, with the
verifier-derived active selector. Zeroing only outputs cannot disable a relation.

## 1. Original logits and first maximum — schema 15

Parameters are `u32(v) || u8(fl)`, with 1<=v<=2^20 and 0<=fl<=30.
The exact previous-position output contains all v signed-int16 logits L_j in
common units 2^-fl. Let H=32768, O=65535, m=max L_j and k the least id attaining
m. Every original logit and m retain their signed source word and offset L+H.
Require 0<=k<v, original L_k=m, and for every real j:

    delta_j=m-L_j, (L_j+H)+delta_j=m+H,
    before_j=[j<k], gap_j+before_j=delta_j.

Both delta and gap lie in [0,O]; the second equation excludes an earlier tie.
The actual source, index comparison, complete vocabulary and attained element
cannot be replaced by a maximum value or a chosen subset. Greedy returns exactly
k. Sampled mode uses this same m before temperature rounding; it need not select k.

Write pad=2^ceil(log2 v), with pad=1 at v=1. Ordered scalars are
`H,O,v-1,pad,2pad-1`; there are no shifts. Each row below lists the complete
ordered terms (count,A,C) in its role. Unless shown, count is one.

| Role | Terms (A,C) | Actual relation |
|---|---|---|
| 1 | (O,1),(O,1) | logit offset plus delta |
| 2 | (O,1),(1,1) | gap plus before |
| 3 | (O,1),(H,2) | source offset plus 2 sign magnitude |
| 4 | (H,1),(H,1) | H plus magnitude |

Roles 3/4 repeat for each original source and m, with canonical sign at zero;
their equality is `(L+H)+2 sign(L) abs(L)=H+abs(L)`. All real indices, including
zero logits, remain active. Padding is outside the v-element reduction: source,
delta, gap and selectors are zero (offset H for a zero signed source), and no
padded row may attain the maximum or become a token.

## 2. One-round temperature — schema 16

Parameters are `u32(v) || u8(fl) || u32(tn,td) || u8(B,F,E,mode)` followed by
u8(split) exactly when mode is nonzero. The selected exp parameters and domains
are exactly [schema 10](full-model-function-bounds.md); its n is v. The positive
u32 temperature tn/td is reduced. The full collection must join this descriptor
to Model's actual sampled exp, schema 10, and schema 15 with the same v/fl.

Define U=2^B, f=2^F, premax=O*td, Nmax=premax*f, D=tn*2^fl,
bias=floor(D/2), qmax=min(U,floor((Nmax+bias)/D)), qDmax=qmax*D.
Ordered scalars are `O,premax,f,Nmax,D,bias,Nmax+bias,U,qmax,qDmax,D-1,v-1,pad,2pad-1`.
There are no shifts. The seven roles are:

| Role | Terms (A,C) | Actual relation |
|---|---|---|
| 1 | (O,td) | pre=delta*td |
| 2 | (premax,f) | N=pre*f |
| 3 | (Nmax,1),(bias,1) | N+bias |
| 4 | (qmax,D) | qD |
| 5 | (qDmax,1),(D-1,1) | qD+remainder=N+bias |
| 6 | (D-1,1),(D-1,1),(1,1) | remainder+strict_gap+1=D |
| 7 | (qmax,1),(U,1) | q+index=U |

Every real j uses the same original delta_j from schema 15, all nonnegative
words, 0<=remainder<D and 0<=q<=qmax. The actual exp argument is z=-q and its
ascending input index is U-q; product-exp splitting instead uses q. Schema 10
consumes exactly these values with active selector one and returns the original
weight w_j. A nonmaximum logit may round to z=0. This is legal and does not alter
the original first logit maximum. An attained maximum gives z=0 and w=2^E.
Operation padding has zero auxiliaries and inactive exp lookup; role 7 is
enforced only for real j, or with right side active*U in padded layouts.

The certificate deliberately admits configurations that can fail on some input
logits. An actual q>U rejects the request; no clipping or extra worst-case
configuration exclusion is introduced. qmax bounds successful results only;
all original source/numerator obligations still apply. Temperature zero never
means greedy. Neither a supplied exp output nor this record admits a table.

## 3. Complete sampled selection — schema 17

Parameters are `u32(v) || u8(E) || u32(pn,pd)`, with the same v/E as the selected
exp, 0<=E<=14, and reduced 1<=pn<=pd<2^32. Let Q=2^E, M=vQ, J=2^32,
T=pn*M, A=pd*M. Ordered scalars are
`Q,M,J,J-1,T,A,JM,M-1,v-1,pad,2pad-1,255,2^24`; there are no shifts.

The full vocabulary permutation pi has ranged entries and inverse inv: for
every original j, inv[j]<v and pi[inv[j]]=j. This is a complete source/gather
obligation, not merely an arithmetic assertion about a supplied list. Every
sorted weight is the actual w_pi[r] from schema 10/16. For adjacent ranks let
diff=w_pi[r]-w_pi[r+1]>=0 and tie=[diff=0], using the complete word zero predicate.
Require `tie*pi[r]+id_gap+tie=tie*pi[r+1]`, with 0<=id_gap<=v-1. The gap is zero
when tie is zero. This enforces descending integer weight and ascending id ties;
sorting original logits instead would change product-exp semantics.

All prefixes P_r remain, even outside the retained set; P_-1=0 and
P_r=P_(r-1)+w_pi[r], W=P_(v-1)=sum_j w_j. Full source membership and the attained
zero exp argument establish Q<=W<=M and first sorted weight Q. Choose 1<=k<=v,
Z=P_(k-1), and V=P_(k-2) or zero at k=1. Require

    threshold=pn*W, top=pd*Z, prior=pd*V,
    threshold+top_gap=top, prior+strict_gap+1=threshold.

Top gap is bounded by A; strict gap by T-1. These force the least inclusive
top-p boundary and positive last retained weight, including at pn=pd=1.
They also give Q<=Z<=W; an independently supplied positive divisor is insufficient.

For every rank, sigma=[r<k], selected_prefix=sigma*P_r,
numerator=J*selected_prefix, and

    C_r*Z+rem=numerator, rem+gap+sigma=sigma*Z.

C_r lies in [0,J], rem/gap in [0,M-1]. Inactive C/rem/gap are zero. Active
remainders are strictly below the same Z, so C is the exact floor quotient.
The original full prefix/order/weight checks remain active for unretained ranks.
C_(k-1)=J exactly; equal adjacent C values are valid empty buckets.

Select rank s<k; let lower=C_(s-1) or zero at s=0. With the original draw
0<=u<J, enforce `lower+left_gap=u` and `u+right_gap+1=C_s`, with both gaps in
[0,J-1]. Return the same token pi[s]. Empty buckets cannot pass these relations.
The four original low hash bytes b_i reconstruct `u=sum b_i*256^i` as a whole
integer. Seed commitment, full draw hash, original absolute position, request
and output joins remain mandatory; bytes or a digest alone authorize nothing.

| Role | Ordered terms (A,C), count one except role 1 | Actual side |
|---|---|---|
| 1 | (count=v,Q,1) | sum of every original weight |
| 2 | (Q,1),(Q,1) | following weight plus diff |
| 3 | (v-1,1),(v-1,1),(1,1) | tie*pi plus id_gap plus tie |
| 4 | (v-1,1) | tie*following id |
| 5 | (M,1),(Q,1) | preceding prefix plus actual weight |
| 6 | (M,pn) | threshold |
| 7 | (M,pd) | top |
| 8 | (M,pd) | prior |
| 9 | (T,1),(A,1) | threshold plus top_gap |
| 10 | (A,1),(T-1,1),(1,1) | prior plus strict_gap plus one |
| 11 | (M,1) | selected prefix |
| 12 | (M,J) | CDF numerator |
| 13 | (J,M) | quotient times original Z |
| 14 | (JM,1),(M-1,1) | product plus remainder |
| 15 | (M-1,1),(M-1,1),(1,1) | remainder plus gap plus sigma |
| 16 | (M,1) | sigma*Z |
| 17 | (J,1),(J-1,1) | lower plus left_gap |
| 18 | (J-1,1),(J-1,1),(1,1) | u plus right_gap plus one |
| 19 | (255,1),(255,256),(255,65536),(255,2^24) | four original hash bytes |

Whole semantic bounds remain in addition to each role's column envelope: each
prefix<=M, C<=J, all ids/inverse indices<v, k-1<v, and selected s<k. Padding is
outside the real permutation and uses zero auxiliaries with disabled selectors;
it cannot become a retained rank, change W/Z or supply the selected predecessor.

## 4. Capacity, consumers and evidence boundary

Temperature Nmax<2^78, D<2^62, qDmax<2^93. Every record value is below 2^94,
with K<=12 byte columns; selection values are below 2^67 and use at most nine
columns. The original-weight sum has raw column bound 255v, carry bound v and
either side at most 256v+255<=268435711<p/2. Other roles have at most four
count-one terms; raw<=4*12*255^2, carry<=4*12*255 and either side<=3133695<p/2.
Thus every exact column satisfies the common strict field-faithfulness test.
These are static analytic bounds, not sampled maxima or one-field lifts.

Schema 15 has 5 scalars/4 roles/8 terms, schema 16 has 14/7/12, schema 17 has
13/19/35. Even bounding every operand cap array by 12 bytes, a term needs at
most 608 bytes and a role's nonterm bytes at most 452. Including the fixed
header/parameters/scalars, complete records are below 12000/20000/40000 bytes,
respectively, within the common 128 KiB cap. Exact counts and all bytes must
match independently derived parameters; unknown modes, suffixes, truncations,
nonreduced rationals and inactive split bytes reject.

E7-08 and E6/E8 consumers must implement the full original logit, source/gather,
permutation, comparison, prefix, quotient and output relations. E3-07/08 and
the selected exp consumers retain complete table/source closure. E8/E14 request/
hash/wrapper consumers must bind the seed and every draw, with global H/query
accounting, all profiles, privacy and Q12/Q29 preserved. E13-04's top-k extension
remains original work. The [request contract](full-model-request.md) adds stop
records; the complete collection, outer identity joins and native controls remain
open. This appendix grants no NC-0107/0108 coverage.

The cost remains O(v log v) sorting and O(v) full arithmetic per generated token,
charged to T_witness, c_a/c_lu and T_misc; static derivation is T_misc. No extra
weight pass, benchmark, probabilistic loss or Transcript challenge is introduced.

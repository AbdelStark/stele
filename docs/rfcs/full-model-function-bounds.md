# RFC-0025 function-bound appendix

Status: Accepted. This appendix belongs to [RFC-0025](RFC-0025-full-model-cqis.md)
§2.8 and uses the [static arithmetic frame](full-model-bounds.md) §5, p=2^31-1,
radix 256 and its complete word predicates. Schemas 10/11 depend on independently
expected shapes and RFC-0021 function/representation parameters. They do not
admit tables or authenticate sources. All canonical tables, identities, source
joins and actual lookup/range consumers remain mandatory.

The question is whether the complete exp/activation domains, masks, component
indices and arithmetic fit closed records without narrowing either target.
Reject this derivation if a permitted parameter escapes a whole-word/column/
capacity bound, or if recombination loses the original lookup input. No new
challenge, cut, soundness loss or performance measurement is proposed.

## 1. Component addressing

Every component here has two i32 columns and RFC-0021 §4's canonical table frame.
Its header is 62 bytes: the 21-byte prefix, TableId[32], u32(N), u32(L), u8(2).
For real rows N, let L be the least power of two >=N. Append these six scalars
for each component in representation order:

    N, L, N-1, L-1, 8*L, 62+8*L.

Append two column roles for each component. As in the arithmetic appendix,
each term is (count, operand maximum, multiplier maximum):

| Role | Terms | Required source/equality |
|---|---|---|
| Row offset | (1,L-1,8) | off=8*row for the original canonical row ordinal. |
| Absolute byte | (1,8*(L-1),1),(1,7,1),(1,62,1) | address=off+lane+62, lane=4*column+byte, column in {0,1}, byte in 0..3. |

Membership uses only row<N. Padding rows N..L-1 have canonical all-zero bytes
but are never function inputs, even when a real query also contains zeros.
The complete regenerated table determines all bytes, including sign extension,
and exact total length. A digest alone is insufficient. Data addresses here
are static preparation/source bounds, not permission to replace a lookup with
prover-selected table bytes or bypass the configured public-MLE consumer.

## 2. Schema 10: exponential

Parameters are n in 1..2^20, B in 7..31, F in 0..30, E in 0..14, and mode
0/1/2 with the exact RFC-0021 meanings. Modes 0/2 require B<=15. Mode 0 has
no split parameter; its in-memory k is zero. Modes 1/2 require 1<=k<=16 and
0<=B-k<=15. Parameter bytes are u32(n)||u8(B,F,E,mode), followed by u8(k)
only for modes 1/2. No alternate function/representation enum is introduced.

Let U=2^B, Q=2^E, a=2^ceil(log2(n)), and set hmax=2^(B-k), lmax=2^k-1
for modes 1/2; both are zero for mode 0. The fifteen initial scalars are

    U,Q,Q^2,Q-1,hmax,lmax,component_count,2U,Q^2+Q-1,Q+3,2Q-1,
    n-1,a,2a-1,62.

Append §1's six scalars per component. There are no shifts. The component
counts/order/real row counts are:

| Mode | Components and N |
|---|---|
| 0 | direct: U+1 |
| 1 | hi: hmax+1; lo: 2^k |
| 2 | hi: hmax+1; lo: 2^k; correction: U+1 |

n is the authenticated attention context capacity or sampling vocabulary size.
An attention request has Nrequest<=n real keys; slots Nrequest..a-1 have selector
zero. At each original real key/token, sigma is the expected lookup selector. For
dense attention it is the causal mask from the original query/key positions;
for sampling every real vocabulary entry has sigma=1. Operation padding
n..a-1 has sigma=0. Supplied sparsity cannot choose sigma. Let delta be the
same nonnegative difference produced by the maximum/temperature consumer,
and index the ascending signed-domain coordinate. Require complete words
0<=delta,index<=sigma*U and delta+index=sigma*U. Masked/padded values are zero.
For attention these are exactly schema 9's original words, not recomputed
advice. Sampling retains its own specified maximum/temperature source chain.

For modes 1/2, require delta=2^k*h+l with 0<=h<=sigma*hmax and
0<=l<=sigma*lmax. Together with delta<=sigma*U this forces l=0 at the
terminal h=hmax. Splitting index instead of delta is invalid. Memberships
(h,H) and (l,Lv) use the configured hi/lo components and same h/l words.
Their values are 0..sigma*Q; let q in 0..sigma*Q, rem,gap in 0..sigma*(Q-1):

    H*Lv=q*Q+rem; rem+gap+sigma=sigma*Q.

Thus q is floor(H*Lv/Q), including Q=1 and its zero remainder. Mode 1's output
Y is that same q. Mode 2 additionally looks up (t,C) at t=-delta in the full
input-indexed correction table, with row ordinal index. Store Coff=C+sigma,
0<=Coff<=3*sigma, and require q+Coff=Y+sigma, 0<=Y<=sigma*Q.
The small range of Coff never replaces that lookup. Mode 0 directly looks up
(t,Y) in the direct table at the same index, 0<=Y<=sigma*Q. Direct/corrected
signed inputs have B<=15 and unique field lifts; mode 1's potentially 32-bit
delta is kept in complete words and split into small hi/lo indices.

The initial column roles, in exact order, are:

| Id | Terms | Meaning |
|---|---|---|
| 1 | (1,U,1),(1,U,1) | delta+index |
| 2 | (1,U,1) | sigma*U |
| 3, modes 1/2 | (1,hmax,2^k),(1,lmax,1) | original difference split |
| 4, modes 1/2 | (1,Q,Q) | H*Lv |
| 5, modes 1/2 | (1,Q,Q) | q*Q |
| 6, modes 1/2 | (1,Q^2,1),(1,Q-1,1) | q*Q+rem |
| 7, modes 1/2 | (1,Q-1,1),(1,Q-1,1),(1,1,1) | strict remainder gap |
| 8, mode 2 | (1,Q,1),(1,3,1) | q+Coff |
| 9, mode 2 | (1,Q,1),(1,1,1) | Y+sigma |

Then append §1's two roles per component: total roles 4/11/15 for modes 0/1/2.
The direct arithmetic parts also satisfy 2*(Q^2+Q-1)<p; neither that fact nor
a small sampled input permits replacing roles 1–3 with single-field equalities
at B=31. All conditional ranges, zero predicates, actual output/source views,
original score arithmetic even when masked, and function/representation identities
are required. At an allowed attained maximum, delta=0 and canonical exp gives
Y=Q>0. This source chain establishes positive mass; a nonzero witness does not.
Product exp remains potentially nonmonotone; no ordering inference is added.

## 3. Schema 11: activation

Parameters are row width d in 1..16384, kind 0..4, F in 0..30 and E in 0..14.
Kinds 0/1/2/3/4 mean sigmoid_q/silu_q/softcap_q/gelu_q/gelu_tanh_q respectively;
these are record tags, not changes to RFC-0021's named identities. Only softcap
has cap_m in 1..65535 and cap_f in 0..30, with odd cap_m when cap_f>0. Other
kinds have no cap bytes (their in-memory cap fields are zero). Parameter bytes
are u16(d)||u8(kind,F,E), then u16(cap_m)||u8(cap_f) only for softcap.

Every selected function uses version 1 and the direct mode 0 representation.
GPT-2 requires kind 4 and the actual up projection's F; Llama requires kind 1
and the actual gate projection's F. E determines the consuming conversion or
gated-product units. Other accepted activation definitions retain their original
tasks; this record does not enable them as substitutions in either dense family.

The entire 65536-row table must pass RFC-0021's exact definition, precision and
signed-int16 output checks before any operation. These static ranges are
conditional on that admission, not a new function-admission test: a bounded
record can be derived for parameters whose full table subsequently rejects.
Checking only selected entries, replacing an overflow with clipping, or silently
reducing E is forbidden. Table rows are in signed input order -32768..32767.

Let a=2^ceil(log2(d)). The ten initial scalars are

    d-1,a,2a-1,32768,65535,65536,98303,131071,2^32-1,65535*65536.

Append §1's six scalars with N=L=65536; there are no shifts. The first three
roles below apply separately to both original input t and original output Y.
Let W be that value's unsigned 16-bit source word, s its Boolean sign, and
o its offset by 32768. Require W,o in 0..65535 and these complete identities:

| Id | Terms | Meaning |
|---|---|---|
| 1 | (1,65535,1),(1,32768,1) | W+32768 |
| 2 | (1,65535,1),(1,1,65536) | o+65536*s, equal to role 1 |
| 3 | (1,65535,1),(1,1,65535*65536) | canonical i32 table word W32=W+65535*65536*s |

The first two enforce s=[W>=32768] and signed value W-65536*s=o-32768;
zero has s=0. The third preserves all four sign-extended bytes. Lookup fields
are the signed values lifted to F_p, not unsigned W32 reduced modulo p.
The input's same o is the row ordinal; the output is that same selected row's
second column. Source bytes, offset/index, field lift and table columns must
meet at the consuming lookup. Append the two address roles, ids 4/5. The
input/output equalities use the same five bound templates without claiming
that their independent witnesses are equal to one another.

There is no table padding, since N=L. Operation padding d..a-1 has input and
output source words W=W32=0, sign zero, offset o=32768 and selector zero. It is not an active input-zero lookup:
sigmoid_q(0) is nonzero, including E=0. Real rows always use selector one.
All real coordinates of the full FFN row remain; no 2048-coordinate research
limit applies. The subsequent gated product or whole-row conversion consumes
these exact output words at the original coordinates.

## 4. Complete-domain bounds and consumers

Every component has N,L<=65536, at most 524288 payload bytes, 524350 total
bytes and maximum absolute address 524349. Exp has at most 33 scalars and 15
roles; activation has 16 scalars and five roles. All operand/result bounds are
<=2^32, so every width and convolution/result column count is at most five.
Each role has at most three count-one terms. Its raw column is <=3*5*255^2,
carry <=3825 and each field side <=979455, strictly below p/2. Complete-word
bounds and final-zero carries prevent aliases, including at delta=2^31.

A role uses at most 2143 bytes under these bounds; the common header and
parameters use fewer than 64 bytes excluding the scalar words. Thus schema 10
is <42000 bytes and schema 11 <16000 bytes, within the unchanged 128-KiB cap.
These analytic limits cover all legal parameters; sampled sizes are evidence
only. No full-domain exp table of 2^31+1 rows is allocated: mode 1 uses its
two bounded components, while direct/correction reject B>15.

E3-07/E3-08 must consume the exact memberships, complete regenerated registry
and source joins. E6 supplies the original selectors, coordinates and public
table layouts; E7-06 consumes the attention differences/recombination and E7-08
the sampled-decoding counterparts. E7-05 and the explicit GPT-2 activation
dependency consume the actual FFN source/output before gated multiplication
or conversion. These remain actual native reduction requirements. Metadata,
numerical tests and byte equality earn no proof, privacy, profile or negative-
control credit. Derivation is T_misc; actual arithmetic/lookup work retains
c_a/c_lu and the original weight pass count.

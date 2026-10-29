# Q26: static scaled-linear arithmetic

Question: can every configured weight projection and embedding conversion derive
field-faithful signed, product and rounding bounds without observing a row's
values, including the int32 gated path and extreme checkpoint exponents? INV-5
and the weight-to-wide-output bindings are at stake. Derivation belongs to T_misc;
actual scale/range work belongs to c_a. Kill criteria: an unbounded field identity,
an accepted one-value substitution, an oracle mismatch, a bound depending on an
observed value, or a legal extreme exponent requiring unbounded record storage.
Research under RFC-0004 A3/A8/A9; no inference proof or NC-0109 admission.

## Closed arithmetic contract

The candidate checks Y=R(A*m*s*2^(ew-Fx+Fo)), signed nearest with ties away,
followed by signed int16 rejection, without saturation. This combines the matrix
output scales in Draft A3/A8/A9; Accepted A1's scalar Requant stays unchanged.
The separately expected, strictly typed `Spec` fixes:

- kind: wide, gated or embedding; dimension: 1..2^20; weight bits: 4 or 8.
- ew: -1099..1024; Fo: 0..30; Fx: 0..30 for wide, 0..44 for gated.
- Dynamic mode has inactive static scale 0; static mode selects s in 1..65535.
- Embedding fixes dimension=1, Fx=0 and static s=1. This is conversion of one
  selected code, not a replacement for the actual embedding gather relation.

Let W=2^(bits-1)-1, with symmetric weights [-W,W] and row codes [-127,127].
Amax=dimension*127*W, or W for embedding. Require 2*Amax<p, p=2^31-1,
before inspecting values. Int8 allows at most 66572 inner entries; int4 allows
the entire proposed dimension domain. Larger dots need a different chunk/carry
contract. The numerical model still restricts inner dimensions to 16384.
Each symmetric source range and actual dot/gather needs its real consumer.

Learned channel m is in 1..65535; its bound is the format maximum, not an observed
mantissa. Dynamic Smax=ceil(32768/127)=259 for wide rows, or
ceil(2^30/127)=8454661 for Draft A8's int32 product. Static Smax is the selected
s. Weighted_max=Amax*65535 and Pmax=Weighted_max*Smax. This format bound does
not prove gate membership, gated multiplication, maximum attainment or conversion.
Actual s is in [0,Smax] for dynamic mode, exactly the configured value otherwise;
s=0 requires A=0. Upstream all-zero and source/dot enforcement remain required.

Set e=Fx-ew-Fo and b=bit_length(Pmax). Static branch selection is:

| Branch | Condition | Exact magnitude relation |
|---|---|---|
| right | 0<=e<=b | D=2^e, h=floor(D/2), qD+r=P+h, 0<=r<D; h=0 at e=0 |
| left | -15<=e<0 | q=P*2^(-e) |
| zero_right | e>b | q=0 since P<=Pmax<2^b<=2^(e-1) |
| zero_only | e<-15 | P=q=0; any nonzero P shifted by at least 16 overflows int16 |

Qmax=min(32768,floor((Pmax+h)/D)) for right, min(32768,Pmax*2^(-e))
for left, zero otherwise. Constant branches never construct huge powers of two.
The exponent domain gives e in [-1054,1143], with bounded record storage.

## Relations and field faithfulness

Witness fields are sign, magnitude, weighted, product, quotient, scaled_quotient,
remainder, output and fixed role columns. All have static/format bounds. Boolean
sign and canonical zero enforce A=(1-2*sign)*magnitude in F_p. Both whole signed
expressions lie in [-Amax,Amax], so 2*Amax<p gives integer equality. The small
output equality uses that sign and q<=32768, with signed int16 output.
Byte-limb roles use the [column lemma](LIMBS.md):

| Role | Count | Left maximum | Right maximum |
|---|---:|---|---|
| weight_scale | 1 | Amax | 65535 |
| row_scale | 1 | Weighted_max | Smax |
| bias (right) | 2 | max(Pmax,h) | 1 |
| quotient_product (right) | 1 | Qmax | D |
| division (right) | 2 | max(Qmax*D,D-1) | 1 |
| left (left) | 1 | Pmax | 2^(-e) |

Both product roles remain in constant branches. Each role checks whole source
ranges, canonical source digits, digit/carry ranges, both zero boundary carries
and local equalities. Result digits bind to the next witness value; bias and
division result digits agree. Wide equality modulo p never replaces these
bindings. Digit caps alone do not prove whole source ranges. Unused
scaled_quotient/remainder fields are zero by static bounds.

Amax<2^30, m<2^16, Smax<2^24 imply Pmax<2^70. Finite right e<=70 and
Qmax*D<=Pmax+h<2^71; the division result bound is below 2^72. Finite left
shifts are at most 15. Every role result is below 2^86; sources/results and
convolutions need at most 11 byte digits/columns. Count<=2 gives raw column
<=2*11*255^2=1430550. A carry cap of 5610 suffices inductively because
floor((1430550+5610)/256)=5610. Both column sides are below 2^21<p/2.
The implementation derives tighter per-column caps. No conjectural bound is used.

## Candidate bytes and model roles

This separate research domain does not add an RFC-0022 v1 schema id. Integers
are little endian, signed fields two's complement; no padding:

1. Literal `stele/research/q26/scaled-linear/v1\0`.
2. Parameters (13 bytes): u8 kind (wide=0,gated=1,embedding=2), u32 dimension,
   u8 bits, i16 ew, u8 Fx, u8 Fo, u8 mode (dynamic=0,static=1), u16 static scale.
3. u32 p, u8 radix bits=8, u8 branch (right=0,left=1,zero_right=2,zero_only=3),
   i16 e, u8 scalar count=10, then u160 scalars in this order: acc_max, scale_min,
   scale_max, weighted_max, product_max, divisor, bias, left_factor, quotient_max,
   output_max. Inactive D,h,factor are zero.
4. u8 role count; roles in table order, omitting inactive roles. Each has sequential
   u8 id from 1, u32 count, u160 left/right/result maxima, u8 source/source/result
   lengths, u8 digit-cap arrays in that order, then u32 carry/lhs/rhs arrays of
   lengths K+1,K,K for K result columns.

At most five roles of at most 237 bytes, with fixed overhead tag length+223,
fit the explicit 2048-byte capacity. Exact regeneration rejects noncanonical
bytes, every truncation and suffix; no parser adopts supplied bounds.

`model_scaled_bounds.records` selects 2+7L records: embedding; each layer's
Q/K/V/O/up/gate/down; head, including tied head. Q/K/V use norm1.E and the
first row policy; O uses attention.fo and its output policy. Up/gate use norm2.E
and second policy. Down uses fu+SiLU.E and gated policy. Head uses final_norm.E
and head policy. Each operation supplies its own output fraction and source
dimensions/bits/exponent. No observed code/mantissa magnitudes are scanned.
Authenticated metadata, actual role associations and all other schemas remain required.

The fixture SHA256 hashes literal `stele/research/q26/scaled-linear-checksum/v1\0`,
u32 record count, then each u16 ASCII role-name length/name and u32 record
length/record. This is correctness evidence, not a complete certificate-set
identity or cqis_id.

## Reproduction and outcome

Run `uv run --locked --script research/cqis-checkpoint/check_causal_model.py --scaled-bounds`.
Seed 2634 checks 10000 specifications against an independent packed-column oracle,
outer struct framing and exact Fraction rounding. Every accepted witness also
checks NumPy int64 digit convolutions and field relations. Counts: 5297 accepted,
4703 overflow rejections; right=1259, left=1918, zero_right=4022, zero_only=2801.
Frozen SHA256: `301994d40fb8dcef20caec81fb86505d577412eac3d839cda318937f07d23673`.
Inner limb/digit helpers are shared; this is not native Rust/GPU parity.

Controls cover every static field/local role, coherent rebuilt substitutions,
field aliases, signed zero, zero scale, wrong static scale, false zero_only,
int16 endpoints/ties, branch boundaries, maximal faithful dots, unsafe dimensions
even with zero data, all strict truncations and every byte flip of representative
records. Actual matrix arithmetic includes a numerator larger than int64.
Thirty numerical models check role selection and independence from observed
embedding weights; every non-overflow model checks all role relations against
its independent numerical composition. The pinned checkpoint adds 16 records, 16419 record
bytes, checksum `08a8c3c10f75c0b15670e7c16e26c8176b06af0b319ee19ab0a6654a4a4dacf8`;
its original configuration, artifact, logits and generation fixture is retained.

Recommendation: continue Q26/A3 toward closed row-conversion, attention, rotary,
residual and decoding schemas, full certificate-set bytes and actual source,
range, lookup and PCS consumers. The small signed-dot path does not replace
arbitrary-width matmul bounds. Native graduation requires an RFC-0022 amendment;
its Accepted bytes stay unchanged. No NC-0109, complete-inference, fidelity or
task-completion credit. Derivation contributes to T_misc, limb/range work to
c_a/T_witness; no measured constant, benchmark, challenge, cut or weight-pass change.

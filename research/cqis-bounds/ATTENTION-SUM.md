# Q26: static signed attention accumulation

Question: can restored-value attention sums remain field-faithful at the full
configured key capacity, with work proportional to actual keys and no allocated
zero tail? INV-5 and probability/value/scale/mask/position bindings are at stake;
the cost terms are T_misc/c_a/T_witness. Kill criteria: a whole-row modular alias,
accepted source substitution, unsafe column cap, runtime-selected bound, oracle
mismatch or work proportional to unused capacity. Research under Draft RFC-0004
A3/A6 and RFC-0009 A2; block rounding, normalization, score/max/function consumers
and complete attention-proof admission remain required.

## Expected domain and static capacities

Spec fixes absolute context length L in 1..2^20, head width W in 1..16384,
value fraction fv in 0..30, probability exponent E in 0..14, dynamic/static value
policy and exact/block1024 accumulation. Dynamic scale metadata is inactive zero;
static scale s is in 1..65535. The term capacity C is L for exact mode and
min(L,1024) for block mode. Write P0=2^E. Dynamic code/scale caps are 127/259;
static caps are min(127,floor((65536+s)/(2*s)))/s. Their product S bounds restored
values, with S<=65535. Zmax=C*P0<=2^34, H=Zmax*S<2^50 and Omax=2H<2^51.
These are format/parameter bounds, never observed probability or value maxima.

The separately expected positions are nonempty, strictly increasing integers
in [0,L), with actual count n<=C and n*W<=2^20. Exact mode has inactive block id
zero. Block mode requires every position//1024 to equal the expected block id;
partial blocks and gaps retain their absolute positions. Weights are integers
in [0,P0], masks are booleans and a masked weight must be zero. Each value row
has W symmetric codes within its policy cap and the corresponding scale within
its policy range. Zero scale requires zero codes, even at masked/zero weights.
Python bool is rejected as an integer. The entry limit is a research resource
cap, not a new inference-plan capacity. Empty blocks contribute zero externally.

The expected inputs must eventually come from the actual probability, mask,
prepared V and scale claims. These checks do not establish maximum attainment,
the exponential function, canonical row conversion, correct head/GQA views,
complete key membership or model/position ownership. In particular, the V scale
is inherited from conversion of the complete projection row before head slicing.
The fraction identifies units even though it cancels from this raw sum.

## Signed sum and capacity-based columns

First bind u_jc=S+code_jc*scale_j with u in [0,2S]. Both sides are in [0,2S],
strictly below p/2 for p=2147483647; the M31 equality is therefore integer-faithful.
For each output column enforce the following with canonical radix-16 digits:

- z=sum_j weight_j; base=S*z; o_c=sum_j weight_j*u_jc;
- o_c+2*b_c*a_c=base+a_c, where b is Boolean and a in [0,H];
- g_c+b_c=a_c, where g in [0,H], excluding negative zero.

Return z and (1-2*b_c)*a_c only after these checks. There is no separate wide
total field bound solely by a field equality. Zero z is valid for an all-masked
block; the complete attention row's positive divisor still needs its consumer.
No division, block rounding or summation of rounded block outputs occurs here.

The six column roles have (term capacity,left maximum,right maximum):

| Scope | Role | Parameters |
|---|---|---|
| shared | weight_sum | (C,P0,1) |
| shared | base | (1,Zmax,S) |
| per column | offset_sum | (C,P0,2S) |
| per column | sign_lhs | (2,2H,2) |
| per column | sign_rhs | (2,H,1) |
| per column | sign_gap | (2,H,1) |

The new bounded_columns helper interprets Spec.count as capacity; existing
limbs.py and Accepted RFC-0022 exact-arity semantics remain unchanged. It derives
all digit/carry/result caps from that capacity, then stores source digit rows
only for the separately expected actual inputs. This is equivalent to an
implicit zero tail. Missing or extra supplied source rows reject; no witness
chooses which expected sources are present. Whole source ranges and exact source
digits are required, along with zero initial/final carries and each column
equation. Result equality is exact after canonical zero extension to 14 nibbles.
The largest role result cap is 8H<2^53, so this width suffices for every role.

For P0<=2^14 the sum of its nibble caps is at most 49. Offset digit caps are at
most 15, so each raw coefficient is at most 735*C<=770703360. The carry recurrence
gives carry<=51380224, LHS<=822083584 and RHS<=822083599, all strictly below p/2.
Weight_sum obeys this same bound. Other roles have at most two terms and fourteen
digits per operand: coefficient<=6300, carry<=420 and both sides<=6735.
At C=2^20,P0=2^14,2S=131070 the actual derived maximum LHS/RHS is
816840960/816840975 and carry is 51052560. Byte radix fails FieldBound even with
only one actual zero source: small observed work cannot authorize unsafe caps.

## Candidate encoding and model roles

This separate research frame uses unsigned little-endian integers without padding:

1. Literal `stele/research/q26/attention-sum-bounds/v1\0` (43 bytes).
2. u32 L, u16 W, u8 fv, u8 E, u8 value mode, u16 scale, u8 accumulation.
   Mode tags are dynamic/exact=0 and static/block1024=1 in their respective fields.
3. u32 p, u8 radix bits=4, u8 scalar count=14; fourteen u160 scalars in order:
   term_cap, probability_max, code_max, scale_min, scale_max, restored_max,
   value_offset_max, weight_sum_max, base_max, offset_sum_max, magnitude_max,
   source_rhs_max, entry_capacity, block_max.
4. Shared then per-column groups, each starting with u8 role count (2 then 4).
   Roles follow the table order, each with u8 id starting at one within its group,
   u32 capacity, three u160 maxima (left,right,result), three u8 digit lengths,
   then left/right/result digit-cap bytes and carry/LHS/RHS u32 arrays.
   The result length K fixes carry length K+1 and both side lengths K.

Left/right/result widths are at most 13/5/14 nibbles. The fixed prefix/groups
occupy 343 bytes; each role needs at most 272 bytes,
giving a conservative 1975-byte bound within capacity 2048. Exact regeneration
from expected Spec rejects every altered field, truncation, mutation and suffix.
One layer.i.attention_sum template covers the shared head configuration of each
layer. The evidence checksum hashes literal
`stele/research/q26/attention-sum-bounds-checksum/v1\0`, u32 record count, then
u16 ASCII role-name length/name and u32 record length/bytes for each record.
This is neither a complete certificate-set identity nor source authentication.

## Evidence and recommendation

Run `uv run --locked --script research/cqis-checkpoint/check_causal_model.py --attention-sum`.
Seed 2643 covers 10000 configurations/rows with independent exact/NumPy int64
weighted sums, packed-column caps, convolution and struct framing. Frozen SHA256:
`008219d51e2d96bc9fa90c5508243b09f7917c022cab2e58701f84ede055f55e`.
The tests-first run rejected the missing implementation. Controls alter each
certificate field and representative bytes, expected source/code/scale/weight,
offset, total/sign/gap, position/block, mask, source arity and carry boundaries.
They cover cancellation, all-zero blocks and full-capacity metadata.

The signed alias control uses static scale 65535, two codes -1 and weights 16384.
The true sum is -(2^31-32768), while a forged positive 32767 differs by p.
Its offset sum is zero and forged base+a=p: a field-only equality accepts;
coherently rebuilt nibble witnesses reject with IntegerRelation. A forged
weight sum shifted by p also rejects. Source checks remain active on zero weights.

Seed 2644 exercises thirty model configurations with dynamic/static V policies;
28 valid cases compare each head's raw sums against independent replay, while
two reject arithmetic overflow.
Positions 1023,1024,2048 exercise separate occupied blocks, a masked middle block
and a partial final block; per-block rounding yields [2,-2], whereas compacting
into one block would give [1,-1]. Rounding here is an existing numerical oracle,
not a relation established by the new checker. Shared inner model primitives
are disclosed; no native Rust/GPU parity is claimed.

The pinned checkpoint adds two records, 3146 bytes and checksum
`c2b7e11cebfbdd44df99ee03c251257cbde08f5ce27709c5385b53c73a2800e9`.
Full/cache/greedy replay preserves every earlier fixture field and checks these
relations for every layer/query/head of the generated sequence. Serialized sizes
are correctness metadata, not performance measurements.

Recommendation: continue Q26 with block rounding, rounded-block summation, signed
normalization, score/max schemas and the complete certificate set. Amend RFC-0022
before native graduation. Actual source/range/function/selection/PCS consumers,
native forward, fidelity and NC-0109/0500..0506 remain required; E5-03/04 and
E7-06/07 retain their original criteria. Derivation is fixed work per template;
source digits and checks use O(n*W) work/data, independent of unused capacity.
These contribute to T_misc/c_a/c_x/T_witness without a measured constant, new
cut, changed proof weight-pass count or admitted inference-proof claim.

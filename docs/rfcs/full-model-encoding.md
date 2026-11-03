# RFC-0025 encoding appendix

Status: Draft. This appendix belongs to [RFC-0025](RFC-0025-full-model-cqis.md).
Its closed fields are a proposed numerical/preparation contract, not an accepting
proof-plan or passport parser. The full proof consumers remain separately required.

## 1. Framing and physical role order

All unsigned integers are little-endian; signed integers use two's complement.
`B(x)=u32(byte_length(x)) || x`. Strings are exact UTF-8 without normalization,
NUL, invalid sequences or surrogate code points. No padding, optional extension,
unknown enum, inactive field or trailing byte is legal. `H` is unkeyed BLAKE3-256.
Every length/product/addition must fit u64 before access or allocation. The fixed
ASCII prefixes below include no NUL or terminator. Schema version is in the prefix.

Family 0 is dense GPT-2: affine LayerNorm, learned positions, biased Q/K/V/O/up/
down, tanh-GeLU, and tied token/head weights. Family 1 is dense Llama: RMSNorm,
no learned positions, unbiased Q/K/V/O/up/gate/down, SiLU gating, and an untied
head. Unsupported architectures reject; this does not cancel RFC-0017 coverage.

Dimensions are `L` layers, residual width `d`, vocabulary `v`, capacity `n`,
query heads `h`, KV groups `g`, head width `a`, FFN width `f`. They have RFC-0025
§1's domains; `h*a=d`, `h % g=0`. GPT-2 additionally requires `g=h`, `f=4*d`.
The actual GPT-2-small/Llama-3.1-8B presets must authenticate their original
dimensions; a general descriptor cannot assign itself either named identity.

Physical records are ordered by the following expansion, with no supplied role
count or arbitrary role names. Each row gives its derived shape. A vector uses
signed int16 and its explicitly selected fractional precision; a matrix uses
explicitly selected int4 or int8 with channel axis 0. Every matrix is stored
output-channel major with its last axis varying fastest.

1. `token` [v,d]; then `position` [n,d] only for GPT-2.
2. For each layer in increasing order: `norm1.gain` [d], `norm1.bias` [d] only
   for GPT-2; Q [h*a,d], K [g*a,d], V [g*a,d], O [d,h*a], up [f,d], gate [f,d]
   only for Llama, down [d,f]. Each GPT-2 matrix is immediately followed by its
   bias vector [output dimension]. Then `norm2.gain` [d], `norm2.bias` [d] only
   for GPT-2.
3. `final.gain` [d], `final.bias` [d] only for GPT-2; then `head` [v,d] only
   for Llama. GPT-2's head is always a reference to physical record zero.

There are exactly `16*L+4` GPT-2 records or `9*L+3` Llama records. Their implicit
ids are 0..count-1. Distinct roles cannot share a physical id, even if their
values are equal, except the prescribed GPT-2 token/head tie. Fused checkpoint
storage is a source transform, not a physical alias of different model roles.
All operations resolve these ids from the family and layer; artifact bytes
cannot supply a different role map or remove a required tensor.

## 2. Source map and exact transforms

Source containers retain the complete safetensors structural checks and the
typed single-file/indexed-shard distinction in RFC-0011 A3. Their production
byte framing and source-to-passport join remain RFC-0025 acceptance work.
This section specifies the new role-to-source transform unambiguously.

`Map = ASCII("stele/v0.1/cqis/source-map") || B(Shape) || Entry[record_count]
|| u32(alias_count) || Alias[alias_count] || u32(ignored_count) || Name[ignored_count]`.
`Shape = u8(family) || u16(L,d,h,g,a,f) || u32(v,n)` in that order.
`Name = u16(length) || UTF8(name)`; names have 1..4096 bytes.

`Entry = Name || u8(dtype) || u8(rank) || u32(dim)[rank] || u8(transform)
|| [u8(part) iff transform in {2,3}]`.
The dtype ids 1/2/3/4 mean F16/BF16/F32/F64. Rank is exactly 1 or 2; dimensions
are positive u32. Element counts and exact source byte lengths fit u64.
There are four closed transforms, applied to raw scalar encodings before any
maxima, scale selection or rounding:

| Tag | Required source and resulting canonical coordinates |
|---|---|
| 0, copy | Source shape equals the complete destination shape; elementwise identity. |
| 1, transpose | Projection/head matrix source [input,output]; destination [output,input], W[o,i]=S[i,o]. Token/position sources use copy. |
| 2, Q/K/V columns | GPT-2 Q, K, V matrices only, source [d,3d]; part 0/1/2 respectively, W[o,i]=S[i,part*d+o]. |
| 3, Q/K/V bias | GPT-2 Q, K, V biases only, source [3d]; part 0/1/2 respectively, B[o]=S[part*d+o]. |

A source name is used once, except tags 2/3: each such name must occur exactly
three times for Q/K/V of the same layer, with the same dtype/shape/tag and the
three prescribed parts. A partial fused selection, mixed copies/slices, overlap,
cross-layer reuse, duplicate part or unused fused interval rejects. Separate
Q/K/V sources use tags 0/1 as appropriate. Even square Conv1D weights explicitly
select transpose. Llama matrices have no inferred permutation. Any source adapter
that changes rotary pairing must supply a separately specified transform; neither
this map nor a shape match authorizes that permutation.

An alias is `Name || u16(target_record_id)`. The only permitted alias is an
optional separately stored GPT-2 head referencing record zero: at most one alias,
and its entire raw dtype, shape and scalar bytes must equal the selected token
source before conversion. Other aliases, including a differently quantised head,
reject. The token entry must use copy. The alias does not create a second output
record, perform another quantisation, or change the one-pass proof requirement.

Ignored names are explicit nonparameter buffers approved by the independently
authenticated source map. They are not authority to omit a required role. The
unique selected names, alias names and ignored names are pairwise disjoint and
their union must equal the complete source container/index tensor-name set.
Aliases and ignored names are sorted by raw UTF-8 bytes with no duplicates.
The complete map is at most 16 MiB. Counts must fit the remaining bytes before
iteration; selected entries are determined by Shape, not an untrusted count.

`source_map_id=H(Map)` binds names, source formats/shapes, every transform,
partition, alias and ignored policy. It does not authenticate an original file
or establish that the mapping is the publisher's intended model. The caller
must independently authenticate both the original source and this complete map.
Quantisation of a fused matrix occurs after its partition: each Q/K/V matrix
has its own tensor exponent. Quantising the fused source once is a different
algorithm and is forbidden by this contract.

## 3. Physical configuration, records and preparation

The configuration of physical record i is
`C_i = u16(i) || u8(rank) || u32(dim)[rank] || u8(bits) || u8(parameter)`.
Shape and rank are derived from §1. For a matrix, bits is 4 or 8 and parameter
is exactly 0 (channel axis). For a vector, bits is 16 and parameter is its
fraction in 0..30. Norm fractions must equal the consuming function's G/Gb;
all other bias fractions must equal the projection's selected bias fraction.
Neither the file nor this metadata selects those expected numerical parameters.

`R_i = ASCII("stele/v0.1/cqis/tensor") || B(C_i) || Scales || u64(payload_length)
|| Payload`. For matrices, Scales is i16(e) then exactly dim[0] positive u16
mantissas, using RFC-0025 §2.1. For vectors, Scales is empty. Payload is continuous
row-major packed int4, int8 or little-endian int16. Int4 earlier elements occupy
low nibbles; only an odd final high nibble is zero padding. Codes -8/-128 reject.
Exact payload length is ceil(element_count*bits/8). No row padding is present.

`Preparation = ASCII("stele/v0.1/cqis/quantiser") || B(Map) || C_i for every i`;
`quantiser_id=H(Preparation)`. Every C_i has a derived length, rank and ordinal.
The algorithm is precisely finite scalar decoding, the closed source transforms,
the minimal shared-exponent/channel-mantissa weight policy, and single-round
wide conversion in RFC-0025 §2.1. No calibration or host cast is implicit.
The actual source hash is instance data and is not part of this algorithm id.

`Artifact = ASCII("cqis-weights-v1") || quantiser_id[32] || u16(record_count)
|| (u64(record_length) || R_i) for every i`; `digest_cqis=H(Artifact)`.
All counts, record metadata and lengths are independently derived before decoding
scales/payloads. A syntactically valid record set is not proof of conversion:
regenerate it from the authenticated source or discharge the separately required
commitment/artifact binding at the actual passport consumer. A legal changed code
must change digest_cqis without changing quantiser_id.

Source repartitioning/header order can change the typed source identity while
leaving Map, quantiser_id and Artifact unchanged. Changing source names or the
ignored policy changes Map and therefore quantiser_id and Artifact's header,
even when all numerical tensor payloads remain equal. No contradictory claim of
source-independent artifact bytes is made.

## 4. Runtime numerical configuration

`Model = ASCII("stele/v0.1/cqis/model") || B(Shape) || C_i for every i
|| u8(f0) || Block[0] || ... || Block[L-1] || Norm(final) || Policy(final)
|| u8(logits_fraction) || B(Decoding)`.
The prefix, Shape and physical configurations have §§1–3's definitions. Source
names/transforms are in Preparation; they cannot choose runtime operation order.
`f0` and logits_fraction lie in 0..30. Decoding has the closed bytes in the
[decoding appendix](full-model-decoding.md).
There is no executable code, arbitrary op list, optional block or JSON in Model.

`Norm = B(Function descriptor) || B(Representation)` using RFC-0021 §4 framing.
For Llama it is rmsnorm_q/mode 3. For GPT-2 it is layernorm_q/mode 4, with version
1 and parameters `u16(d) || u8(F,G,E,Gb) || u32(en,ed)`; mode 4 has no parameters
and exactly the existing rsqrt_q TableId. LayerNorm has the same thirteen-byte
RMSNorm tuple plus Gb, with Gb immediately after E. All function/representation
parameters are validated, not just their hashes. d equals Shape.width; G/Gb equal
the corresponding physical gain/bias fractions. F equals the actual incoming
residual fraction; E determines the converted norm output's source units.

`Policy = u8(mode) || u32(scale)`, dynamic=0/static=1. Dynamic scale is exactly
zero in configuration (the actual per-row scale is a witness). Static scale lies
in 1..65535 for int16 inputs and 1..8454661 for the gated int32 product. All row
outputs remain symmetric int8; unrepresentable static conversions reject. These
mode-specific limits do not authorize a full-range int32 general converter.

`Block = Norm(first) || Norm(second) || u8(output_fraction)[projection_count]
|| u8(mid_fraction,out_fraction,attention_fraction) || Policy[7]
|| u16(score_m) || i8(score_e) || u8(accumulation,drop)
|| B(exp Function descriptor) || B(exp Representation)
|| B(activation Function descriptor) || B(activation Representation) || B(Rotation)`.

Projection order is Q,K,V,O,up,down for GPT-2 and Q,K,V,O,up,gate,down for Llama.
Every output fraction and the three residual/attention fractions lie in 0..30.
Bias fractions come from each projection's physical bias C_i, not an extra
independently changeable value. The seven policies are, in order: first norm
output, complete Q row, complete K row, complete V row, assembled attention row,
second norm output, complete FFN activation/product row. There are no per-head
or per-channel activation policies. The last policy sees int16 for GPT-2, the
int32 gated product for Llama; all others see int16.

Attention uses Q/K/V projection fractions directly, exp's F and the explicit
score_m/score_e. O's source fraction is attention_fraction. Exact accumulation
is tag 0 and requires drop=0; block1024 is tag 1 with drop 0..62 and the statically
checked block bound. exp is the selected RFC-0021 product or nearest function,
with its one explicit representation. Neither B/E nor split has a hidden default.
The O projection output and incoming residual align once into mid_fraction.
The second norm F equals mid_fraction. Down output and that middle residual
align once into out_fraction. First norm F is f0 for layer zero and the preceding
out_fraction thereafter. Final norm F equals the last out_fraction.

GPT-2 activation is gelu_tanh_q/version 1/direct, with F equal to up's fraction;
its E gives the down-input fraction. Llama activation is silu_q/version 1/direct,
with F equal to gate's fraction; down-input fraction is up_fraction+E (at most
44). A function's full table must satisfy RFC-0021 output/range/precision checks.
The final norm's output is converted under Policy(final), then projected by the
prescribed head using logits_fraction. No final head bias exists in either family.

Rotation is empty for absence. GPT-2 requires absence; Llama requires a present
descriptor. A present descriptor is
`ASCII("stele/v0.1/cqis/rotation") || u16(width) || u32(length)
|| u8(family,layout) || u32(original) || u64(num,den)[4]`.
The four reduced rational pairs are theta,factor,low,high; family is 0:base,
1:linear, 2:llama3; layout is 0:adjacent, 1:split. Width is even, 2..head_width;
length equals Shape.context. Theta and factor are in [1,2^32]. Base fixes factor
to 1/1; base/linear fix original=0 and low=high=0/1. Llama3 has
0<low<high<=2^32 and original in 1..2^20. Denominators are positive; all numerator/
denominator fields fit u64. No equivalent nonreduced encoding is accepted.
The exact coefficients are RFC-0025 §2.4's real-frequency/Q14 definition.

`rotation_id=H(Rotation)`; canonical data is
`ASCII("stele/v0.1/cqis/rotation-data") || rotation_id[32] || i16(C,S)` for each
position then pair, with exactly length*width/2 pairs and no data padding.
The registry derives the sorted unique rotation descriptors by raw rotation_id,
retains every layer-to-id reference separately, regenerates every coefficient,
and compares complete data digests. Changed pairing changes identity even where
coefficient arrays coincide. MLE/code layouts and zero-padding selectors are
actual proof-plan work; a raw data digest does not supply those consumers.

Every inner Function/Representation/Rotation frame is capped at 128/192/128 bytes;
Model is capped at 1 MiB. Bounds precede loops and allocations; checked canonical
decode followed by exact re-encoding must equal the original bytes. Conflicting
representations of one FunctionId reject. The function manifest contains the
unique selected functions, while the ordered operation references retain first
norm/attention-exp/second-norm/activation for every layer, then final norm and any
sampled-decoding function. Reduction-selected range functions remain additional
proof-plan obligations; they cannot disappear because the neural set omits them.

Model parsing checks every closed field/domain, physical ordinal/shape/format,
norm gain/bias fraction, adjacent residual unit, activation source fraction,
head/group/rotary dimension and conflicting representation before returning
structural metadata. No physical shape is adopted from a C_i header. GPT-2 has
exactly six projection fractions and no rotation; Llama has seven and a present
rotation. The up-plus-activation fraction of its gated product is at most 44.
Policy's u32 scale retains the complete gated limit 8454661; a u16 parser would
incorrectly narrow it. Unknown fields, inactive bytes and suffixes reject.

This structural step precedes complete admission. Registry must regenerate and
validate all selected table/rotation data; Bounds must derive and validate the
static score, full-block and every other arithmetic certificate. A descriptor
can parse while its full table or static bound fails. Such a configuration must
reject before inference or proof construction. A successful Model parser is
not an admitted operation, verified source, passport or proof record.

The whole Model fits below 220000 bytes by the declared domains, independently
of sampled fixtures: at most 2052 physical records of at most 13 bytes, 128
blocks of at most 1494 bytes using the inner caps, and less than 800 bytes for
the remaining header/final-norm/policy/decoding fields. The 1 MiB parser cap
therefore covers the complete domain. Counts/inner lengths are checked before
iteration and slicing; native fallible allocation remains required.
Checking an independently expected H(Model) is only a content-identity join.
It cannot replace the complete cqis_id, which additionally binds Scales,
Registry and Bounds, or authenticate its own expected value.

## 5. Public scale parameters

The quantised matrix scales are independently authenticated CQIS parameters,
not prover-supplied tight bounds inferred from a witness. Their complete frame is
`Scales = ASCII("stele/v0.1/cqis/scales") || H(Model)[32]
|| (u16(record_id) || i16(e) || u16(m)[output_dimension])` for each matrix in
physical record order. There is no vector entry, count, duplicate or omitted
matrix. e is in [-1099,1024] and every m is in [1,65535]. All-zero-source
minimality is checked during conversion, not inferred by the scale parser.

The artifact's corresponding Scales bytes must equal these exact parameters at
the source/artifact/passport consumers. A tied head uses record zero's same scale
entry. Static arithmetic derivation may use these authenticated scale parameters,
but never an observed maximum code/activation to narrow a declared format.
The total number of matrix channels is v+n+9*L*d for GPT-2, or
2*v+L*(3*d+2*g*a+2*f) for Llama. Thus there are at most 2^24 mantissas in this
domain. Derive the complete length before reading; Scales is capped at 64 MiB.
This separate bound does not inherit Model's 1 MiB metadata cap. Stream validation
and fallible allocation remain native requirements; no entire-copy promise is
made by these bounds. RFC-0011's public/encrypted-to-verifiers scale policy remains.

The largest GPT-2 channel count is 6815744, with 770 matrices, since its FFN
constraint limits d to 4096. The largest Llama count is 16777216, with 898
matrices. The exact maximum Scales lengths are therefore 13634622 and 33558078
bytes, including the 54-byte prefix/hash header and four bytes per matrix.
These are analytic domain bounds, not sampled maxima or benchmark results.
The decoder derives this exact size and matrix order from the checked Model
before reading entries. It compares the complete H(Model), including numerical
fields unrelated to shape, and validates every positive mantissa. A legal
changed channel changes H(Scales); matching shape/exponent alone is insufficient.
Structural validation does not establish the source-dependent minimal exponent
or mantissas, nor authenticate the expected Model/Scales digests.

## 6. Registry and numerical identity

The ordered neural function roles are first norm, attention exp, second norm,
activation for each layer, then final norm, then sampling exp if selected.
There are exactly 4*L+1+[sampled] roles. Every role retains its FunctionId and
RepresentationId even when functions repeat. The inner Manifest uses the exact
RFC-0021 frame and its complete regenerated table-data digests, with the proposed
LayerNorm mode from §4. Include the unique union, sorted by raw FunctionId/TableId;
no caller-supplied additional/unused function or component is allowed here.

`Registry = ASCII("stele/v0.1/cqis/registry") || H(Model)[32] || u16(role_count)
|| (FunctionId[32] || RepresentationId[32]) for each role || B(Manifest)
|| u16(L) || RotationRef[0] || ... || RotationRef[L-1] || u16(rotation_count)
|| (B(Rotation) || H(canonical_rotation_data)[32]) for every unique rotation`.
RotationRef is u8(0) for absence or u8(1) followed by rotation_id[32]. The final
rotation entries are sorted by raw rotation_id; unequal descriptors with equal
ids reject. The expected set is derived from Model, not supplied references.
The registry is capped at 1 MiB, Manifest at 256 KiB, rotations at 128 entries.
At most 514 unique functions and 516 component tables are possible in this domain.
Length bounds are metadata bounds, not permission to omit full data regeneration.
Reduction range functions and coded public-source roots remain part of the full
proof plan, with all original registry/source/selector obligations.

Registry validation derives the exact ordered metadata and unique definition
sets from the structurally checked Model. It checks exact total length and all
metadata bytes before generating data. Every remaining 32-byte field is then
compared with the digest of its complete regenerated component or rotation data;
there is no supplied-data authority callback or option to skip regeneration.
An immutable cache may retain only digests computed by that same full generation
path, keyed by the complete checked definition. Validate host fields before a
cache lookup; Boolean pseudo-integers must not alias valid integer keys.

Rotation data generation streams position-major rows of at most 32768 bytes,
retaining every pair through length*width/2. It has no former research-size cap.
The data prefix and rotation_id participate in the hash even when two layouts
produce identical coefficient values. Table generation retains all real rows
and canonical zero padding, including every correction component. A full-table
overflow or failed precision certificate rejects the complete Registry.

The declared caps give Manifest at most 250161 bytes: 33 header/count bytes,
514 function entries of at most 324 bytes and 516 components of at most 162
bytes. Registry's ordered references, rotation records and framing bring its
domain bound below 312000 bytes, within 1 MiB. These metadata capacities do not
bound preparation time or the total regenerated data size, and do not establish
native fallible allocation, public-MLE authentication or passport admission.

`cqis_id = H(ASCII("stele/v0.1/cqis/identity") || H(Model)[32]
|| H(Scales)[32] || H(Registry)[32] || H(Bounds)[32])`.
Bounds must be the complete statically derived collection with a closed schema,
not the existing twelve-family study or an opaque byte string. Its header binds
Model/Scales/Registry hashes, never cqis_id itself; this avoids an identity cycle.
The [collection appendix](full-model-bound-collection.md) specifies the exact
nineteen-schema frame, fixed operation expansion and complete parameter joins.
Full outer authentication and actual consuming-reduction closure remain required;
this proposed identity join is not a complete passport or proof implementation.

The passport must jointly authenticate the exact Model, Scales, Registry, Bounds,
cqis_id, Preparation/quantiser_id, typed original source identity, digest_cqis,
complete plan, commitment/layout/source and table bindings, certificate, fidelity
and registration fields. The source map comes from Preparation and the physical
C_i must equal Model's. Original source-config/tokenizer files need exact-byte
identities at their actual adapter/traffic consumers. No content hash authenticates
its own expected value. The numerical identity contains no private tensor payload
or public proof-admission flag and does not instantiate the complete passport.

## 7. Remaining acceptance work

The [request contract](full-model-request.md) fixes request/stop/token-I/O
subrecords with the exact Model decoding descriptor in public policy. It does
not replace the complete typed public-input/passport/commitment frame.
The complete passport/public-statement field schemas and actual source/collection
consumers still require the contracts in RFC-0025 §7. Sections 3–6 need
independent complete-codec/config/flow evidence before acceptance. This appendix
specifies no generic operator extension, successful proof record or profile.
It remains Draft until the entire acceptance gate closes.

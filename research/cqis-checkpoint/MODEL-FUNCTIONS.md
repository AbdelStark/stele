# Model function roles and canonical manifest — Q26

Status: Draft RFC-0004 A3/A10 model association using unchanged Accepted
RFC-0021 §4 function/representation/manifest bytes. Original E5-03 criteria and
blocked status remain unchanged; this is not a complete proof registry.

Question: can every configured norm/attention-exp/SiLU operation retain its
expected FunctionId and RepresentationId while its unique function set derives
the exact canonical manifest with regenerated component data, agreeing with
the native implementation? Security properties are selected-function authority,
role completeness and definition-to-data binding. Cost terms are T_misc and
one-time table preparation; no measured constant or inference weight pass.

Kill criterion, stated before implementation: drop the adapter if it omits or
deduplicates an operation role, adopts a supplied function/data digest, loses
a selected representation, admits a wrong component closure or disagrees with
native full manifest bytes. Reuse the existing manifest contract, not a new
interpretation of its bytes. Keep source/table proof consumers separate.

The implementation decodes and checks the canonical model configuration against a
separately expected identity. In each layer retain norm1, attention_exp, norm2,
silu in that order, then final_norm: exactly 4L+1 roles, at most 513. Select norm
mode 3, configured exponential representation and SiLU mode 0. Derive the unique
sorted function/representation set and complete component closure under RFC-0021.
Generate every component's canonical data before admitting its manifest digest.

Accepted descriptors already limit each component to at most 65536 padded rows
and two columns, including high/low product-exp components. The dense candidate
has at most 4L+1 distinct components: up to three per exp, one per SiLU and one
shared rsqrt. Derive/check these static limits before generation. Do not impose
an observed-data bound or mistake the B-bit exp domain for a 2^B materialization.

The research frame binds the expected configuration identity and
ordered operation FunctionId/RepresentationId references to the unchanged
manifest bytes. This is not the full cqis_id, artifact identity or table-root
record. Range/selector functions must come from real reduction lowering; table
code choices/tree ids need a verifier-owned proof plan. RoPE remains its Draft
A7 definition, not an invented RFC-0021 FunctionId. Actual source/gain/range/
lookup/branch consumers, native inference and fidelity remain mandatory.

## Selection and exact framing

`selection` derives every operation reference from the checked Config. Norm
functions encode the exact d/F/G/E/en/ed tuple in RFC-0021's thirteen parameter
bytes. Ordered roles are `layer.i.norm1`, `layer.i.attention_exp`,
`layer.i.norm2`, `layer.i.silu`, followed by `final_norm`. Identical functions
retain every role; only the unique manifest function set is deduplicated.
The derived set must equal the existing configuration's selected representations.
Conflicting selections for one FunctionId reject. Complete component closure
and its sorted TableId order are inherited from the Accepted manifest contract.

The outer domain is ASCII `stele/research/q26/model-functions/v1` plus NUL
(38 bytes), followed by expected config identity[32] and u16 role count. Each
role contains u16 ASCII name length, the name, FunctionId[32] and
RepresentationId[32]. A u32 manifest length and the complete unchanged RFC-0021
manifest finish the frame. All integers are little-endian. There is no padding,
unknown role, deduplicated role, extension or trailing data. Validation checks
the supplied type/size, checks the expected config identity, regenerates the
entire expected frame and compares every byte. Supplied fields select no authority.

The identity is configuration-only: learned weight/gain values do not select
functions. Configuration still identifies physical tensor roles, so a valid
role swap changes this frame even when selected functions and manifest coincide.
An artifact commitment is separate. Equal nearest-exp outputs under direct and
corrected representations do not make their representations interchangeable.
RoPE and actual source/range/table reductions remain explicitly outside this set.

## Static resources and native comparison

For L<=128 layers, there are exactly 4L+1<=513 roles and at most that many
unique functions. Components comprise one shared rsqrt, at most L SiLU tables,
and at most 3L exponential tables, hence at most 513. Each selected component
has at most 65536 padded rows and exactly two columns. These shape limits are
checked before generation; B=31 product exp uses bounded high/low components.
At the conservative maximum, complete generation traverses at most 67239936
padded scalar entries; this is a static work bound, not an observed value.

Function, representation and table-descriptor envelopes are at most 128/192/128
bytes. The manifest therefore has at most 25+8+513*(4+128+192)+513*(2+128+32)
=249351 bytes. Role names are capped at 64 bytes, so the complete outer frame
has at most 38+32+2+513*(2+64+64)+4+249351=316117 bytes, within the 1 MiB cap.
The builder joins bounded chunks once; it does not repeatedly copy a growing
outer frame. Existing table generators and their fixed research cache limits
remain in effect. No arbitrary supplied row count or data hash drives generation.

The native `function_manifests` example reads bounded test selections and calls
the unchanged `stele_cqis::functions::Manifest::new`. Input is u16 count<=513,
then u16-length function descriptors<=128 and representation frames<=192. Lengths
are checked before payload reads; the selection vector reserves fallibly.
Each result is the full canonical manifest in hex or the native rejection.
It accepts no row-data or data-digest authority and changes no native library API.
This executable is parity plumbing, not a native model or inference verifier.

## Tests and scope

Run `uv run --locked --script research/cqis-checkpoint/check_causal_model.py
--model-functions`, or `--model-function-controls`. The initial test file had a
syntax typo; after correction it failed with the missing adapter module before
implementation. The maximum distinct-function fixture also had to derive its
block drop when changing exp precision; its invalid intermediate configuration
correctly rejected with BlockBound. No implementation check was weakened.

The metadata corpus varies model dimensions/layer counts, norm precision and
canonical epsilon over 10000 configurations. An explicit struct oracle checks
norm parameter bytes and every ordered reference, selected function set and
component shape/closure. A separate 128-layer metadata case exercises 513 roles,
513 distinct functions and 513 distinct components without claiming that its
entire table data was generated in that metadata test.

Complete manifest/frame cases cover direct exp, corrected nearest exp, product
exp, maximum B=31 product exp, the pinned function choices, and 128 layers with
repeated functions. Independent outer framing and complete regenerated table-data
digests are checked, then full native manifest bytes must agree. Native empty-set,
duplicate-function and whole-table-overflow cases exercise distinct outcomes.
Inner certified table generators and configuration fixtures are shared and
explicitly disclosed; their existing per-operation corpora remain separate.

Controls rebuild framing after omitting/duplicating/reordering operation refs,
replacing a function/representation or role, omitting a manifest function,
altering a component data digest, truncating or extending frames, and changing
outer identity/count/length bytes. Equal norm functions cannot erase roles.
Different expected configurations reject old frames even when their inner
function sets coincide. Bad expected identities/types/capacities reject before
function-data admission. These research controls earn no production NC credit.

The pinned baseline retains all nine operation roles and three unique functions
with three components. Its unchanged manifest is 733 bytes, SHA256
`2fd8f1478871e8c6bceb4d0e4a2b495aceb9beb976cc5c98679849e4692ae0c2`.
The model frame is 1531 bytes, SHA256
`401fe1faf4ea56d564b88bf0c5a4132e211339e7f4d71220c8263654deec3afb`.
These are serialization/correctness measurements, not performance results.
The checkpoint checker retains the exact checked Config for native manifest
comparison, rather than rebuilding selected representations from numerical state.
All prior baseline and separate block-variant fixture fields remain unchanged.
The new outer identity describes the baseline configuration only.

## Recommendation

Continue Q26 with the symbolic source/range/branch/index claim graph and complete
plan lowering. Actual function lookups must consume the configured tables and
selectors; canonical table data alone does not authenticate any witness row.
RFC-0011 A2 code identities/tree ids/roots must be derived from a verifier-owned
plan, not invented by this adapter. Range functions selected by lowering are
not part of this neural-function set. Full native inference, fidelity, private
PCS/ZK/FS and supported architecture coverage remain required.

Data regeneration and exact validation are one-time preparation work in T_misc;
there is no fitted constant, inference weight-pass change, cut or random loss.
The Python validator regenerates the expected complete manifest/frame, retaining
existing bounded numerical caches. The native manifest generates component data
in sequence; no new streaming, succinct verification or performance claim is made.

The successful seed2661 metadata corpus retains 89996 operation references;
its frozen SHA256 is
`d5ded583511f94d2e7e5972966e0da8d6110ad6d8584ab1f3379f088af7d0feb`.
The six complete model frames have combined SHA256
`b0c345912fe50df2391aefe89a9776b5b247a654e71423f4f35941e3460bd7cd`.
All nine native cases agree, including the empty set and two explicit rejections;
220 selected byte mutations reject. The pinned full/cache/greedy replay passes
with exact native manifest agreement and every prior fixture field preserved.

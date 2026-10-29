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

Candidate: decode and authenticate the canonical model configuration against a
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

An explicit research frame will bind the expected configuration identity and
ordered operation FunctionId/RepresentationId references to the unchanged
manifest bytes. This is not the full cqis_id, artifact identity or table-root
record. Range/selector functions must come from real reduction lowering; table
code choices/tree ids need a verifier-owned proof plan. RoPE remains its Draft
A7 definition, not an invented RFC-0021 FunctionId. Actual source/gain/range/
lookup/branch consumers, native inference and fidelity remain mandatory.

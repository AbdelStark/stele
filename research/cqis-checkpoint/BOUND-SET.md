# Scoped model arithmetic record collection — Q26

Status: Draft RFC-0004 A3/A6–A10 evidence. All original E5-03 criteria and
blocked status remain unchanged. This is not a complete proof-plan contract.

Question: can the twelve existing arithmetic record families form one closed,
canonical collection derived from independently expected configuration and
artifact identities, without omission, duplication, reordering or adoption of
supplied record metadata? Security properties are complete scoped membership,
static authority and preservation of model/representation/source identity.
Preparation and collection validation belong to T_misc/T_witness.

Kill criterion, stated before implementation: drop this candidate if a legal
model role is omitted/deduplicated, a different source/configuration/representation
can reuse the same framed collection, runtime magnitudes tighten any record,
a supplied frame selects its own schema or identity, or resource limits depend
on untrusted record lengths. Do not claim source/table proof authentication.

The implementation reconstructs the bounded numerical model using the existing loader
from separately expected configuration/artifact hashes, then derives every
unchanged record through its closed family adapter. Retain both expected hashes
in the collection. Runtime Model alone is insufficient because it loses physical
source labels, function representations and exact rotation descriptors. No
unvalidated artifact exponent or source-observed bound may choose a record.

The family order is scaled-linear, row, rotary, residual, greedy, attention sum,
attention normalization, attention block, attention score, attention maximum,
gated product, RMSNorm. Within each family retain its existing model-role order.
For L layers and B block-mode layers, count is 25L+B+5, at most 3333. Records
are keyed by family and role, since row/rotary query/key role strings overlap.
Identical bytes retain every role. All schemas remain unchanged; only RMSNorm
uses Accepted RFC-0022 bytes in this collection, the others remain Draft.

The frame is a distinct research domain plus expected config/artifact
hashes, u32 record count and entries containing u8 closed family id, u16 ASCII
role length/name and u32 record length/bytes, all little-endian. Cap each name at
64 bytes and record at 8192; the complete frame is bounded by 32 MiB. Validation
regenerates the expected collection and compares exact bytes, never parses a
supplied count into trusted roles. Existing loader preallocation limits remain.

Function component
manifests/data roots, symbolic source/range/branch/index consumers and full plan
lowering remain separate. Config-selected function representations are preserved
by the expected config identity, not admitted as table bindings. RoPE's Draft
function definition must not be relabelled as an existing FunctionId. This work
introduces no challenge, loss, cut, proof weight pass or measured constant.

## Exact format and authority

The domain is ASCII `stele/research/q26/model-bounds/v1` plus NUL. It is followed
by the expected 32-byte configuration identity, expected 32-byte artifact digest
and little-endian u32 count. Each entry is u8 family id, little-endian u16 ASCII
role length, exact role bytes, little-endian u32 record length and exact record
bytes. Family ids are 1 through 12 in the order above. No alignment, padding,
unknown family, record alias, count extension or trailing bytes is permitted.
The complete expected frame is regenerated from checked source objects.

| Family id | Existing adapter | Count |
|---|---|---:|
| 1 | scaled-linear | 7L+2 |
| 2 | row conversion | 7L+1 |
| 3 | rotary | 2L |
| 4 | residual | 2L |
| 5 | greedy | 1 |
| 6 | attention sum | L |
| 7 | attention normalization | L |
| 8 | attention block | B |
| 9 | attention score | L |
| 10 | attention maximum | L |
| 11 | gated product | L |
| 12 | RMSNorm | 2L+1 |

The 103-byte header and at most 3333 entries, each at most 1+2+64+4+8192=8263
bytes, imply a maximum of 27540682 bytes, below the enforced 33554432-byte cap.
The existing canonical loader checks descriptor bounds, per-tensor/per-block/
aggregate element caps and rotation-generation caps before materialization.
This implementation reuses that loader, including its research-scale limits.
No record length or count supplied for validation controls an allocation or loop.
An oversized supplied frame rejects before the expected frame is generated.

Expected configuration and artifact identities are separate caller inputs.
The loader checks the canonical configuration identity, its physical Spec set,
exact expected artifact length/digest and each canonical physical record, then
regenerates rotations. Scaled-linear exponents therefore come from validated
model bytes. Actual input activations, gains, codes and channel mantissas never
tighten these bounds; physical content changes still change the framed artifact
identity. Config changes likewise remain visible even if execution is identical.
Matching self-selected hashes is not authentication of external provenance.

This is a scoped static-template collection for the dense candidate, not every
range/lookup/branch/index reduction instance of a proof. A shared per-layer
attention template does not authenticate individual heads, GQA groups, positions,
masks or blocks. Tied embedding/head roles retain distinct operation entries
while the canonical configuration points both to the same physical record.
The frame is not the Accepted cqis_id, a passport, table-binding record or
receipt. It changes none of the inner encodings or arithmetic lemmas.

## Tests and pinned evidence

Run `uv run --locked --script research/cqis-checkpoint/check_causal_model.py
--bound-set`, or `--bound-set-controls` for attacks. Tests were written first
and failed with the missing collection module. The outer struct encoder and
explicit family/role coverage oracle are independent of the collection code;
inner adapters and canonical loader are deliberately shared and retain their
existing separate primitive/model coverage. No new independent numerical or
native collection parity is claimed.

The seed2657 corpus has 256 varied models and 14310 records. It covers one to
three layers, both weight formats, tied/untied heads, static/dynamic row choices,
varied norm units/gain precision, optional rotations and exact/block attention.
Largest ordinary frame is 96592 bytes. The separate 128-layer block-mode case
has all 3333 required entries and 3876218 bytes. Frozen corpus SHA256:
`cfa53be38034d7da5dcc18ce24eb95bfee21010875303f4367ba0eda4757ef13`.
These are serialization sizes and correctness checks, not performance results.

Controls rebuild complete framing after omitting, duplicating or reordering
entries, changing families or roles, or deduplicating equal norm bytes. All
reject with BoundSet, including collisions between row/rotary query roles.
A further 566 one-byte mutations cover the complete outer header, every entry
family/length field and seeded content positions, with truncation/suffix/type
and resource-cap controls. The validator never adopts mutated embedded hashes.

Distinct selected exponential representations, swapped gain-source roles and
rotation bases at width two can yield the same numerical Model and identical
inner records. Their expected configuration identities and collection frames
must still differ. Source gain/code/mantissa mutations leave inner records
unchanged but alter the artifact scope. A weight exponent change alters the
corresponding scaled record as well. A product-exponential selection can also
share static records without sharing configuration identity. Old-scope frames
reject for the new expected inputs; old expected hashes reject changed sources.

The pinned checkpoint adds 55 entries totaling 66060 bytes with checksum
`444e793d18d33fbdad4dfb281bb58825fd0d9e9dd89c88eb3263beb33163a712`.
Every prior baseline and separate block-variant fixture field is preserved.
The collection describes the exact baseline configuration; its identity is
not reused to describe the separate block variant's semantics.

## Recommendation and costs

Continue Q26 with explicit function/component registry data binding and the
symbolic source/range/branch/index claim graph. The canonical configuration
retains selected representations and rotation definitions, but this collection
does not authenticate their table contents, reduction selectors or sources in
an actual proof. Complete native inference, architecture/fidelity scope and
private PCS/ZK/FS consumers remain open; original controls receive no credit.

The current research implementation reconstructs the bounded model on each
collection derivation, scanning physical data and regenerating rotations. It
also retains model arrays, all record bytes and the joined frame. Validation
regenerates this whole expected frame; it is not a streaming verifier or a
performance optimization. This is preparation/validation in T_misc/T_witness,
with no changed fitted constant, inference weight pass, intermediate cut or
probabilistic soundness term. Native graduation still needs its full contract.

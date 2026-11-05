# Native Map and Preparation — E5-03

Same-author `cqis-numerics` and `soundness-auditor` review of RFC-0025
encoding §§2–3. Native SourceMap and Preparation now check complete metadata.
Original file/container validation, raw alias equality, source conversion,
Artifact validation and the assigned controls remain E5-03 delivery work.

Map has one entry for every physical ordinal derived from Shape. Its parser
checks exact UTF-8 names, scalar formats, source ranks/dimensions and complete
u64 byte lengths. Copy, transpose and fused Q/K/V transforms are closed by
physical role. Token and position cannot select transpose. Fused matrices and
biases retain their different source shapes and prescribed part numbers.

A sorted index of selected names checks all uses of each source together.
A fused name requires precisely three matching dtype, shape, transform and
layer entries with all three parts. Other names occur once. The optional
GPT-2 alias targets token record zero and cannot overlap a selected name;
Llama cannot add an alias. Ignored names are strictly sorted by raw UTF-8 bytes
and disjoint from both sets. Actual container names and raw alias bytes still
need validation against this expected metadata.

Map borrows immutable Rust slices; safe callers cannot alter those bytes while
the map exists. It returns no partial checked map on any failure. The 16-MiB cap
is checked first. Physical entry counts come from Shape, and ignored counts
must fit the remaining bytes before allocation. The ignored reference array
is bounded by `(16 MiB / 3) * size_of::<&str>()`; every vector allocation is
fallible. Source tensor contents are not loaded or admitted by this interface.

Preparation checks Map.Shape against the complete expected Model and derives
every C_i from its physical ordinal, dimensions and configured format. Parsing
compares the entire expected configuration sequence and requires exact EOF.
Its 17-MiB cap covers the maximal Map and 2052 configurations. The identity
hashes only the canonical Preparation fields, while a separate Model identity
records the object against which those fields were checked. Original source
hashes and runtime Model fields are not silently added to quantiser_id.

Independent fixtures cover 68 valid metadata configurations, including the
original named geometries and both maximum shapes, plus 67 malformed maps.
Tests compare every entry and complete Preparation bytes/identity. Controls
cover every truncation of a representative complete Map and Preparation, every
physical configuration byte, wrong expected identities and wrong Model shape.
Unicode normalization is not applied; distinct exact UTF-8 names stay distinct.
These fixtures confer no original-checkpoint or numerical-conversion credit.

## Workflow 03

1. SourceEntry and SourceMap implement encoding §2; Preparation implements §3.
2. No random challenge, transcript absorb or challenge order changes.
3. No proof claim is emitted. Source ownership, conversion and Artifact/passport
   consumers remain required at their separately specified boundaries.
4. Unit controls reject individual name, shape, role, part, alias and configuration
   changes. No assigned NC id or actual source-binding edge is marked complete.
5. No soundness-accounting line changes because no random challenge or query is
   introduced.
6. The static Bounds collection remains unchanged. Source metadata cannot select
   a different Model operation order or supply a witness-dependent certificate.
7. The complete physical set and full fused partitions remain mandatory; ignored
   names do not authorize missing parameters or bypass container coverage.
8. Canonical byte order and integer fields determine both identities. Sorting is
   used only to validate complete name groups; encoded entry order is unchanged.
9. Native/reference metadata parity passes at the stated dimensions. GPU parity,
   original checkpoint conversion and inference are not claimed.
10. Parsing and preparation remain T_misc. No online weight pass or measured
    cost-model constant changes; no performance result is asserted.
11. The crate remains `no_std` and forbids unsafe code. Reads, full scalar byte
    products and allocations are checked; complete frames must be exhausted.
12. Existing Shape, Map, Preparation, physical role and source vocabulary is used.

I tried to break it by altering fused parts, crossing layers, reusing source
names, adding forbidden aliases and changing physical configurations, and the
control tests rejected it at the specified metadata boundaries. This same-author
review does not approve the unfinished E5-03 task PR.

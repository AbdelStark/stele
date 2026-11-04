# Native Artifact streams — E5-03

Same-author `cqis-numerics` and `soundness-auditor` review of RFC-0025
encoding §3. Artifact now has complete native structural validation and
bounded emission. Source/container validation, source-dependent minimal scales,
exact conversion, assigned controls and original-checkpoint qualification remain
required before E5-03 is complete.

ArtifactLayout derives every record, configuration, element count, payload length
and global address from the checked Model. All size products and address additions
use checked u64 arithmetic. Its final extent is strictly below 2^39; there is no
former research element cap or metadata-sized whole-Artifact limit. Layout is
explicitly metadata only and cannot construct a completed Artifact.

Both streaming paths first join complete Preparation and Scales to the exact
Model. Preparation and Artifact share the canonical C_i encoder; regression
fixtures verify that Preparation bytes and identities remain unchanged. Supplied
counts and lengths are compared against expected bytes and never allocate a
payload buffer or choose a record. Every scale exponent and original channel
mantissa is checked or emitted in physical order.

Input and output chunks are at most 65536 bytes. Two fallibly allocated buffers
of that size handle expected scale bytes and actual stream bytes; the record
layout is bounded by the checked physical count. Payloads are neither retained
nor copied into whole-model storage by the implementation. Short reads retain
the full expected extent. Int8 -128 and either int4 nibble equal to -8 reject.
Only an odd complete int4 payload has one final high padding nibble; row and
chunk boundaries introduce no padding. All int16 patterns remain structurally
legal, with conversion overflow checked by the separate source converter.

The consumer checks EOF after the final Artifact byte. The producer also checks
EOF on each expected physical payload stream. Both compare the complete byte
count with the derived layout before returning a completed identity. Any reader,
writer, code, padding or exhaustion error returns no Artifact. A successful
writer acknowledgement identifies emitted bytes but does not establish later
storage integrity or a commitment to those bytes.

Independent fixtures cover 34 complete artifacts with both families and mixed
formats, plus one generated complete artifact whose token tensor has 5,242,880
elements. The latter exercises emission and validation beyond the former 2^22
element cap without storing a large payload fixture. Two cases cross 64-KiB
boundaries in both scales and payloads, including odd-width int4 rows and an odd
final element. Separate named/maximal layout fixtures check every address at
GPT-2-small, Llama-3.1-8B and both maximum shapes. They confer no full-checkpoint
conversion or inference credit.

Controls mutate every header/configuration/scale byte in a representative
artifact; omit and duplicate every record; truncate at record/payload boundaries;
and substitute the input identities. They reject forbidden codes, final padding,
oversized read results, premature EOF, suffixes and read/write failures. A legal
changed code remains structurally valid and changes digest_cqis; checking the
old expected digest rejects only after complete validation.

## Workflow 03

1. ArtifactRecord, ArtifactLayout and Artifact APIs implement encoding §3.
2. No challenge, transcript absorb or challenge order changes.
3. No proof claim is emitted. Conversion, source ownership, actual storage and
   Artifact commitment/hash consumers remain independently required.
4. Unit controls cover structural byte and input joins. No assigned NC id or
   actual proof-level claim-graph edge is marked complete by codec tests.
5. No soundness-accounting line changes: no new random challenge or query exists.
6. Bounds derivation remains unchanged. Layout uses static Model dimensions and
   formats, not runtime codes or observed inference maxima.
7. Complete physical records, every channel scale and exact final int4 padding
   remain mandatory. No per-row padding or omitted vector is allowed.
8. Physical order and exact integer encodings determine bytes; read chunk sizes
   do not affect the complete digest.
9. Native/reference bytes and identities match for 35 complete artifacts. The
   four full-size layout checks do not claim GPU parity or original inference.
10. Artifact preparation remains T_misc. No online weight pass or measured
    cost-model constant changes; no performance result is asserted.
11. The crate remains `no_std` and forbids unsafe code. Allocations are bounded
    and fallible, offsets retain u64 precision, and validation requires EOF.
12. Existing Artifact, Preparation, Scales, physical record and digest_cqis
    vocabulary is retained.

I tried to break it by changing metadata and codes, substituting scales, omitting
records, corrupting padding and failing I/O, and the control tests rejected it
at the specified structural boundaries. This same-author review does not approve
the unfinished E5-03 task PR.

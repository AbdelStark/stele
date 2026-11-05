# Native Registry validation — E5-03

Same-author `cqis-numerics` and `soundness-auditor` review of RFC-0025 encoding
§6. This checkpoint supplies complete Registry construction and validation;
the complete quantiser task, original-source conversion, static Bounds and
actual inference/proof consumers remain unfinished.

The expected Model determines every ordered FunctionId/RepresentationId pair,
the unique function/component closure, every layer rotation reference and the
sorted unique rotation definitions. Supplied counts and descriptors never select
what to generate. The crate-private Manifest layout reuses the existing canonical
encoder and records the offsets of data digests. It cannot be constructed or
returned as a public Manifest or Registry.

Validation checks the total length and every metadata segment before entering
the generation loop. Only the derived 32-byte data slots are omitted from that
first comparison. Each slot then receives a digest of its complete native table
or rotation generation. Invalid precision, full-table overflow or a mismatched
digest prevents construction of the public Registry. No caller can supply a
table-truth callback, populated cache or successful partial record.

All reservations derive from checked Model/Manifest bounds. Function,
component and rotation limits remain 514, 516 and 128; Manifest and Registry
caps remain 256 KiB and 1 MiB. An already generated Registry can compare exact
bytes without regenerating data. Its private fields preserve that provenance;
its content hash still needs independent outer authentication.

The independent fixture generator calls qualified pure framing and Arb data
oracles, without invoking historical campaign mains. Six complete records cover
both families and direct/product/corrected exp representations, nonzero
corrections, fractional activations and full rotary digests. Four additional
fixtures compare only the complete named/maximal metadata layouts. They are
explicitly not full-data qualification for those shapes.

Tests reject every changed metadata byte before data checking, truncations,
suffixes, oversized input, a changed Model with the same shape, a changed
expected Registry identity, each supplied component/rotation digest and a
complete activation-table overflow. Existing Manifest, function and LayerNorm
fixtures retain their exact bytes. The stdin/stdout parity adapter accepts a
complete independently framed record and rejects malformed input frames.

Full named-geometry qualification is separate from the bounded tests. The
`qualify_named_registries.py` runner compares the complete native result with
independent full Arb regeneration, records source/binary/artifact hashes, and
rejects incomplete output or source changes. Llama's full configured rotation
has 8,388,608 pairs. This is a numerical Registry qualification configuration,
not an original-source identity, fidelity preset or performance benchmark.

## Workflow 03

1. Public Registry APIs implement RFC-0025 encoding §6. The example is a binary
   parity adapter for that same API, not a proof-admission entry point.
2. No challenge, transcript or absorb order changes.
3. No field claim is emitted. Bounds, the complete numerical identity, passport
   and actual public-MLE/proof consumers still need the resulting Registry.
4. Structural, digest and generation-failure tests exercise the native boundary.
   Assigned E5-03 NC controls remain required with their complete actual consumers;
   this checkpoint claims no new catalogue coverage.
5. No soundness-ledger line changes.
6. Registry validation does not derive arithmetic Bounds or admit an operation.
   The complete nineteen-schema collection remains required.
7. Native component generation includes all real rows and canonical zero padding;
   rotary data has no padding. Proof masks/selectors remain separate consumers.
8. Raw-identity sorting, operation order and complete generation are deterministic.
   No hash-map iteration or timing-dependent order selects bytes.
9. Complete numerical reference parity passes on bounded fixtures. Full named
   generation is recorded separately. GPU and proof-byte parity are not claimed.
10. No online weight pass or measured cost-model constant changes. No performance
    result is claimed without a benchmark ledger entry.
11. The crate remains `no_std`, with checked lengths, fallible reservations and
    private checked states. Construction returns no partial Registry on failure.
12. Names retain Model, Registry, Manifest, FunctionId, RepresentationId,
    Rotation and component vocabulary.

I tried to break it by substituting metadata, ordered references, Model identity
and data digests, and by selecting an overflowing complete table, and the control
tests rejected those changes at their stated structural or generation boundary.
This same-author review does not approve the unfinished E5-03 task PR.

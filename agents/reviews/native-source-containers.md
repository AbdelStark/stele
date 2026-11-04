# Native safetensors structure — E5-03

Same-author `cqis-numerics` and `soundness-auditor` review of RFC-0025 source §2.
SourceContainer reads the original header through a completed SourceSnapshot.
Every header chunk is revalidated, including bytes beyond the first chunk.
Only complete structural metadata escapes; index/package selection, raw aliases,
SourceConfig semantics, exact conversion and original source authority remain due.

The parser checks the eight-byte header length against the 100000000-byte cap
and original file extent, then requires the initial opening brace. Strict UTF-8
and nonrecursive closed JSON grammars reject duplicate decoded keys, unknown or
missing descriptor fields, nonstring annotations, floating/Boolean integers,
nonfinite JSON tokens and unpaired surrogates. Integer -0 is accepted as zero,
matching the qualified parser. Names are decoded without normalization.

All nineteen structural storage dtypes retain their exact bit widths. Scalars
and empty tensors are legal, including full u64 dimensions in zero-sized shapes.
Shape products and bit counts are checked in their original order. Every span
must match its integral-byte size, remain inside the original payload and join
the complete dense coverage with neither overlaps nor holes. Empty spans obey
the same start/end/name order. Returned tensor metadata is sorted by decoded
UTF-8 name and contains absolute original-file offsets. Raw nonfinite floating
payloads remain structurally legal; selected conversion must reject them.

The caller admits a conservative sum of requested metadata allocation bytes.
That sum includes the original header, decoded strings, vector growth and freed
temporary keys/annotations; no refund makes the limit less conservative.
All allocation requests are fallible and charged first. Allocator rounding and
bookkeeping are outside the logical budget. Each snapshot read uses at most
65536 additional bytes; only one such chunk is retained at a time. A chunk crossing
the header boundary includes payload bytes. Header bytes are dropped after parsing;
returned metadata retains no payload. There is no element-count cap.

The fixture generator calls only the qualified source.parse helper, without
running a historical campaign. Its 108 cases include 62 valid containers and
46 malformed ones: all nineteen dtypes, empty/scalar tensors, shuffled records,
seeded shapes, original annotations, escaped/raw Unicode and header/chunk
boundaries. Tests compare every dtype, shape, offset and extent. Controls also
check metadata budget failures, short reads, first/later read errors and changed
snapshot chunks. The initial duplicate-key control caught a rejection-reason
mismatch; duplicate tensor keys now reject before span coverage validation.

## Workflow 03

1. SourceContainer and SourceTensor implement complete structural source §2 checks.
2. No challenge or transcript absorb changes.
3. Metadata exposes no payload or proof claim. Every consuming payload pass must
   use the same verified snapshot; complete package and conversion remain required.
4. Source containers reject malformed single-field descriptors, duplicate keys,
   coverage changes and mutated header bytes. No production NC id is completed.
5. Header reads use the existing snapshot replay SHA-256 inventory. No new hash
   family, algebraic loss or ledger formula is introduced.
6. Structural products use checked u64 arithmetic, never observed witness maxima.
7. Complete declared payload coverage includes ignored/empty tensors. Selection,
   alias equality and scalar finiteness remain separate mandatory checks.
8. Original bytes are hashed by the snapshot; JSON is never reserialized into a
   replacement source identity. Sorting is deterministic and allocation-free.
9. Native metadata and specified rejection reasons match the independent fixtures.
   Named-model, inference and CPU/GPU proof parity are not claimed.
10. Parsing remains preparation T_misc; no measured constant or online weight pass.
11. The crate remains no_std and forbids unsafe code. Fixed JSON grammar depth,
    checked offsets and explicit fallible metadata admission bound this parser.
12. Existing source/container/tensor/shape/offset vocabulary is retained.

I tried to break it by changing one header byte after complete-file validation,
and the control rejected it with SnapshotData before metadata escaped. This
same-author review does not approve the unfinished E5-03 task PR.

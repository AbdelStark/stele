# Native Source and Assets frames — E5-03

Same-author `cqis-numerics` and `soundness-auditor` review of RFC-0025 source
§§1,3. Native Source and Assets now validate complete declarations. Actual
whole-file hashing, complete container/index/selection checks, raw alias equality,
SourceConfig semantics, conversion and original-model qualification remain required.

SourceFile borrows exact UTF-8 names and declared SHA-256 words from immutable
frame bytes. Basenames reject emptiness, NUL, path separators and exact dot/dot-dot
labels. No normalization or filesystem access is performed. Full u64 file lengths
remain metadata; they never size an allocation or imply a file has been read.

Source distinguishes a single safetensors file from an indexed bundle. Kind 1
requires an original JSON index and nonempty sorted unique safetensors shards.
The index's 100000000-byte limit, shard count bound and aggregate shard-name
bound are checked. Every original file length, including the index, participates
in a checked u64 sum. Kind 0 has exactly one file and no inactive index bytes.

The typed checkpoint identity is exactly kind plus the declared original-file
SHA-256 for kind 0, or kind plus H(Source) for kind 1. The separate frame_identity
always hashes the full Source. `decode_expected_frame` explicitly checks that
full-frame identity, including labels. Tests show why renaming a single file
preserves its typed identity while changing the Source frame; indexed renaming
changes both. These checks do not authenticate a publisher or actual file bytes.

Assets requires one JSON config, nonempty sorted unique tokenizer declarations
and the exact optional generation tag/body. Config, tokenizer and generation
labels cannot overlap. Their full aggregate length is checked before returning
assets_id. The expected adapter still determines the required role set and must
consume the same original config/tokenizer/generation bytes; supplied metadata
cannot establish that semantic completeness.

Both 512-MiB frame caps are checked before parsing. A supplied file count must
fit at least 43 remaining bytes per File before fallible vector allocation;
Source applies its additional index-derived count bound. Names and hashes stay
borrowed. Complete exhaustion is mandatory, and no partial declaration escapes.
Joint checkpoint/auxiliary label and aggregate-length checks remain part of the
pending complete package validator.

Independent fixtures cover 66 valid Source/Assets pairs and 39 malformed frames.
They include the maximum 65535-byte basename, exact u64 maximum file/aggregate
lengths, both Source kinds, generation presence, exact Unicode labels and all
declared file fields. Tests also truncate every byte of representative frames
and reject changed externally expected hashes. These are metadata fixtures,
not evidence that maximum-length or original named-checkpoint files were loaded.

## Workflow 03

1. SourceFile and Source implement source §1; Assets implements source §3.
2. No random challenge, transcript absorb or challenge order changes.
3. No proof claim or tensor view is emitted. Complete actual package validation,
   source authority, conversion and passport consumers remain required.
4. Unit controls reject malformed names, counts, order, role collisions, length
   overflow, suffixes and hash joins. No assigned NC id is marked complete.
5. No soundness-ledger line changes: no random challenge or query is added.
6. Static numerical Bounds remain unchanged; file declarations cannot supply
   runtime maxima or alter physical Model roles.
7. Complete declared file lists and optional-field rules are enforced. Actual
   tensor coverage, ignored-buffer checks and source aliases remain mandatory.
8. Exact bytes determine all hashes. Sorting is checked, never normalized into a
   different accepted encoding; single-file and bundle identities stay distinct.
9. Native/reference frame and identity parity passes for the stated fixtures.
   Original checkpoint, GPU, inference and proof parity are not claimed.
10. Metadata parsing remains preparation T_misc. No online weight pass or measured
    cost-model constant changes; no performance result is asserted.
11. The crate remains `no_std` and forbids unsafe code. Reads and aggregate sums
    are checked, and bounded file-list allocations are fallible.
12. Existing File, Source, Assets, index, shard and typed checkpoint vocabulary
    is retained; SourceFile names the Rust representation of a File descriptor.

I tried to break it by changing kinds, names, counts, ordering, role membership
and aggregate lengths, and the control tests rejected it at the specified frame
boundaries. This same-author review does not approve the unfinished E5-03 task PR.

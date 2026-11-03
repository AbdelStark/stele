# RFC-0025 typed source and auxiliary files

Status: Accepted. Part of [RFC-0025](RFC-0025-full-model-cqis.md), Q26/E5-03b,
and RFC-0011 A8. These records bind original file bytes. They do not establish
publisher authority, source conversion, tokenizer semantics or a proof source.

## 1. Closed file and source frames

Use the encoding appendix's little-endian integers and unkeyed BLAKE3-256 H.
A File is `u16(name_length) || UTF8(name) || u64(length) || SHA256(bytes)[32]`.
Names are exact nonempty UTF-8 basenames of at most 65535 bytes, without NUL,
slash, backslash, normalization, `.` or `..`. Labels never authorize filesystem
access or model-code execution. Hash every original byte, including headers,
annotations, whitespace and padding; never hash a reconstructed JSON object.
Each file length and the aggregate file length fit u64.

    Source = ASCII("stele/v0.1/cqis/source") || u8(kind) || body
    kind 0 body = File(single safetensors)
    kind 1 body = File(original index) || u32(shard_count) || File[shard_count]

Kind 0 has exactly one `.safetensors` file and no index. Kind 1 has a `.json`
index and a nonempty unique shard list sorted by raw UTF-8 basename; every
shard ends in `.safetensors`. The index name is distinct from shard names.
Unknown kinds, inactive fields, duplicate/unsorted names and suffixes reject.
The complete frame is at most 512 MiB. Index length is at most 100000000 bytes.
Shard count is at most index_length/16, and total shard-name bytes at most
index_length: each distinct filename must occur in an index entry. These loose
structural bounds cover the complete index grammar before any record allocation.
Together with 42 framing/hash bytes per File and the index File, they bound
Source below 363 MiB, independently of checkpoint payload size.

The typed checkpoint identity is exactly 33 bytes: kind 0 followed by the
original single-file SHA-256, or kind 1 followed by H(Source). The latter is
a bundle identity, never a single-file digest_hf. Index name/bytes, shard names,
lengths, contents and partition all participate in the bundle identity.
For kind 0 the filename is in Source but does not change the file's SHA-256.
The complete passport must authenticate both Source and its derived typed
identity, together with the expected Map/Preparation, Model and Artifact.

## 2. Complete container and selection checks

The supplied file set must equal Source's exact expected labels, including the
index for kind 1. Compare every actual length and whole-file SHA-256 before
returning tensor views. The expected Source itself requires independent
authentication; describing supplied files does not provide that authority.

Retain the pinned safetensors v0.6.2 structural policy from the
[source study](../../research/cqis-checkpoint/SOURCE.md): bounded u64 header
length, opening brace, strict UTF-8 JSON, duplicate rejection at every depth,
exact tensor descriptor fields, string-only annotations, checked integer
dimensions/offsets/products, integral-byte storage, sorted nonoverlapping dense
coverage and exact file exhaustion. Floating JSON numbers, Boolean integers,
nonfinite JSON tokens and unpaired surrogates reject. Scalar/empty tensors and
all nineteen structural dtype tags retain their defined byte widths. Selected
values use only F16/BF16/F32/F64; actual scalar finiteness is checked by conversion.

The index follows the [shard study](../../research/cqis-checkpoint/SHARDS.md):
exact metadata/weight_map fields, u64 total_size, other annotations strings,
unique keys, nonempty weight_map and exact shard basenames. Every index-assigned
tensor exists in that exact file. Every actual tensor occurs once across all
shards, including ignored tensors; no unindexed or duplicated data is allowed.
Recompute total_size from all payload spans, including ignored tensors, and
compare exactly. No requested shard-size convention limits a physical shard.

Validate the complete expected SourceMap first. Actual tensor names must equal
its selected, alias and ignored name union. Each selected entry has exactly its
declared raw dtype and source shape; fused uses retain their prescribed common
source and complete partition. Each allowed GPT-2 alias has identical raw dtype,
shape and every scalar byte to the original token source before conversion.
Ignored buffers still undergo complete structural, hash and coverage checks.
No name, shape or equality can create an additional physical alias.

## 3. Configuration, tokenizer and generation files

These original files have a separate exact-byte record:

    Assets = ASCII("stele/v0.1/cqis/source-assets") || File(config)
             || u32(tokenizer_file_count) || File[tokenizer_file_count]
             || u8(generation_present) || [File(generation) iff present]

Config is exactly one `.json` file. Tokenizer files form a nonempty unique set
sorted by raw UTF-8 name. Generation is absent or exactly one `.json` file;
the presence tag is 0/1. All names across the roles are distinct. All lengths
and their sum fit u64; the frame is at most 512 MiB. Before iterating a supplied
count, require enough remaining bytes for at least 43 bytes per File. No caller
count or file suffix selects extra fields. Define assets_id=H(Assets).

The independently expected model/text adapter chooses the exact required file
set and generation presence. Verification compares that set, every actual file
length and SHA-256; it cannot infer completeness from an untrusted manifest.
Checkpoint and auxiliary labels are disjoint in the joint source package. The
joint supplied dictionary must be exactly their union, without unused files.
Tokenizer payloads may be binary or textual and are hashed as exact bytes.

This record does not parse config values, choose EOS ids, instantiate tokenizer
code or prove text-to-token conversion. The actual adapters must check family,
dimensions, norm/rotation/decoding choices and every used tokenizer/generation
parameter against these same authenticated original bytes. File identity alone
does not prove that an inference or traffic adapter consumed the file. Those
semantic consumers remain required before full model/statement admission.

## 4. Snapshot, resources and consumers

The research interface accepts only immutable bytes for each file, snapshots
the mapping, checks the complete package and returns read-only tensor slices
backed by those same bytes. It makes no whole-tensor payload copies. Later
changes to the caller's dictionary cannot replace those backing bytes. Mutable
buffers, even read-only views over mutable storage, are not accepted inputs.
No partial set of tensor views escapes a failed check.

This prototype retains entire input files; it is not evidence for native
bounded-memory file loading. A native loader must establish an immutable
snapshot or validate the same bytes during every consuming pass. Hashing one
file and later reading an unchecked mutable replacement is insufficient.
Full-domain checked offsets are preserved; old element-count research caps
cannot restrict a named checkpoint. Header/metadata allocation and I/O failure
remain subject to explicit native resource admission.

Source hashing, parsing and reproducible conversion are preparation T_misc.
No new challenge, cut, profile, measured constant or online weight pass is
introduced. Actual E5 source conversion, E6 owned views, E12-05 passport,
E14-02 commitment/hash and traffic/tokenizer consumers must retain these exact
identities and bytes. Native controls, H/query accounting, private PCS/ZK,
Q12/Q29, fidelity and full inference/verification remain mandatory.

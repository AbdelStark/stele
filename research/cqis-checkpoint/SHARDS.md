# Q26: indexed checkpoint sources and typed identity

Question: how can a checkpoint index and all its safetensors shards determine one
exact source identity while preserving the quantised artifact under repartitioning?
The security properties are exact file-set and tensor-location binding, raw-file
hashes, total payload accounting and separation of single-file and bundle identity.
Kill criteria: a duplicate/unindexed/mislocated tensor accepted, an omitted or
substituted shard accepted, ambiguous manifest bytes, or repartitioning changing
an otherwise identical selected parameter artifact.

This research continues RFC-0004 A3 / RFC-0011. No complete passport, native
streaming source adapter, source-to-commitment proof or profile is admitted.

## Index and exact physical source set

The pinned [Hugging Face serializer](https://github.com/huggingface/huggingface_hub/blob/v0.34.4/src/huggingface_hub/serialization/_torch.py)
writes an index with metadata and a weight_map from tensor names to filenames.
Its [split helper](https://github.com/huggingface/huggingface_hub/blob/v0.34.4/src/huggingface_hub/serialization/_base.py)
tracks total_size and places oversized tensors in individual shards; a requested
shard size is not an upper bound for every resulting file. The candidate validates
actual file contents and lengths, without assuming any particular partition sizes.

The candidate index is UTF-8 JSON of at most 100,000,000 bytes with exactly
metadata and weight_map. Duplicate keys at every depth, floating JSON numbers,
Boolean pseudo-integers and invalid Unicode reject. metadata.total_size is a u64;
other metadata entries must be strings and are not interpreted as tensor aliases.
The nonempty weight_map has fewer than 2^32 distinct exact UTF-8 tensor names.
Each value is a nonempty UTF-8 basename of at most 65535 bytes, ending in
.safetensors, without slash, backslash or NUL. The prototype receives immutable
file bytes by label; it never follows paths or executes model code. A native file
adapter still needs its own bounded access and lifetime contract.

The supplied file dictionary and independently expected SHA-256 dictionary must
both equal the complete set of filenames named by the index. Check the original
index SHA-256 and every original shard SHA-256 against those expectations. No
unused, missing or substituted file is allowed. Snapshot supplied immutable bytes
before hashing/parsing; later dictionary changes cannot substitute other payloads.
The aggregate shard-file length must fit u64.

Parse every shard using SOURCE.md's complete structural checks. No tensor may
occur in multiple files, even with equal payloads. Each file's actual tensor-name
set must exactly equal the names that weight_map assigns to that filename. Thus
an index cannot silently select one copy from duplicate physical parameters.
Recompute total_size as the sum of all serialized tensor payload lengths, including
ignored tensors, and compare exactly; headers are not counted. This is the chosen
physical-size contract, not authority derived from a supplied metadata integer.
Unknown alias/storage conventions need their own explicit contract.

Apply the same exact selected/ignored partition and selected dtype/shape checks
as the single-file adapter. Every selected source value is converted under the
existing offline policy; any selected nonfinite/overflow failure returns no
artifact. No name normalization, implicit alias, transposition or fallback is
introduced. The full authenticated plan still must justify selected roles and
ignored entries; syntactically valid selections can describe the wrong model.

## Bundle manifest and source-kind separation

The complete research bundle manifest is

    ASCII("stele/research/q26/checkpoint-bundle/v1")
    || u64(index_file_length) || SHA256(original_index_bytes)[32] || u32(shard_count)
    || for each shard in raw UTF-8 filename order:
       u16(filename_length) || filename || u64(file_length) || SHA256(original_file)[32].

Lengths are little-endian, with no padding. Index count/filename/length limits make
this framing injective and its metadata length fit u64. Independent struct-based
encoding checks every field and ordering rule. The index hash binds the exact
name-to-file map and all annotations; the file hashes bind complete containers,
not just selected numerical values. The expected digest set still needs trusted
publication/registration provenance; matching self-chosen hashes is insufficient.

Define bundle_id=BLAKE3(manifest). A typed source identity is exactly 33 bytes:
kind 0 followed by the actual single-file SHA-256, or kind 1 followed by bundle_id.
The latter is explicitly not a SHA-256 of one safetensors file. Separate kinds
remain distinct even if the following 32 bytes happen to coincide. Unknown kinds
must reject in the eventual admitted consumer; this prototype emits the two forms
but does not supply that verifier or its canonical outer passport encoding.

The sharded preparation descriptor is

    ASCII("stele/research/q26/sharded-source/v1")
    || u64(selection_length) || SOURCE.md's complete SourcePreparation bytes.

Its BLAKE3 source_preparation_id identifies this index/coverage policy and the
full offline Specs/ignored selection. The actual partition, index and file hashes
are source instance data and do not alter the conversion algorithm identity.
Repartitioning unchanged tensors or reordering index JSON therefore preserves the
quantised artifact and changes bundle identity. Both changes remain observable.
The final quantiser/passport contract must include the typed source, complete
preparation identity and artifact digest under its authenticated outer framing.

RFC-0011 A3 records the required typed-source extension as Draft. The original
single-file SHA-256 obligation is preserved, not silently reinterpreted as a hash
of hashes. Existing commitment-to-artifact, wrapper, privacy and certificate work
remain mandatory. No production registry admission or new catalog-control credit.

## Evidence and recommendation

Run `uv run --locked --script research/cqis-checkpoint/check_shards.py`.
Ten thousand mixed bundles use one to five shards, all four supported source
encodings, int4/int8/wide policies, different shapes and explicitly ignored integer
scalars. Full artifact bytes match unsharded preparation from retained input data.
Independent manifest encoding agrees exactly. The single-file reader's pinned
upstream differential evidence remains the underlying container check.

Negative cases cover missing/extra/substituted files, wrong expected hashes,
mislocated/unindexed/duplicated tensors, wrong total_size, metadata/name errors,
unknown source dtype/shape, invalid basename syntax and duplicate index keys.
Original-index whitespace/order changes produce a new bundle identity while
retaining identical artifacts. These checks are research tests, not production
passport or NC-0109 controls. Counts and correctness hashes are not benchmarks.

The verified tiny-random-gpt2 source is also locally repartitioned into 2, 3, 7 and
64 shards; all 64 tensors are retained. Run the script with
`--checkpoint /path/to/model.safetensors` to verify [the fixture](shard-checkpoint.json).
Every partition reproduces the exact previously recorded complete parameter
artifact digest. These are generated repartitions of the pinned published file,
not a claim that its publisher released those sharded files. No model forward,
fidelity, multigigabyte memory test or ZK proof follows from this integration.

Continue Q26 with complete source/operation/passport identity and closed static
certificate schemas, then native bounded streaming and actual consumers. The
prototype retains full file/tensor data; it establishes no native memory bound or
performance result. Parsing/source hashing/preparation belong to T_misc. No fitted
constant, commitment, FS challenge, soundness-ledger term or inference weight-pass
change is introduced, and the full end-to-end inference objective remains open.

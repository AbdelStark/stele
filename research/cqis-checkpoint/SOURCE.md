# Q26: exact safetensors source adaptation

Question: how do actual checkpoint file bytes, their SHA-256 digest, and explicit
source tensor names/dtypes/shapes determine the quantiser's inputs? The security
properties are unambiguous metadata, complete buffer validation and reproducible
source selection. Kill criteria: overlap/hole/duplicate metadata acceptance, a
source dtype/shape substitution, a source hash computed from reserialized metadata,
or disagreement with the pinned upstream reader on supported ordinary files.

This research continues RFC-0004 A3 and RFC-0011. It does not authenticate a
publisher, admit a passport or prove commitment/source binding. Native streaming,
sharded checkpoints, full source/plan identity and static certificates remain required.

## Container contract and primary references

The [upstream format](https://github.com/safetensors/safetensors#format) describes
an eight-byte little-endian header length, UTF-8 JSON tensor metadata and a dense
payload. Tensor offsets address that payload. It permits empty/scalar tensors,
requires complete coverage without holes and disallows duplicate keys. Raw values
may include nonfinite numbers; container parsing alone does not reject them.

The [pinned v0.6.2 implementation](https://github.com/safetensors/safetensors/blob/v0.6.2/safetensors/src/tensor.rs)
sets a 100,000,000-byte header limit. Its validation orders tensors by offset,
checks element-count/bit-size overflow and requires integral-byte spans, including
four- and six-bit dtypes. The candidate reproduces these structural size checks
with u64 arithmetic, including all nineteen dtype tags from that pinned version.
This does not supply CQIS numerical conversion for every container dtype.

The adapter additionally enforces the format's initial opening brace, unique
keys at every object depth, exact tensor descriptor fields and a string-only
annotation map. Python integer/Boolean distinctions are checked explicitly;
floating JSON numbers, NaN/Infinity tokens and unpaired Unicode surrogates reject.
These are candidate fail-closed input rules, not a claim that every upstream
parser version already enforces them. No parser output can authorize itself as
the selected model configuration. The prototype catches malformed/deep JSON
failures and validates the complete buffer before returning tensor data.

## Exact selected inputs and source hash

The expected Specs retain the preceding record study's name/dtype/shape/policy.
Each selected name must exist exactly once in the actual file and have exactly
its expected dtype and shape. Supported selected encodings are F16, BF16, F32 and
F64, using the exact finite scalar adapters. A selected nonfinite value rejects
preparation. Scalar/empty tensors can be read structurally, but cannot be selected
under the present positive-shape record contract. Other structurally valid dtypes
may appear only as explicitly ignored source tensors, with no numerical admission.

The caller supplies a duplicate-free list of ignored names, disjoint from selected
names. The file must contain exactly the union of those two sets. A new source
tensor cannot silently disappear; a missing selected/ignored name rejects. Names
are exact decoded Unicode strings with no normalization or alias inference.
Selected artifact labels satisfy RECORDS.md's ASCII rule. Ignored labels may be
other valid UTF-8 names, and are sorted by their encoded bytes for identity.
The full authenticated model contract must justify exclusions; merely putting a
required weight in this list would define the wrong model, not prove it correct.

An expected 32-byte source digest is compared with SHA-256 of the entire original
file: eight-byte length, original JSON including annotations/padding, and payload.
A mismatch rejects before parsing. Successful preparation returns that actual
file digest as digest_hf, alongside the derived artifact and its content digest.
The caller must obtain the expected digest from its intended published checkpoint;
matching a self-chosen digest does not authenticate a publisher or registration.
No hash of a source map or reconstructed header replaces the actual file hash.

Reordering annotation keys or changing permitted header padding can leave every
tensor unchanged while changing SHA-256. The candidate accepts either encoding
against its own exact expected hash and produces the same quantised artifact.
Using the other encoding with the first expected digest rejects. Thus raw source
identity and quantised numerical identity remain deliberately distinct.

## Source selection identity

This study adds a separate research source-preparation descriptor:

    SourcePreparation = ASCII("stele/research/q26/source/v1")
                        || quantiser_id[32] || u32(ignored_count)
                        || (u32(name_length) || UTF8(name)) in raw byte order
    source_preparation_id = BLAKE3(SourcePreparation)

All lengths are little-endian. Ignored names are unique, individual lengths/count
fit u32 and the complete descriptor fits u64. The embedded quantiser_id is derived
from the full expected offline Specs/algorithm in ARTIFACT.md, not supplied by
the file. The new version fixes the source-adapter policy above. The actual source
digest is separate instance data; it does not change the algorithm identity.

This descriptor is intentionally separate from the existing research artifact's
v1 quantiser_id. The final Accepted quantiser/passport contract must incorporate
both source adaptation/selection and offline conversion, and bind the actual
source digest and resulting artifact digest. No existing format is silently
relabelled complete. There is no supplied source-to-commitment proof, PCS packing,
codeword proximity, wrapper check or ZK guarantee in this prototype.

Tied embedding/LM roles still need authenticated plan references to the same
physical record; this reader does not duplicate, transpose or guess aliases.
Sharded source files need a complete container/index/digest contract and a separate
implementation; a hash of concatenated shard hashes is not claimed to equal the
SHA-256 of any safetensors file. This remains required for the full model scope.

## Reproducible evidence and recommendation

Run `uv run --locked --script research/cqis-checkpoint/check_source.py`.
Ten thousand pinned-upstream serialized files agree byte-for-byte on extracted
tensor payloads and exactly on dtypes/shapes; selected artifact output matches
preparation from the independently retained input arrays. These files vary all
four supported source formats, shapes, channel axes, int4/int8/wide policies and
explicitly ignored integer scalar entries. Additional fixtures check all nineteen
structural dtypes, zero-size/scalar tensors and non-physical header key order.
No host floating-point arithmetic is needed for this differential test.

Malformed tests cover duplicate keys at each relevant depth, holes, overlaps,
wrong lengths, trailing data, unsupported metadata, dtype/shape substitutions,
Boolean pseudo-integers, overflow, sub-byte misalignment, UTF-8/surrogates,
truncations, excessive header length, selection omissions and source-hash mismatch.
An ordinary source reader accepts nonfinite payloads; selected conversion rejects
them. These are research tests, not production NC-0109 or passport controls.

The initial reproducibility check detected upstream annotation HashMap iteration
order changing raw fixture hashes. The corpus now uses a single annotation key;
explicit two-key fixtures retain both orders to check original-byte hashing.
The fixed corpus, pinned package lock and correctness checksum are reproducible.
Counts/checksums are not benchmark observations or model-fidelity results.

Continue Q26 with sharded/indexed sources, complete authenticated operation/source
configuration and every static certificate schema/consumer. Native bounded parsing,
fallible streaming/resources, Rust parity, actual checkpoint/commitment binding,
full inference/fidelity and privacy remain required. The research reader retains
whole file/array data and makes no streaming memory claim. Preparation/source
hashing belongs to T_misc; no fitted constant, extra inference weight pass,
challenge, soundness-ledger term or admitted profile is introduced.

## Pinned checkpoint integration

The corpus also includes reproducible preparation of every parameter in
[Hugging Face's tiny-random-gpt2 checkpoint at 71034c5](https://huggingface.co/hf-internal-testing/tiny-random-gpt2/tree/71034c5d8bde858ff824298bdedc65515b97d2b9).
The expected raw-file SHA-256 is
`8111d5afb0715dbf5a31396d31432cb56370ba23f6650a035ea0fc8a20b4e500`.
All 64 F32 tensors and 111,968 parameters are checked against fixed fixture shapes
and the upstream reader; none are ignored. Candidate storage uses int8 matrices
with axis 0 for embeddings and axis 1 for GPT-2 Conv1D weights, and int16/F=8 for
all vectors. These are explicit fixture preparation choices, not admitted bias,
LayerNorm, position or other forward semantics. The output artifact has 128,373
bytes; this is an exact encoded length, not a performance benchmark.

Run the pinned script with `--checkpoint /path/to/model.safetensors` to verify
[source-checkpoint.json](source-checkpoint.json). CI downloads the immutable
revision and checks the hard-coded source hash before extraction. No model code
is executed. The integration supplies a complete parameter artifact and metadata
checks, not a CQIS forward pass, fidelity report, full model passport or ZK proof.

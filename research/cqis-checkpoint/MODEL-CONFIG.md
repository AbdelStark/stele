# Q26: causal model configuration and physical roles

Question: can one canonical descriptor select every executed numerical parameter
and physical tensor role, then reconstruct the complete causal model from an
independently expected identity and the validated weight artifact? The properties
at stake are deterministic model selection, source-role association and complete
unit/function binding. Preparation/validation belongs to T_misc/T_witness.
Kill criteria: an omitted choice, an accepted role/shape/source substitution,
two accepted encodings of one descriptor, or reconstructed execution disagreeing
with the original model. Research under RFC-0004 A3/A6–A9; no proof admission.

## Defined model and role selection

`model_config.py` describes sequential dense RMSNorm/SwiGLU blocks and the A9
embedding/final-norm/head boundary. Each physical role contains its complete
RECORDS.md Spec: exact name, source encoding, shape, bits and channel axis/gain
fraction. Matrices are output-channel major, axis zero; gain fractions must equal
their norm's G. Seven block roles are Q,K,V,O,up,gate,down in that order. Shape
checks derive each role from d, hidden size, heads, groups and head width. Names
are globally unique. A tied head is an absent head record and reuses the embedding;
a second record with the same name rejects. No tensor naming heuristic, transpose,
automatic scale choice or implicit architecture operation occurs during loading.

The descriptor includes every runtime policy/unit, exact RMSNorm epsilon, exp
Function/Representation, SiLU Function and certified A7 rotation descriptor.
Norm uses RFC-0021 version 1/mode 3; SiLU uses version 1/direct mode 0. The exp
representation is explicit even when direct/corrected evaluation has identical
outputs. Repeated FunctionIds must select the same RepresentationId. The sorted
unique representation set is derivable without generating table contents. This
does not admit a function manifest, table data digest, lookup or passport.

The configured context length is common to all layers. Absent rotation has width
zero and adjacent layout; no inactive family/angle fields exist. Present rotation
includes its length, family, exact rational parameters and layout, and must fit
the head width. Cross-block/final-norm units must agree. Only contiguous real
positions and causal attention are selected by this version. Greedy EOS and token
limits remain separate request inputs; no sampling or tokenizer is inferred.

## Exact candidate bytes

All integers are little-endian without padding. `B(x)=u16(len(x)) || x`.
`S(s)=B(RECORDS.md Config(s))`; `N(n)=u16(d)||u8(F)||u8(G)||u8(E)||u32(en)||u32(ed)`.
`P(p)=u8(mode)||u16(scale)`, dynamic=0/static=1, with dynamic scale zero.

    Model = ASCII("stele/research/q26/model/v1") || NUL
            || u32(context_length) || u16(block_count)
            || S(embedding) || u8(untied) || [S(head) iff untied=1]
            || N(final_norm) || S(final_gain) || P(final_policy) || u8(logits_fraction)
            || Block[0] || ... || Block[L-1]
    Block = N(norm1) || N(norm2) || S(gain1) || S(gain2)
            || S(Q) || S(K) || S(V) || S(O) || S(up) || S(gate) || S(down)
            || u16(heads) || u16(groups) || u16(head_width) || u8(fq) || u8(fk)
            || P(query) || P(key) || u16(score_m) || i8(score_e)
            || B(RoPE descriptor, or empty for absence)
            || u8(fv) || u8(attention_output_fraction) || P(value) || P(attention_output)
            || u8(accumulation) || u8(drop)
            || B(exp Function) || B(exp Representation) || B(SiLU Function)
            || u8(fu) || u8(fo) || u8(fd) || u8(fout)
            || P(first_norm_output) || P(second_norm_output) || P(gated_product)

Accumulation is exact=0/block1024=1. Function/Representation bytes are RFC-0021's
existing frames; RoPE uses ROPE.md's complete frame. Signed score exponent uses
two's complement. Context is 1..2^20, layers 1..128; vocabulary is 1..2^20,
d/hidden widths at most 16384 and attention shapes obey A6. Other numeric domains
are the existing checked parameter domains. The decoder rejects unknown tags,
invalid enums, noncanonical rationals, truncated frames, trailing bytes, aliases,
conflicting representations and inconsistent shapes/units. Total descriptor bytes
are capped at 2^20, inner Spec/Function/Representation/RoPE frames at 512/128/256/128
bytes. Length checks precede loops and payload allocation; decoded bytes must
exactly re-encode. No JSON serialization determines these identities.

    config_id = BLAKE3(Model)
    artifact_digest = BLAKE3(validated ARTIFACT.md bytes)
    instance_id = BLAKE3(ASCII("stele/research/q26/model-instance/v1") || NUL
                         || config_id[32] || artifact_digest[32])

This is a research model identity, not the complete Accepted cqis_id. The loader
requires independently expected config/artifact hashes, derives the exact Spec
set from the descriptor, validates every artifact record, regenerates rotations
and constructs the model. A legal role swap changes config_id; a legal value/scale
change changes artifact_digest; either changes instance_id. Supplying both a
changed artifact and its new hash deliberately defines a different model. Hashes
do not authenticate their own provenance, a publisher, source-to-weight conversion,
or a PCS commitment. Source/index/config-file hashes and ignored-source policy
remain separate source-preparation/registration data, not inferred from labels.
The returned Model is numerical state; callers retain configuration/instance ids
separately. Identical numerical models can share local caches despite distinct
source labels or proof representations. No authenticated cache scope is claimed.

## Evidence, costs and remaining work

Run the locked causal script with `--configuration` (corpus plus adversarial
controls), or `--configuration-controls` for the controls alone. The corpus uses
seed 2632 and 10,000 model objects with varied independent units, scale policies,
head/group shapes, tied/untied heads and present/absent rotations. An independent
struct-based outer encoder matches every byte; existing inner codecs are shared.
Each loaded model must equal the complete original object. A subset also compares
all cuts/head records against the independent numerical oracle and cached steps.
Of 100 numerical cases, 67 accept and 33 reject for the same reason as the oracle.
Corpus SHA-256: `d348f520db57d6d3b8047b4f9d178c2d611cf8ea366295d30460aee8e681b46a`.
The byte-mutation corpus uses seed 2633; valid changed configurations must fail
against the original expected identity. Targeted controls cover role swaps,
payload changes, whole-field identity sensitivity, duplicate records, malformed
artifact headers even with recomputed hashes, 128 layers and preallocation limits.
Of 10,000 byte mutations, 9482 reject structurally and 518 decode but fail the
original identity. Another 268 valid whole-field changes alter that identity.

The pinned checkpoint now runs entirely through this loader. Its descriptor is
2575 bytes, with config id `1d22d4d41a69081111c7ac582172c67cfec640b7a8893a9849063168bf5f921b`.
The original artifact/source identities, prompt, generated tokens and full logit
checksum remain unchanged; the additional instance id is in causal-checkpoint.json.
These lengths/counts/checksums are correctness evidence, not benchmark results.

Metadata validation/hashing is O(descriptor bytes); loading scans physical bytes
and regenerates O(context*rotary_width) coefficients. It retains source/artifact
bytes, parsed records and model objects; no streaming claim. Before physical
parsing/generation, the loader caps each tensor at 2^20 elements, all tensors at
2^22, each block's matrices at 2^20, each rotary table at 2^16 pairs and distinct
tables collectively at 2^20 pairs/absent-position entries. These resource limits
do not establish full-size serving capacity. No measured cost constant, proof
weight pass, cut, challenge, ledger line or production control changes.

Continue Q26 with canonical full certificate/registry sets, general authenticated
source-role lowering, native Rust/NumPy GPT-2-small and Llama-3.1-8B, fidelity and
actual private proof consumers. Other architectures and request/proof identity
remain required. Draft A10 records this boundary; original task criteria remain.

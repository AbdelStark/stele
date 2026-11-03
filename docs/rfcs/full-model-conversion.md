# RFC-0025 exact original-source conversion

Status: Draft. Part of [RFC-0025 §2.1](RFC-0025-full-model-cqis.md), Q26/E5-03b,
the [source appendix](full-model-source.md) and [encoding §3](full-model-encoding.md).
Conversion consumes the same immutable source bytes that passed every file,
container, index, selection and alias check. It implements the declared scalar,
transform, scale and packed-code rules without host floating-point arithmetic.

## 1. Original coordinates and exact scalars

Validate Model and Preparation, then the complete Source/Assets package before
using its tensor slices. Each physical role has exactly one declared Map entry.
For physical matrix row r, column c and output/input dimensions R,C, the source
scalar index is r*C+c for copy, c*R+r for transpose, or c*(3*R)+part*R+r for
GPT-2 fused Q/K/V columns. A vector index r is unchanged for copy and becomes
part*R+r for fused Q/K/V bias. These formulas follow the already checked Map
shapes and full partitions. Multiply by the declared scalar byte width and
check the complete source span before reading. Source offsets never wrap or
become field residues. Container offsets include the exact original header.

Each scalar is decoded as signed n*2^p using integer bit operations under the
declared F16/BF16/F32/F64 format. Subnormals retain their exact value; both signed
zeros become zero. Every selected NaN/infinity rejects, including values that
would otherwise round to zero or occupy a different fused partition. Ignored
buffers retain structural checks without imposing selected-scalar finiteness.
Permitted alias equality is checked on raw bytes before this decoding.

## 2. Minimal scales and physical payloads

Derive every matrix's exponent and channel mantissas from its own transformed
source, following RFC-0025 §2.1. Fused Q/K/V matrices have separate exponents;
they never inherit one exponent computed for the combined source. A zero row
uses mantissa one and its matrix's exponent; an entirely zero matrix uses e=0.
The least exponent and least positive mantissas are mandatory. No observed
quantised code or clipping step may substitute for original-source maxima.

Integer dyadic comparisons determine the complete matrix maximum. A second
pass obtains each row maximum and writes its u16 mantissa without retaining a
whole matrix of decoded scalars or an array of all row maxima. Conversion then
rounds each signed source value once, half away from zero, after exact division
by that row's m*2^e. Retain the symmetric int4/int8 ranges and continuous packing
from encoding §3. There is no per-row nibble padding; only an odd final high
nibble is zero. Int16 vectors use their independently configured fraction and
reject overflow. No automatic format, fraction, saturation or scale change is
permitted. A tied head uses the original token physical record and its scales.

Derive complete canonical Scales from these values. Produce the exact Artifact
using Model's physical order, Preparation/quantiser_id, those same Scales and
every converted payload byte. Source headers, shard partition and signed-zero
representations may change Source while preserving the numerical payload.
This does not weaken the passport's separate original-source binding.

## 3. Completion, resources and authority

The research converter validates every selected scalar and vector range before
emitting Artifact bytes. It uses two complete matrix scans to derive scales
and one matrix scan to emit codes; vector validation and emission are separate
passes. These are offline preparation scans, with no change to the one online
weight pass. Full input files remain retained immutable byte objects. Tensor
transforms use indexed scalar reads, without whole transformed-tensor copies.

Emission uses at most 65536 bytes per chunk. Scales uses its existing 64 MiB
metadata bound; per-matrix mantissa storage derives from the complete channel
count. Source values, scale words and offsets retain their full declared
domains, with no old element-count limit. No bounded-memory native file loader
or fallible-allocation guarantee follows from this Python interface.

A success result is returned only after the entire Artifact reaches the output
sink and the complete emitted bytes are hashed. A failed write or exception
leaves an unusable partial artifact, which the caller must discard. A returned
digest identifies the emitted bytes; storage integrity still requires reading
and validating the actual stored Artifact. A callback acknowledging a write is
not a proof that another storage system or commitment contains those bytes.

Source/Assets authority, semantic config/tokenizer/generation adapters, the
outer passport, actual commitment-to-Artifact hash proof, native E5/E6/E12/E14
consumers and all original private PCS/ZK/profile/fidelity requirements remain
separate. No source proof handle, challenge, cut, measured constant or native
negative-control credit is created by numerical conversion.

# RFC-0025 numerical model execution

Status: Accepted. Part of [RFC-0025](RFC-0025-full-model-cqis.md), Q26/E5-03b.
This describes the research composition of its existing numerical definitions.
It does not add a proof protocol, native source handle or accepted passport.

## Artifact and configuration

`model_execution.load` takes the complete Model, Map, Scales, immutable Artifact
bytes and an independently expected Artifact digest. It validates Model/Scales,
the exact complete Artifact and its digest before returning numerical data.
Physical records retain their declared order, shapes, signed int4/int8 codes,
int16 vectors and original per-channel scales. Int4 indexing remains continuous
across rows, including odd row widths. GPT-2's head selects token record zero.
The reader retains the original immutable byte object and decodes individual
codes without constructing whole transformed tensor copies.

Before execution, enforce the complete configured static score bound and
1024-slot weighted block bound. Small inputs, a short prefix or zero codes do
not relax either check. SiLU and GELU-tanh select output fraction at most input
fraction, as required for their complete int16 tables. Numerical point evaluation
uses the existing certified definitions with bounded, definition-only caches.
Complete Registry regeneration/admission remains a separate requirement; a
point result cannot authenticate a supplied table, rotation or data digest.

## Full and cached evaluation

Full evaluation embeds every original token at its absolute position, executes
every declared block, and returns all residual rows and vocabulary logits.
The implementation includes GPT-2's learned positions, LayerNorm, all affine
biases and GELU-tanh FFN, and Llama's RMSNorm, configured rotary layout, grouped
attention and exact signed int32 gated product. Each operation consumes its
declared units and row-conversion policy. There are no implicit alignments,
per-head scale recomputations, intermediate bias roundings or gated int16 casts.

Attention evaluates the configured score arithmetic for all supplied keys and
uses only unmasked keys for its first maximum and exponential weights. Absolute
1024-key blocks include zero masked contributions; full and cached execution
therefore retain the same boundaries. Heads inherit complete-row K/V scales,
and the concatenated attention output is converted once before O projection.

A cache retains the complete token prefix and each layer's exact post-rotation
K codes/scales and V codes/scales. Its scope contains Model, Scales and Artifact
identities; changing any of them rejects reuse. Append validates the complete
prefix lengths, per-layer shapes, units, code/scale domains and canonical zero
rows. Positions are the original dense prefix indices. The new immutable cache
is returned only after all layers and the vocabulary head succeed.

This cache is internal numerical execution state, not externally authenticated
proof evidence. Structural checks cannot prove that arbitrary caller-forged K/V
values came from prior inference. Native source/commitment and prefix-state
consumers must establish that provenance; no research constructor grants it.

Generation consumes the [Model-bound request decoding](full-model-decoding.md),
validates the seed even at a zero limit, and evaluates every chosen token before
testing EOS. An evaluation failure rejects the request, including when that
token is EOS. Completion then checks the full request/stop rule. The final EOS
therefore participates in full/cache equivalence.

## Resources and remaining delivery gates

All configured shape domains remain those of Model. The old research product
caps do not constrain this executor. It retains the complete Artifact, full
residual/logit arrays for batch evaluation, and full K/V prefixes for cached
evaluation. Storage includes O(Nv+NLd) execution arrays plus original Artifact
bytes and bounded derived-point caches, for actual sequence length N. Host
resource admission and native fallible allocation remain required.

The independent oracle uses rational arithmetic and Arb intervals; it does not
load model source code. Generic full/cache tests and large addressing cases do
not establish named checkpoint fidelity, Rust/NumPy parity, native proving,
verification, private PCS/ZK or profile delivery. Full authenticated source and
config/tokenizer/traffic joins, Registry/Bounds consumers and outer statement
remain required. This adds no challenge, intermediate commitment or online
proof weight pass and reports no measured cost constant.

## Original-source preparation and numerical identity

`preparation_execution.prepare` snapshots the exact original-file dictionary,
checks SourceConfig's architecture/role binding, converts the original immutable
source tensors, then validates the stored Artifact bytes against the conversion
digest before numerical execution. The same Model/Map/Assets and derived Scales
flow through every stage. A complete return requires all file, alias, selected
scalar, vector-range, Artifact and static execution checks to succeed.

The helper retains complete original/output bytes in research memory. It grants
no publisher authority or native proof handle. Original-source authority must
come from the authenticated passport/statement, and the separate commitment to
Artifact hash relation still needs its actual proof consumer. Tokenizer assets
are hash-bound bytes here; this token-domain executor does not establish text
encoding or traffic ownership. Named fidelity retains its original tokenizer
and complete evaluation requirements.

The encoding appendix's numerical identity preimage is exactly 152 bytes:
its existing domain prefix followed by H(Model), H(Scales), H(Registry), H(Bounds).
`identity_frame` validates the complete collection, including same-Model Scales
and complete definition-derived Registry data, before constructing those bytes.
Verification rederives the full preimage from independently expected inputs.
The identity is its BLAKE3-256 digest. No field is adopted from supplied identity
bytes, and no opaque Bounds/Registry hash can replace their required validation.
This closes the numerical identity join only; complete passport/public-input,
commitment/layout, profile and source consumers remain separate requirements.

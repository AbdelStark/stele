# Q26: ordered checkpoint artifact and preparation identity

Question: how are canonical tensor records composed into one reproducible weight
artifact, and which complete offline conversion parameters determine its quantiser
identity? The properties at stake are framing, exact record-set/order enforcement,
metadata binding and deterministic content hashing. Kill criteria: ambiguous
composition, omission/duplication accepted, caller order changing canonical bytes,
or a conversion parameter changing without changing the prepared configuration.

This is a research candidate for RFC-0004 A3 / RFC-0011, using the preceding
source/scales/records studies. It does not admit a production artifact, authenticate
safetensors input, or supply the operation plan/static certificates/proof consumers.

## Scope of the preparation identity

The selected Specs are the exact nonempty set of physical tensors to prepare.
Every Spec has the complete closed fields in RECORDS.md, including name, source
dtype, shape and weight bits/channel axis or wide fractional precision. The
candidate algorithm is exactly finite scalar decoding, QUANTISER.md's symmetric
weight policy and RECORDS.md's wide conversion; no calibration data, automatic
precision selection, implementation callback or alternate rounding is accepted.
Changing any of these semantics requires a new algorithm version/domain.

This identity covers offline source-to-artifact conversion only. Runtime dynamic
or static activation scales, residual alignment, operation roles/ties, architecture
and certificates belong to the complete CQIS configuration/plan; they must be
bound there. They do not change these offline weight/gain bytes and are not
smuggled into a claim that this preparation identity is the complete cqis_id.
A label is not evidence that it matches a safetensors source name or role.

Sort selected Specs by raw ASCII name bytes; duplicate names reject. Builder
argument order has no meaning. Require the source/record dictionary to contain
exactly those names, rejecting every missing or extra entry. Preparation converts
every selected source and emits nothing if any conversion fails. The eventual
source adapter must decide and authenticate which checkpoint entries populate
this selection, including permitted omissions and tied aliases. The candidate
itself has no alias field: tied roles must reference one physical named record.

## Complete candidate framing

All lengths/counts are unsigned little-endian, without padding or trailing bytes.
Let C_i be each canonical tensor Config and R_i its Record in sorted-name order.
The research candidate uses 32-byte BLAKE3 outputs throughout:

    Preparation = ASCII("stele/research/q26/quantiser/v1") || u32(count)
                  || (u32(len(C_i)) || C_i) for every i
    quantiser_id = BLAKE3(Preparation)
    Artifact = ASCII("stele/research/q26/weights/v1") || quantiser_id || u32(count)
               || (u64(len(R_i)) || R_i) for every i
    digest_cqis_candidate = BLAKE3(Artifact)

Count lies in [1,2^32-1]. The full record length is derived from its expected
Spec, including config, scale span and payload; the frame must equal it exactly.
Each record and total Artifact length must fit u64. Preparation configuration
lengths fit u32 under RECORDS.md's rank/name limits; the explicit count bounds
also keep the theoretical total metadata length below u64. Prototype storage and
native resource limits are separate: this does not promise that maximal legal
sizes can be allocated on a particular machine.

The parser derives ordering, quantiser_id, count and every record length from
independently expected Specs before parsing content. Unknown identity, changed
count, a missing/extra/duplicate/reordered record, wrong embedded metadata,
malformed lengths or any inner record violation rejects. Even equal-sized
records cannot be duplicated under different expected names. Correct field widths
and canonical inner encodings make the complete framing injective; identifier
collision claims still depend on BLAKE3's collision assumption.

The `chunks` prototype first validates and snapshots all immutable record bytes,
checks total length, and only then returns an iterator over header/length/record
segments. Later caller dictionary edits cannot alter that iterator. Concatenating
it equals Artifact. This avoids a second joined copy for callers consuming its
segments, but source preparation and record validation still materialize data;
it is not measured streaming performance or a native memory/capacity guarantee.

## Content identity is not checkpoint authentication

`assemble` accepts any syntactically valid record set. `prepare` derives its
records from the supplied source tensors. The former cannot check scale minimality
or source provenance without the latter's original inputs. The candidate digest
changes under a legal payload mutation while quantiser_id remains unchanged:
the algorithm/configuration is the same, but its purported output is different.
Auditors must compare against actual source-derived output; an arbitrary supplied
quantiser_id/digest pair is not verification of a committed model.

These research domains remain distinct from any Accepted production
cqis-weights-v1. No source-map hash is substituted for RFC-0011's digest_hf:
actual safetensors bytes, container parsing, shard selection/order, source aliases
and complete metadata remain to be specified. BLAKE3 framing does not establish
committed field packing, codeword proximity, commitment-to-digest binding, ZK or
wrapper verification. It does not expose an artifact's private values publicly;
publication/access and passport confidentiality remain separate contracts.

## Evidence and next requirements

Run `uv run --locked --script research/cqis-checkpoint/check_artifact.py`.
An independent struct-based frame constructor checks full preparation/artifact
bytes and identifiers for 10,000 mixed artifacts of one to five tensors, with
permuted Specs and source insertion order. The preceding record study supplies
the independent inner arithmetic/codec evidence; this outer test does not pretend
to independently re-prove scalar conversion or BLAKE3 itself. A fixed two-record
fixture records complete bytes and hashes for reproduction.

Every strict truncation of that fixture rejects. Targeted mutations cover prefix,
identity, count, length, swapped/missing/extra/equal-sized duplicate records, wrong
metadata, and source/record-set errors. Every conversion parameter is checked for
identity sensitivity. A legal value mutation changes only content identity, and
snapshot/late-invalid-record tests check the segment iterator's boundary. Corpus
counts and the SHA-256 correctness checksum are not performance measurements.

Continue Q26 with authenticated source adaptation and the closed static certificate
schemas/bytes/consumers. Complete operation plans must bind every runtime scale,
function and tied role. Native fallible streaming, Rust parity, full reference
inference/fidelity, PCS packing/privacy and actual NC-0102/0109/passport controls
remain required before graduation. No Accepted text, core code, commitment count,
FS challenge, soundness-ledger term, profile or one-weight-pass requirement changes.
Preparation/hash work belongs to T_misc; no fitted constant or benchmark is claimed.

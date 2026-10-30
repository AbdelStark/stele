# Model RMSNorm records and numerical composition — Q26

Status: Draft RFC-0004 A3/A8/A9 model evidence using Accepted RFC-0021 §2.3 and
RFC-0022's unchanged RMSNorm schema/bytes. E5-03 remains blocked; original
acceptance and NC-0109 are unchanged.

Question: can every layer/final norm derive its expected record from model
metadata and connect checked input/gain rows to the following row conversion,
with native full-byte and arithmetic agreement? Source associations and static
integer faithfulness are at stake; cost terms are T_misc/c_a/T_witness.

Kill criterion, stated before implementation: drop the adapter if it omits or
deduplicates a required role, adopts actual magnitudes, accepts a substituted
record/source, or disagrees with the independent/native references. No new
norm schema, table, Accepted format, proof consumer or measured constant.

## Expected roles and existing schema

`model_norm_bounds.spec` copies exactly d/F/G/E/en/ed from a separately expected
validated RMSNorm Parameters object. It supplies no observed magnitude and no
free field or role schema. `records` emits `layer.i.norm1`, `layer.i.norm2` for
each layer i in model order, followed by `final_norm`. The count is 2L+1;
identical parameter tuples retain distinct model roles and identical bytes.
The adapter changes neither Accepted RFC-0022 derivation nor its native API.

`check` re-encodes the expected parameters and validates every supplied byte
before invoking the existing norm relation checker. That checker binds the
expected signed input and gain rows, statistic, epsilon ratio, normalized
mantissa/exponent, numerical reciprocal value, signed products, selected
rounding branch and output. Its byte-column equalities reject integer aliases;
the inherited static bounds and capacities are unchanged. The numerical
reciprocal test is not an authenticated lookup of the configured rsqrt table.

For each actual token, norm1 consumes the layer input and gains1; norm2 consumes
the first residual output and gains2. The final norm consumes the final layer
output and final gains. Checked norm outputs feed the existing wide-row
conversion relation at the norm's E, using the appropriate first/second/final
static or dynamic policy. Checked row scale, codes and units must match the
independent model reference. Full model outputs also match that reference.
This is conditional numerical composition; source/gain ownership is external.

The checksum domain is `stele/research/q26/model-norm-bounds-checksum/v1` plus
NUL. It frames u32 little-endian record count, then each ASCII role with its
u16 length and each unchanged RFC-0022 record with its u32 length. This is a
correctness checksum, not cqis_id, a plan identity, source authentication or a
complete bound-set format. No new serialization is introduced into production.

## Evidence and controls

Run `uv run --locked --script research/cqis-checkpoint/check_causal_model.py
--model-norm`, or `--model-norm-controls` for the local tamper controls. Tests
were written first and failed because the adapter module was absent.

Seed 2655 supplies 10000 parameter sets over the full supported dimension,
F/G/E and positive reduced u32 epsilon ranges. An independent scalar/column/frame
oracle checks each complete record, and the native `static_records` example
must agree on every byte. Frozen full-byte corpus SHA256:
`049f542209a04e4c933814482f40ff18aba7c9e68a0faf9da0f00444830faaa8`.

Thirty seed2656 models vary one to three layers, norm E/G and static/dynamic
conversion policies. All 150 model-role records pass native full-byte comparison.
Twenty-four full replays agree; six overflow in both independent and actual
model evaluation. The 354 valid norm rows compare normalization intermediates
and outputs with the native `norm_arithmetic` example, independent rational
reference and bounded NumPy output arithmetic. A separate native row rejects
Overflow and the relation witness builder rejects OutputRange for that row.
The model-record byte SHA256 is
`de70bba8c00a2d0b90fd5561320d90c55316ea7b5ac845bc5706ffbbb3cc419d`.
Shared norm/row primitives and model fixtures are disclosed; the existing
primitive corpus is not claimed as newly independent coverage.

Controls change a source or gain while retaining the witness (SourceSign),
change reciprocal J (Table), add p to S and rebuild the columns
(IntegerRelation), change output (OutputRelation), omit a witness row (Witness),
substitute valid parameter records or malformed byte frames (Encoding), and
supply malformed sources/types (Input). Equal-record roles must survive;
changing only norm2 or final metadata must change only that role. Zeroing
learned sources/gains must leave all records unchanged. These local research
controls do not satisfy the actual consumer's NC-0109 or source/lookup controls.

Pinned replay adds norm evidence while preserving every previous fixture field.
Both its six-token exact-attention replay and the separate block-mode replay
compose every norm with row conversion. The exact replay additionally checks
all five records and thirty norm rows against native implementations. The block
variant remains a different numerical configuration, not the baseline identity
or a claimed generated continuation. Serialized sizes are not benchmarks.
The fixture has five records totaling 11400 bytes, with correctness checksum
`8e482df9e64cda45e5853c339c0f398dc1a0c430d69d6e150b786b1a38edd5ca`.

## Remaining contract

The next coverage step is an explicit scoped bound-set, function-registry and
source-association contract. In particular, roles are not authenticated merely
because their records coincide with a local model object. Real source, range,
branch/index, function/table and reduction consumers remain necessary, as do
native full-model integration, fidelity, privacy, PCS/FS and GPU parity.
E5-03/04 and all original criteria remain blocked/unchanged. This adapter adds
no challenge, loss, cut, weight pass or fitted cost constant; eventual bound
association belongs to T_misc and actual norm/row checks to c_a/T_witness.

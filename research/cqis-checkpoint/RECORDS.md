# Q26: canonical physical tensor records

Question: which exact source/configuration and physical output bytes identify a
quantised weight or wide gain tensor, before a PCS layout or full operation plan
is chosen? The security properties are unambiguous decoding, configuration
matching, exact gain conversion and canonical padding. Kill criteria: two accepted
encodings of one record, an out-of-range decoded value, a shape/channel ambiguity,
a nonfinite source accepted, or an exact/NumPy conversion mismatch.

This study is a candidate for RFC-0004 A3 and RFC-0011. It does not define a PCS
message packing, admit a complete cqis_id/quantiser_id/passport, or establish that
source bytes came from an authenticated safetensors container. E5-03 stays blocked.

## Configuration and physical axes

Every record has an independently expected Spec: (name, source encoding, shape,
output bits, parameter). The name is 1..255 ASCII letters, digits, underscores,
periods or hyphens. Source ids 1,2,3,4 mean binary16, bfloat16, binary32, binary64
as defined by the source scalar study; raw scalars are little-endian and finite.
Signed zero converts to integer zero. No host floating-point arithmetic is used.

Shape has rank 1..255 and positive u32 dimensions. Its product N and source/output
byte lengths must fit u64, checked before accessing source bytes or allocating
shape-dependent arrays. Shapes and physical source arrays are row-major, with
the final axis varying fastest. There are no strides, implicit transposes,
broadcasts or tensor padding in this candidate.

For output bits 4 or 8, parameter is the channel axis, strictly below rank. Channel
j consists of all source coordinates whose selected axis equals j, ordered by
physical flattening. QUANTISER.md supplies the exact shared exponent, positive
mantissas and symmetric ranges [-7,7]/[-127,127]. Output values retain the original
physical order. Scale j always applies to axis coordinate j, independent of the
later logical matmul view. A vocabulary-major embedding uses axis 0 for both its
gather and tied LM head. This record does not authenticate those operation roles.

For output bits 16, parameter is the fractional precision F in [0,30]. Every
source g converts to H=R(g*2^F), using one signed half-away rounding; all outputs
must lie in [-32768,32767]. This supplies a candidate exact conversion for norm
gains. It does not select F, silently lower it, saturate, or admit other operation
roles such as biases. One overflowing element rejects the whole preparation.
With decoded source g=n*2^e, |n|<2^53, so conversion uses the already studied
integer shift without a potentially enormous intermediate power. Exact powers,
signed ties, zero, subnormals and extremes retain their specified behavior.
The absolute conversion error is at most 2^(-F-1) for every successful entry.

## Candidate bytes

Unsigned integers are little-endian; signed integers are two's complement.
These research-only domain strings deliberately do not claim to be the complete
RFC-0011 cqis-weights-v1 or production quantiser_id encoding.

    Config = ASCII("stele/research/q26/tensor-config/v1")
             || u16(name_length) || name
             || u8(source_id) || u8(rank) || u32(dim_0) || ... || u32(dim_r-1)
             || u8(output_bits) || u8(parameter)
    Record = ASCII("stele/research/q26/tensor-data/v1")
             || u32(config_length) || Config
             || Scales || u64(payload_length) || Payload

For int4/int8, Scales is i16(shared exponent in [-1099,1024]) followed by exactly
shape[channel_axis] positive u16 mantissas, in channel order. For int16, Scales
is empty: F already defines its units. There is no second scale count or optional
field. All-zero weights prepared from zero source have exponent 0 and mantissas 1.
Checking scale minimality or source-derived values requires regeneration; parsing
ranges alone cannot establish them.

Int8 payload is N signed bytes; int16 is N signed little-endian 16-bit words.
Int4 payload packs consecutive physical values: the earlier element occupies
the low nibble. Interpret each nibble as signed four-bit two's complement, and
reject -8. Pack continuously across row/channel boundaries, with no per-row pad.
Only an odd final element has padding: its unused high nibble must be zero.
Thus [1,2,3,4,5,6] in shape (2,3) has bytes 21 43 65, not two padded rows.
Payload length is exactly ceil(N*bits/8). Int8 -128 is likewise excluded; int16
retains its full signed range. Reject trailing bytes, truncated fields, nonzero
padding, wrong sizes, unsupported metadata and out-of-range scales/values.

The parser compares the exact Config against independently supplied expected
metadata before interpreting scales or payload. A record cannot select its own
expected source format, shape, channel axis or precision. Full static admission
must itself obtain that expectation from authenticated plan/passport data.
Bounds on the complete scale span and payload precede their decode loops; a huge
advertised dimension with a short record cannot trigger the advertised allocation.
The research prototype retains arrays and is not a streaming native reader.

For source binary16 [1,2,3], shape (1,3), axis 0 and int4, the candidate has
exponent -17, mantissa 56174 and codes [2,5,7], giving payload 52 07. Changing
52 to 51 produces another syntactically valid record with codes [1,5,7]. It must
be rejected by comparison with regenerated source output or the eventual source
binding proof; the decoder correctly does not pretend to authenticate origins.
No digest of caller-supplied bytes is identified as the actual digest_hf.

## Evidence and remaining obligations

Run `uv run --locked --script research/cqis-checkpoint/check_records.py`.
The independent encoder groups coordinates by Cartesian products and uses struct
packing; the candidate uses row-major strides and explicit byte arithmetic.
Rational bisection/neighbor distances independently determine scales/rounding.
All 10,000 int4 and 10,000 int8 tensors match complete bytes and decoded values.
For 10,000 wide tensors, exact and NumPy signed-integer decisions agree: 1,980
succeed and 8,020 reject overflow. Shapes of ranks 1..3, every channel axis, all
four source formats and precisions 0..30 are sampled, with explicit maximum-size,
signed-boundary, zero, tie, nonfinite and malformed cases. The fixture records
canonical examples and a SHA-256 correctness checksum; these are not benchmarks.

Every strict truncation of the hand vector rejects. Wrong expected name, dtype,
shape, axis or width rejects; exponent/mantissa/length/range mutations and all 15
nonzero unused nibbles reject. Successful records re-encode byte-identically.
The legal-value mutation above deliberately demonstrates the separate source
obligation. These are research tests, not NC-0102/0109 or passport-control credit.

Continue Q26 with a complete ordered multi-tensor artifact and quantiser identity,
source-container/shard/name/alias resolution, tied-role binding, calibrated/static
configuration if selected, every static certificate schema and actual consumers.
The full cqis_id/operation plan still must bind forward scales and conversions.
Native fallible streaming/capacity behavior, Rust parity, complete reference/fidelity,
PCS packing/source proof/ZK, wrapper binding and full inference remain required.
Preparation requires source maxima before weight conversion, so native execution
must account for storage or repeated preparation reads; this is separate from
one weight pass per inference proof. No measured T_misc/c_a constant, commitment,
challenge, soundness-ledger term, admitted profile or weight-pass change is claimed.

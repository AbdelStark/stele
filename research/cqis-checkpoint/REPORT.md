# Q26: exact checkpoint scalar conversion

Question: can checkpoint scalar bytes be converted into a unique exact numerical
form without host floating-point arithmetic, while rejecting every nonfinite
encoding? The property at stake is quantiser reproducibility and source-format
binding. The kill criterion is any rational-value mismatch, finite nonzero
round-trip failure, accepted nonfinite encoding or lost subnormal. This addresses
one prerequisite of Draft RFC-0004 A3, not the complete E5-03 contract.

## Candidate semantics

The research decoder supports explicitly selected binary16, bfloat16, binary32
and binary64 scalar formats, with respective exponent/fraction widths (5,10),
(8,7), (8,23), (11,52). These layouts follow the primary
[NVIDIA numeric type documentation](https://github.com/NVIDIA/cutlass/blob/main/media/docs/cpp/fundamental_types.md)
and [floating-point format reference](https://docs.nvidia.com/cuda/archive/13.1.0/cuda-programming-guide/05-appendices/mathematical-functions.html).
[Python's binary packing documentation](https://docs.python.org/3/library/struct.html)
also distinguishes the IEEE binary16/32/64 formats from native host formats.
The prototype uses none of those libraries' floating-point conversions.

The candidate explicitly chooses little-endian scalar bytes, with no padding or
trailing bytes. This is a proposed source adapter, not a complete checkpoint file
format or an accepted change to CQIS. Unknown formats and wrong length/type reject.
An all-one stored exponent rejects `Nonfinite`, including both infinities and
every signaling/quiet NaN payload. Denormals are preserved exactly, never flushed.

For sign s, fraction f of width t, stored exponent E of width b and bias
B=2^(b-1)-1, finite normal values are
(-1)^s*(2^t+f)*2^(E-B-t). Subnormals are
(-1)^s*f*2^(1-B-t). Remove powers of two from the nonzero significand to obtain
the unique signed odd n and integer e with value n*2^e. Both source zeros map to
(0,0). This numerical normalization does not equate original checkpoint byte
hashes: raw source bytes and their dtype still require the passport binding.

The exact pair has abs(n)<2^53 and -1074<=e<=1023 across the candidate set.
Those bounds follow from the stored precision and exponent fields; no sampled
maximum, host arithmetic behavior or model calibration is used. This pair is a
research representation, not a protocol wire encoding or a bound certificate.

## Independent evidence

Run `python3 research/cqis-checkpoint/check_scalars.py`. The decoder extracts
integer fields and removes powers of two. Its independent oracle parses bits in
MSB textual order and sums their rational contributions. A separate inverse finds
the rational binary scale and reconstructs each finite nonzero original encoding.
The source zero sign alone is intentionally normalized. No path uses host floats.

The committed candidate fixture records these exact decision counts:

| Source format | Checked | Finite accepted | Nonfinite rejected |
|---|---:|---:|---:|
| binary16 | 65,536 | 63,488 | 2,048 |
| bfloat16 | 65,536 | 65,280 | 256 |
| binary32 | 11,536 | 11,493 | 43 |
| binary64 | 22,288 | 22,279 | 9 |

Both 16-bit domains are exhaustive. Each wider format has 10,000 seeded raw words
plus every exponent with both signs and zero/minimal/maximal fractions. The checks
include signed zeros, normal/subnormal boundaries, smallest subnormals and largest
finite values; six exactly common values yield identical pairs across formats.
Malformed lengths, unknown formats, Boolean pseudo-parameters and mutable byte
buffers reject. Counts and SHA-256 correctness checksums are not benchmarks.

Format metadata is essential: little-endian bytes `003c` denote 1 in binary16
and 1/128 in bfloat16. Hashing the raw bytes without binding the selected source
format cannot identify a unique numerical checkpoint. This is a prerequisite
for the future quantiser/passport consumer, not a new proof control in this study.

## Recommendation and remaining contract

Continue Q26 with these exact source-adapter candidates when completing RFC-0004
A3 and RFC-0011's checkpoint/quantiser encodings. Do not import the research module
into core crates. E5-03 remains blocked: weight-scale selection, int4/int8 policy,
channel/tensor order, zero-row conversion, residual alignment, static fallback,
quantiser identity and all per-reduction certificate schemas remain unresolved.

This study adds no proof message, random challenge, claim, committed tensor,
soundness-ledger term, NC-0109 result or profile admission. Scalar decoding is
linear in source bytes with bounded per-scalar state during preparation; no fitted
T_misc/c_a constant, weight-pass change or performance result is claimed. Native
Rust/NumPy quantiser parity and full reference inference remain required.

## Scale-policy continuation

The [exact quantiser candidate](QUANTISER.md) continues Q26 with explicit int4/int8
weight scales and dynamic/static int8 row policies. Independent rational bisection
and signed-neighbor rounding agree on 20,000 weight tensors and 20,000 row decisions.
The study proves scale minimality, symmetric ranges and per-entry error bounds;
zero rows preserve scale zero and static overflow rejects. Reproduce with
`python3 research/cqis-checkpoint/check_quantiser.py`. These remain candidate
choices; complete configuration/identity, alignment, native parity, static
certificates and real consumers are still required before E5-03 acceptance.

## Alignment and tied-storage continuation

The [alignment study](ALIGNMENT.md) defines candidate combined matmul scales,
one-round residual alignment and one vocabulary-major quantised tensor shared
by embedding/LM-head roles. Exact rational and NumPy integer checks cover 20,000
scale decisions, 10,000 residual decisions and 10,000 tied-role cases, including
overflow rejection. Concrete witnesses distinguish separate rounding and separate
transpose quantisation from the proposed semantics. Continue Q26 with explicit
artifact/plan/source-role bytes and static certificates; native inference and
production control obligations are unchanged.

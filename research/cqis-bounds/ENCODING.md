# Q26 canonical static-bound records

Question: can the closed Requant and RMSNorm schemas produce one bounded,
canonical byte record that a native implementation can validate against separate
expected parameters? INV-5 and deterministic CQIS identity are at stake; derivation
and encoding cost belong to T_misc. Kill criteria: two accepted encodings for one
expected schema, an altered field accepted, a field not rederived from static
parameters, a supported record exceeding its declared capacity, or a mismatch
with the independent column oracle.

This is research under RFC-0004 A3. It defines no authenticated plan, reduction,
proof verifier or NC-0109. The two mathematical schemas already have native
numerical parity; this study concerns their static records. Every other operation
schema, native certificate delivery and actual range/source consumer remains
required for E5-03 and end-to-end inference.

## Candidate format

All fixed integers are little-endian. The record begins with ASCII
`stele/v0.1/cqis/bounds`, u32 version 1, u8 schema (1 Requant, 2 RMSNorm),
u16 parameter length and exact parameters. Requant parameters are u16 mantissa,
u8 shift, u8 target bits; RMSNorm uses RFC-0021's thirteen parameter bytes.
Next are u32 M31 prime, u8 radix bits 8, u8 scalar count and that many u160
scalars; u8 signed-shift count and that many i16 shifts; u8 role count and the
ordered role records. Counts are fixed by the selected closed schema.

Requant scalars, in order: divisor, bias, product_max, quotient_max, output_max,
output_lhs_bound, output_rhs_bound. There are no signed shifts; its six roles
are input_lhs, input_rhs, product, bias, quotient_product, division.
RMSNorm scalars: unit, S_max, N_max, P, A_max, D_max, MD_max,
round_divisor_max, round_bias_max, left_factor_max, sign_lhs, sign_rhs.
Its signed shifts are shift_min, shift_max. Its eleven roles are statistic,
numerator, scaled, normal_product, normal_sum, xy, product, bias,
quotient_product, division, left. Role ids are consecutive u8 values from one
within each schema. The formulas are in [Requant](REQUANT.md) and [norm](NORM.md).

Each role encodes its id, u32 count, u160 left_max/right_max/result_max,
u8 left digit count, u8 right digit count and u8 column count K. The digit-cap
arrays follow in left/right/result order as u8 values, then K+1 carry caps,
K left-side bounds and K right-side bounds as u32 values. Their derivation is
the [column lemma](LIMBS.md) with radix 256. Both zero boundary carries are
encoded. There is no supplied field-half value or implicit field reduction.

All supported closed-schema values/results fit u160 and each digit/column
count is at most twenty. A role uses at most 372 bytes; the largest envelope
uses at most 4,386 bytes. Set the explicit total capacity to 8,192 bytes.
Unknown versions/schemas, wrong parameters/counts/order, noncanonical integers,
truncation and trailing data reject. Full expected regeneration precedes
admission; bytes never choose their own expected parameters or authorize a plan.

## Evidence and graduation

The check script independently parses the framing, derives scalar/role parameters,
and compares every column with the packed-polynomial/prefix oracle. It also
checks 10,000 varied static configurations per schema, boundary golden records,
every one-byte mutation and every truncated prefix of those records, substitutions
of valid records for different expected parameters, and resource/type rejection.
Run `uv run --locked --script research/cqis-bounds/check_encoding.py`.
All 20,000 configurations and six full-byte boundary vectors pass. The corpus
record lengths are 951..1176 bytes for Requant and 2208..2923 for norm; these
are fixture sizes, not a performance measurement or a replacement for the
analytical 4386-byte bound. Its SHA-256 is
`6ebb4c66a125e60a031f6ba76aaf75e330dc21f96ac1f2509a7fa1f8352503e0`.
Tests preceded implementation and first failed at the absent encoding module.
The [closed contract](../../docs/rfcs/RFC-0022-static-arithmetic-records.md)
must be Accepted before native code uses this format. No result here completes
E5-03 or grants proof/control credit.

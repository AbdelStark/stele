# CQIS scalar arithmetic (E5-01)

Run `uv run --locked --script harness/cqis/check_arithmetic.py` from the repository.
The pinned NumPy reference uses int64 only and compares 10,000 seeded cases each
for requant8, requant16 and residual addition against the actual Rust API, plus
signed ties, target boundaries, maximum accumulators/mantissas and invalid
configuration cases. The reference uses quotient/remainder comparison; Rust uses
the biased magnitude specified by RFC-0004 A1. Both reject target overflow.

`stele_cqis::Requant::new(mantissa, shift)` accepts mantissas 1..65536 and shifts
0..=62. `apply(i32, Format::Int8|Int16)` returns a checked i16 holding a value in
the selected format. Shifts above 62 reject because this implementation represents
the positive divisor and biased magnitude in signed int64. No negative shift,
saturation, wrapping or floating-point rounding is used. Native Rust i32/i16
types enforce accumulator/residual input ranges. `residual_add` rejects any
sum outside int16.

These scalar semantics supply no proof acceptance, transcript, lookup, CQIS
identity, tensor scale alignment or field-bound certificate. Weight formats and
quantisation policy belong to E5-03; both residual operands must already share
the tensor's scale. Static certificates and the consuming sign/range reductions
remain required even when a runtime arithmetic call succeeds.

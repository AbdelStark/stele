# E5-01 scalar arithmetic review

Reviewer: codex-root, also the author; cqis-numerics and soundness-auditor passes.
Not an independent audit. Scope: native integer scalar operations, no field proof.

I tried to break it with negative ties, zero, both target endpoints, maximum
accumulator/mantissa products, overflowing outputs and residual sums, and the
named rejection/parity tests rejected the invalid cases for range/configuration
reasons. Constructor state is private; native types constrain accumulator inputs.

- RFC-0004 A1 overrides the original contradictory rounding prose. The code
  applies the sign after rounding the magnitude, including e=0 and zero. It
  does not implement half-even, half-up, truncation, saturation or wrapping.
- Mantissa is positive and below 2^16. Shifts 0..62 ensure positive D<=2^62;
  |acc*m|<=2^31*(2^16-1), and adding bias<=2^61 fits int64. Multiplication,
  absolute value, shift and biased addition are checked. Negating q is safe
  under those static native-integer bounds. Unsupported shifts reject.
- The full signed int8/int16 ranges follow A1's output contract. Weight
  quantisation policy and exponent alignment are not inferred from that API.
  Residual add uses checked int16 addition with saturation disabled.
- Rust/NumPy int64 parity covers 30,363 decisions: 10,000 seeded cases for each
  of three operations plus explicit boundaries/errors. NumPy uses a different
  quotient/remainder formulation. Its seed and dependency version are pinned.
  Rust tests were written first and failed on the missing API before implementation.
- No challenge, transcript, claim consumer, commitment or proof binding is
  added. No production NC or soundness-ledger credit is claimed. Sign/range
  lookups and bound certificates remain E5-03/E7 obligations. Integer success
  does not establish field faithfulness or accept an inference statement.
- The adapter only drives the same public API for parity; it cannot bypass
  validation. Core code is no_std, safe Rust, integer-only and deterministic.
- No cost-model constant, benchmark result, weight pass or intermediate
  commitment changes. The scope introduces no allocation in core arithmetic.

Sign-off: approve scalar arithmetic for gated merge after the full repository
checks pass. This does not approve quantisation, inference or a proof reduction.

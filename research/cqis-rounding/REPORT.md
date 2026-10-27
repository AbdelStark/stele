# CQIS signed rounding conflict

Question Q10: which exact signed rounding relation implements the round-half-away
semantics named by E5-01, ADR-005 and RFC-0004 §5.1?
The security property at stake is that inference and the proved integer relation
compute the same output. Kill criterion: a signed tie or a rounded-up value differs
between the forward rule and its relation. That criterion is met by the current text.

## Counterexamples

For `t = acc·m = -1` and `e = 1`, the §5.1 formula `(t + 2^(e-1)) // 2^e`
returns zero. Round-half-away returns `-1`. Section 3 separately names half-even.
For `t = 1, e = 1`, round-half-away returns `y = 1`, but the unadjusted relation
`t = y·2^e + r` requires `r = -1`, violating `0 ≤ r < 2^e`.
These are specification inconsistencies, not implementation bugs.

## Proposed relation and evidence

Use the sign of `t` and round its nonnegative magnitude: with `D = 2^e`,
`h = D/2` for `e > 0` and zero otherwise, decompose `|t| + h = q·D + r`.
Set `y = sign(t)·q`, choosing the positive sign for zero.
`q = floor((|t| + h)/D)` rounds to the nearest integer, with magnitude increasing
at exact ties; multiplication by the original sign gives round-half-away.
This is the proposed correction in RFC-0004 A1, not accepted protocol behavior.

Run `python3 research/cqis-rounding/check_rounding.py`. Both counterexamples are
asserted and the candidate relation agrees with an exact `Fraction` reference on
69,661 signed/shift cases, including extreme int32 accumulator products.
This is correctness evidence without floats or model data; no benchmark is reported.

## Recommendation and limits

Review and accept an exact rule before implementing E5-01 or the corresponding
reductions. No Rust/NumPy parity, static field-bound certificate, range lookup,
inference fidelity, or proof soundness is established by this research script.

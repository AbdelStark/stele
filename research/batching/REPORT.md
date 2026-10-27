# Batching contract study (Q18)

Question: which schedule, bytes and final obligations implement instance and
virtual-tensor claim batching with bounded RLC+SC error? Kill criteria: accepting
false public claims, dropping obligations, changing sums through padding, or
failing to detect a missing final absorb in a subsequent relation.

Reproduce: `uv run --locked --script research/batching/check_batching.py`.
The pinned Python oracle reuses the independent research field/sumcheck arithmetic
and BLAKE3 backend; it imports no core code. Proving exhaustively sums residual
hypercubes; public verification independently uses eq weights. This is a byte/
algebra oracle, not a performance implementation.

Evidence: 46 honest cases cover both fields/modes, degrees 0..4 and zero/equal/
unequal dimensions. Four vectors record descriptors, proofs, points, gamma,
accounting and a chained A1 proof. False sums, malformed shapes, missing finals,
omitted contributions, early coefficients, unused false finals and omitted
BatchFinal reject at their stated checks. A constant-summand counterexample puts
the selector outside P. Two hundred seeded coefficient checks include extension
points, Boolean prefixes and overlaps; exhaustive nonzero F5 polynomials of
lengths 1..4 obey the root bound. These finite checks earn no NC credit and do
not discharge E3-02's 10^4-point gate. See the [obligation](../../formal/batching.md).

Recommendation: accept A2/A4 after skill review, then implement both modes and
real controls. Arbitrary points can cost O(t 2^m); disjoint prefix blocks admit
linear construction. No performance, GPU, independent-audit or profile claim.

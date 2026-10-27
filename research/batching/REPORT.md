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

## Production corpus (RFC-0006 A2, E3-02)

`uv run --locked --script research/batching/check_batching.py --verify-corpus research/batching/corpus.jsonl`
regenerates and checks the committed 276 cases; `--write-corpus` regenerates the fixture.
`cargo run -q -p stele-sumcheck --example batch_corpus -- research/batching/corpus.jsonl`
uses the real Rust public-table verifiers and checks production prover bytes on honest cases.
Both control/accounting gates compare exact decisions, all suffix-point obligations, and SC/RLC records.
The JSON mode/statement/tables are verifier-owned harness inputs, not proof-supplied routing.
This is a logical subproof corpus, not RFC-0016's inference-proof parser or profile certification.

Cases include both fields/modes, singleton and zero rounds, degree 0..4, mixed degrees,
unequal-size padding, empty inputs, aliases, zero relations and full-extension witnesses/points.
False statements get fresh oracle proofs. Malformed lengths, out-of-range limbs/ids,
invalid descriptors, conflicting aliases, unused/unclaimed values and omitted BatchFinal
have exact expected errors. Every accepted result's obligations are independently consumed.
The existing named NC controls remain the catalog evidence; this corpus adds no NC credit.
E3-02 still requires its measured c_sc/peak-memory ledger.

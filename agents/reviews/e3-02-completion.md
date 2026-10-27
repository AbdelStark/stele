# E3-02 acceptance audit

Author/reviewer: codex-root; same-author skill passes, not independent audit.
Scope is RFC-0006 A2 batching, not complete inference or profile certification.

| Acceptance | Executable evidence |
|---|---|
| NC-0202 | Registered production control runs both modes in QM31/OM31; one omitted contribution gives RoundSumMismatch. |
| RLC/shared SC | Both-field byte tests and the 276-case corpus compare all returned fields; accounting gate independently derives descriptor records. |
| Both modes/sizes/fields | 42 mode-0 plus six mode-1 byte vectors, full corpus, and both-field benchmark cases. |
| NC-0206/0205/0802 | Early gamma, unused/unclaimed value and omitted BatchFinal controls run both modes/fields through real consumers. |
| 10^4 coefficients | 10,000 seeded points per field; arbitrary points, Boolean prefixes, overlaps, duplicates and cancellation. |
| Rust/Python agreement | 64 accepted and 212 rejected corpus cases; complete id/point/value obligations and exact errors compared; accepted public obligations consumed. |
| Closed registry | Eight typed labels match the canonical inventory; BatchCoefficient maps to RLC; invalid-registry gate remains enforced. |
| c_sc/peak memory | Native QM31 and OM31 ledgers record all samples, exact integer time/point ratios, logical table payload, process RSS, plan digest and clean source SHA. |

Benchmark source is `095cfa445f864c7ecd3ae7ccef72fbf5c6be463f`; runner/example are
unchanged since measurement. Ledgers validate and match source, plan digests, stage
totals and sample counts. This establishes CPU baselines, not a fitted constant,
GPU speed, isolated scratch memory, inference throughput or a full-profile bound.
Existing tests/gates stay required. NC-0203 remains E3-06's wrong-layer obligation;
Q12 and other protocol tasks remain open. No acceptance criterion was removed.

Recorded ledgers: [QM31](../../bench/ledger/e3-02-batching-qm31.json) and
[OM31](../../bench/ledger/e3-02-batching-om31.json). Measurement semantics and rerun
commands are in the [benchmark guide](../../bench/README.md#batching-e3-02).

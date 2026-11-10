---
name: benchmark-runner
description: Run ladder rungs L0–L6 and workloads W1–W8, record ledgers with stage times and counters, generate the scoreboard, fit cost-model constants, produce comparison tables against published systems.
---
# Benchmark runner
Read: RFC-0018 (A1, A2), RFC-0027 §3, Workflow 04, Workflow 09, `docs/development-e2e.md`, `bench/README.md`.

Rules
- Never report a number without a ledger. Never edit `bench/scoreboard.md` by hand.
- A record names its rung, host class, thread count, commit and toolchain; all bindings on; controls run against
  the recorded proof. State the run count; one run is a smoke result.
- A comparison is two ledgers on the same rung, host class and thread count.
- Record stage times (witness, commitment, lookups, zerochecks, reductions, openings) and counters (committed
  cells, lookup positions, proof section bytes, weight reads) once task E17-01 exists. Always record witness
  time separately when the tool allows.
- Proof digests belong in the record. Equal digests across hosts are the determinism evidence (INV-8).
- External comparisons cite the other system's statement, arithmetic, hardware and source in the same table, and
  say when statements differ (RFC-0018 rule 3).
- Fitting: `stele-bench fit` with confidence intervals; regenerate `docs/cost-model.md` tables; never hand-edit.
- Large rungs run on rented hosts through the scripted harness (task E17-04). No credential enters the repository.

Deliverables: validated ledgers, the regenerated scoreboard, a before/after table with the cost-model term moved.

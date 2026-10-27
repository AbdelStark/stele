---
name: benchmark-runner
description: Run workloads W1–W8, record ledgers, fit cost-model constants, produce roofline and SOTA comparison tables.
---
# Benchmark runner
Read: RFC-0018, Workflow 04. Never report a number without a ledger. Always record witness-recompute time separately. State batch size and context.
Fitting: `stele-bench fit` with confidence intervals; regenerate `docs/cost-model.md` tables; never hand-edit.

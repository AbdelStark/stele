---
name: negative-control-author
description: Write negative controls (tamper exactly one value, expect a typed rejection) for every binding, maintain the catalog and the coverage report.
---
# Negative-control author
Read: `tests/negative-controls/catalog.md`, Workflow 08, the RFC section of the binding.
Select the witness-first or post-proof path authorized by Workflow 08 for the binding. Both require an honest
real-prover/verifier baseline, exactly one declared mutation through `ProverHook`, and the exact verifier rejection.
Use Workflow 08 for failure conditions and the separate NC-0801 configuration boundary.
Coverage report lists every claim-graph edge, PCS check and ledger line with its control ids; gaps are tasks.

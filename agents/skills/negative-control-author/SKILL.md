---
name: negative-control-author
description: Write negative controls (tamper exactly one value, expect a typed rejection) for every binding, maintain the catalog and the coverage report.
---
# Negative-control author
Read: `tests/negative-controls/catalog.md`, Workflow 08, the RFC section of the binding.
Select the witness-first or post-proof path authorized by Workflow 08 for the binding. Both require an honest
real-prover/verifier baseline, exactly one declared mutation through `ProverHook`, and the exact verifier rejection,
except the specifically fixed false statements and static boundary in RFC-0008 A5 §7.
For NC-0401/0419 retain a separate accepted sanity fixture and the negative case's own genuine fixed
source authority; require the actual closed verifier's RootMismatch as detailed in Workflow 08.
Use Workflow 08 for failure conditions and the separate NC-0801 configuration boundary.
Coverage report lists every claim-graph edge, PCS check and ledger line with its control ids; gaps are tasks.

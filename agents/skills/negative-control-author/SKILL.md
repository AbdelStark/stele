---
name: negative-control-author
description: Write negative controls (tamper exactly one value, expect a typed rejection) for every binding, maintain the catalogue and the coverage report, including relation-engine and commitment-scheme controls.
---
# Negative-control author
Read: `tests/negative-controls/catalog.md`, Workflow 08, the RFC section of the binding.
Select the witness-first or post-proof path authorized by Workflow 08 for the binding. Both require an honest
real-prover/verifier baseline, exactly one declared mutation through `ProverHook`, and the exact verifier rejection,
except the specifically fixed false statements and static boundary in RFC-0008 A5 §7,
and the precisely scoped NC-0315 false-byte statement in RFC-0024 §6.
For NC-0401/0419/0315 retain a separate accepted sanity fixture and the negative case's own genuine fixed
source authority; require the actual closed verifier's RootMismatch as detailed in Workflow 08.
Use Workflow 08 for failure conditions and the separate NC-0801 configuration boundary.
Coverage report lists every claim-graph edge, PCS check and ledger line with its control ids; gaps are tasks.

Relation engine (RFC-0026 §9, RFC-0028 §6): use the three shapes of Workflow 08 — commit one value and prove on
another; prove with a virtual column that differs from its definition; change one public input with the header
restamped so the engine, not the header comparison, rejects.
A control that is accepted is a P0 defect in the protocol or the verifier, never a test to weaken.
A near-miss test on the plain checker is not a control and earns no catalogue credit.
Ids proposed in a Draft RFC enter the catalogue only when the RFC is Accepted.

---
name: negative-control-author
description: Write negative controls (tamper exactly one value, expect a typed rejection) for every binding, maintain the catalog and the coverage report.
---
# Negative-control author
Read: `tests/negative-controls/catalog.md`, Workflow 08, the RFC section of the binding.
A control: builds an honest witness, applies one tamper through `ProverHook`, runs the real prover (no shortcuts), asserts the exact verifier error and that the honest run is accepted.
Coverage report lists every claim-graph edge, PCS check and ledger line with its control ids; gaps are tasks.

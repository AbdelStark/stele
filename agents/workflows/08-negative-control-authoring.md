# Workflow 08 — Author a negative control
1. Identify the binding (claim-graph edge, PCS check, ledger line, public-input field).
2. Write the control as a test in `tests/negative-controls/<area>/nc_<id>.rs` using the `ProverHook` API to tamper exactly
   one value *after* the honest witness is built; assert the verifier returns the typed error named in `catalog.md`.
3. Add the catalog row: id, binding, RFC section, tamper description, expected error, status.
4. A control that is *accepted* by the verifier is a release blocker and a P0 issue; never weaken the control.

# Negative-control harness (RFC-0002 §7, task E0-03)

Run `scripts/gates/negative-controls.sh --coverage` from the repository. The command
runs the harness self-controls, then executes the protocol registry and prints coverage.
It accepts no check-disabling options. This test-only workspace member cannot be imported
by the core crates; `cargo deny` enforces that boundary.

For each protocol binding:

1. Write `<area>/nc_<id>.rs`, declare its `[[test]]` target in this crate's Cargo manifest,
   and assert that the hook changes exactly one intended value.
2. Use `check_control` with the real prover and verifier. It first verifies the honest
   witness, applies `ProverHook` to a clone, proves again, and requires the exact typed
   rejection. Prover failures, no mutation, acceptance, and unrelated errors fail the test.
3. Share that control's runner with the explicit registry in `src/main.rs`. Set the catalog
   row to `done` with the same expected error name. Failed, duplicate, unknown, or mismatched
   registrations cannot earn coverage. Error strings must not expose witness data.

`harness/nc_stub.rs` exercises the full harness sequence on a two-cell fixture. It is
separate from protocol code and has no NC id. It establishes no inference binding.
The registry is empty: all 66 currently cataloged controls, spanning 17 catalog bindings,
remain missing. Range rows expand to individual ids; malformed and duplicate ids fail.

Coverage is over the current catalog, not a complete enumerated claim graph. Several
rows are still broad categories or lack exact errors. E8-04 must expand those rows and
cross-check the implemented claim graph, PCS checks, and ledger lines. No complete proof
or 100% binding coverage is claimed by the harness bootstrap.

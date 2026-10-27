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
3. Share that control's runner with the explicit registry in `src/lib.rs`. Set the catalog
   row to `done` with the same expected error name. Failed, duplicate, unknown, or mismatched
   registrations cannot earn coverage. Error strings must not expose witness data.

`harness/nc_stub.rs` exercises the full harness sequence on a two-cell fixture. It is
separate from protocol code and has no NC id. It establishes no inference binding.
NC-0801 executes the production transcript registry validator and rejects one duplicated
label with `DuplicateLabel`; it earns configuration coverage only. Including the
seven sumcheck/batching controls and Merkle NC-0602, 9/68 controls run,
59 remain missing, and 3/17 catalog binding categories have proof controls. Range rows expand
to individual ids; malformed and duplicate ids fail.

Coverage is over the current catalog, not a complete enumerated claim graph. Several
rows are still broad categories or lack exact errors. E8-04 must expand those rows and
cross-check the implemented claim graph, PCS checks, and ledger lines. No complete proof
or 100% binding coverage is claimed by the harness bootstrap.

RFC-0012 A1 authorizes a separate `check_configuration` path for the registry
collision control only. It must call the production registry validator on both
honest and one-value-mutated configurations. No-op mutations, honest rejection,
tamper acceptance and wrong errors fail. The harness configuration fixture is
not the production control and earns no catalog credit.

Registrations declare `ControlKind`. Only the registry collision id may be
`Configuration`; it may not be relabelled `Proof`. Configuration passes count
as executed controls, are printed explicitly, and never count toward covered
proof-statement bindings. All proof controls still require real prover/verifier
execution through `check_control`.

RFC-0006 A1 proof-artifact controls use `check_proof_control`: produce and accept
an honest proof, clone it, mutate one declared value through `ProverHook`, and
require the same production verifier's exact rejection. The control asserts the
single-value difference. The helper's self-checks earn no catalog coverage.

E3-01's standalone NC-0200/0201/0205/0800/0802 tests now run both challenge fields
through the real sumcheck engine and public consumer. They are registered in the
coverage inventory; the covered categories do not imply all their controls exist.

NC-0602 authenticates actual Merkle openings for both byte columns and child roots.
Its one-byte leaf and sibling mutations must fail with RootMismatch; membership
does not establish PCS encoding/proximity, query selection or full inference.

E3-02 batching controls live in `src/batching.rs` and run through the real prover/
public verifiers in both modes and fields: NC-0202/0206 and extensions of 0205/0802.
NC-0205 also changes one unclaimed virtual-tensor entry while keeping the initial
claims fixed; the public consumer must reject the false final evaluation.

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
label with `DuplicateLabel`; it earns configuration coverage only. Including the conditional stacked, PCS and closed lookup variants, 41/94 controls run,
53 remain missing, and 9/25 catalog binding categories have proof controls. Range rows expand
to individual ids; malformed and duplicate ids fail.
Streaming NC-0210 uses a real prepared file: change one unused source record,
produce the changed Streaming proof, and apply its single changed final through
ProverHook. Both fields reject it with ClaimMismatch against the original inputs.

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
execution through the applicable accepted-baseline or specifically fixed-statement path.

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

NC-0204 uses the production Small strategy on an unsigned table narrowed from
an original value of 65536. The unused input keeps all round messages unchanged;
exactly one final evaluation changes. Both fields require the unchanged public
consumer to reject with ClaimMismatch against the original table. A constructor
error earns no credit, and typed storage alone supplies no authenticated range proof.

NC-0406..0408 use the native fraction prover and unchanged public original-array
consumer in both fields. Root, unused child and equality-final mutations reject
with the catalog errors. NC-0409/0410 now reject selector and unused original-column finals through the
selected-product prover and actual public source consumer. NC-0409 also changes
one upstream unused tree child, requiring p=sigma_tilde(r) to reject. The conditional
closed field lookup now consumes these results through Table and certified originals;
full private lookup and inference remain unadmitted.

NC-0411 derives one next-layer round value with Gamma before Fraction/Layer or
Fold before Final, then applies only that value to an honest native proof.
NC-0802 also omits the tree/selected-product A1 Final when deriving one final
value for a following real sumcheck. Both fields reject at the catalog boundary.
Exact-order replay must first match the native proof; no alternate verifier or
state import is used. These controls do not add an FS theorem or profile admission.

RFC-0008 A5 §7 fixes false source256/selector1/range_8 statements for NC-0401
and NC-0419. They have no accepted proof under that statement. Keep a separate
accepted source7 sanity fixture; the negative attempt owns its genuine source256
certificate before every outer draw. Apply the one source or early-fitted mu
mutation through ProverHook, regenerate real dependent proofs, and require the
unchanged closed verifier's RootMismatch. Never transfer source7 authority or
claim an accepted baseline for source256. NC-0415 separately checks the static
GroupBound admission boundary, without allocating a fictitious huge witness.

The closed lookup controls also execute NC-0400/0402/0403/0416/0417/0418,
retaining exact failure prefixes. The composed NC-0610 variant changes one mu
opening row value and reaches actual PCS ValueMismatch. The NC-0802 variants
omit Statement, Multiplicities or the first MultiplicityClaims only while
computing one replacement final for a following A1 proof. The submitted lookup
proof stays honest and must close first. Genuine nonzero physical-tail proofs
with zero selected weights are accepted through every structural consumer.

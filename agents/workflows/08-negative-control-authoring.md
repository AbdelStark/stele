# Workflow 08 — Author a negative control
1. Identify the binding (claim-graph edge, PCS check, ledger line, public-input field).
2. Write the control as a test in `tests/negative-controls/<area>/nc_<id>.rs` using the `ProverHook` API to tamper exactly
   one value *after* the honest witness is built; assert the verifier returns the typed error named in `catalog.md`.
3. Add the catalog row: id, binding, RFC section, tamper description, expected error, status.
4. A control that is *accepted* by the verifier is a release blocker and a P0 issue; never weaken the control.

RFC-0012 A1 exception for NC-0801 only: this is registry configuration validation,
not a proof witness. Run the actual core registry validator on an honest registry,
replace exactly one label with another, and require DuplicateLabel. Check honest
acceptance, exact mutation and exact rejection through a dedicated configuration
control path; do not invent a proof verifier or count it as a statement binding.
Production must use the same validation. All proof-witness controls retain steps
1–4 above and the real prover/verifier requirement.

RFC-0006 A1 also permits `check_proof_control`: produce an honest proof through the
real prover, require honest acceptance, clone the proof, apply `ProverHook` to
exactly one declared proof value, and require the unchanged real verifier's exact
rejection. Assert the single-value difference and hold its public statement fixed.
For transcript controls, an adversarial replay using production Transcript/prover
operations may compute the replacement; no state import, injected RNG, test-only
verifier bypass or toy verifier is permitted. This is a proof-artifact control,
not a configuration-validation exception. Honest/prover failures, no-op mutations,
acceptance and wrong errors fail. Witness-first controls retain their existing path.

RFC-0008 A5 §7 fixes false source statements for NC-0401 and NC-0419: genuine
source256, selector1 and range_8. Such a statement has no accepted honest proof.
Keep a separate genuine accepted source7 sanity fixture. For the negative case,
fix its own source256 certificate before every outer draw, declare exactly one
source deviation (0401) or early-fitted mu entry (0419) through ProverHook, and
regenerate genuine dependent registrations/trees/openings. Hold that negative
statement unchanged through the actual verifier and require RootMismatch.
Never reuse source7 authority for source256 leaves or claim an accepted baseline
for the false statement. This narrow Accepted-contract requirement does not
relax any verifier check or the ordinary accepted-baseline control paths.
NC-0415 is the separately specified static descriptor GroupBound boundary;
it requires no fabricated huge proof or claim of proof-statement acceptance.

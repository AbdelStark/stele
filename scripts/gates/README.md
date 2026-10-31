# CI gate contracts (RFC-0020 §5, E0-02)

`cargo fmt`, Clippy, workspace tests, and dependency bans execute directly in CI.
`rfc-status.sh` checks every Rust RFC citation against a unique Accepted document.
`docs-links.sh` checks inline Markdown local file targets in README, docs, and agents;
it does not validate remote URLs or heading fragments. Fenced examples are excluded.

The negative-control gate now validates the suite layout, runs harness tests, and
executes registered controls before reporting catalog coverage. The stub self-control
has no NC id and receives no inference coverage credit. Real transcript/sumcheck/Merkle
controls now run; other protocol source guards remain until their controls exist. Undeclared control source
files and `done` rows without an executable registration fail CI.

The ledger gate runs the Rust validator on `bench/ledger/*.json`; native CPU
measurements are linked from `bench/README.md`.
Locked dependencies are fetched before the offline build and validation steps.

The accounting gate compares the production transcript registry and actual sumcheck
SC receipts against the independent corpus and descriptors. Mutations of the SC
numerator or Final label fail. This covers the implemented reduction, not complete
inference accounting or a profile budget. Remaining unimplemented protocol crates
must match the empty bootstrap snapshots, with no unvalidated artifacts:

| Gate | Replacement task | Required validator |
|---|---|---|
| digest | E8-06 | Generate fixed W8 proofs and compare reference digests |
| negative-controls | E8-04 | Expand the E0-03 harness to actual protocol bindings |
| soundness-accounting | E2-01, E8-05 | Compare transcript challenges to ledger enumeration |
| parity | E10-01 | Compare real CPU/CUDA bytes on the GPU runner |
| ledger-validate | Implemented in E0-05 | Validate measured records with `stele-bench ledger validate` |

`bootstrap-sources.json` fingerprints empty crate manifests and sources. These are
**not proof digests**. Do not refresh this file to accept new protocol behavior.
Implement the validator with its producer, remove the corresponding bootstrap guard,
and replace its scaffold tests with honest acceptance and rejection controls in that task.
Deleted files, added files, and unrecognised artifacts fail closed. There is no bypass flag.

The artifact locations are `tests/digests/`, `tests/negative-controls/`, `tests/soundness/`,
`tests/parity/`, and `bench/ledger/`. `README.md`, `catalog.md`, and `.gitkeep` alone do
not constitute runnable artifacts. The glossary linter reads the forbidden-word list from the glossary and rejects new
occurrences in repository Markdown. `glossary-exceptions.json` records exact existing
lines with reasons and occurrence counts, preserving Accepted RFCs and historical
comparisons. Repeating an exempt line or leaving a stale exception fails the gate.
Exceptions require review; they are not a document-wide opt-out.

`rust-policy.sh` supplements Clippy by rejecting direct floating-point types and literals
in core and control-suite Rust sources, including literals without explicit type annotations.
It skips strings, character literals, and nested comments. Clippy's type/arithmetic lints
are forbidden at workspace level, so source-level lint allowances cannot weaken them.
This is a source policy check, not a proof about macro expansions or third-party API return
types; new macros and dependencies still require review under the existing guardrails.

Required CI runs on pull requests, avoiding duplicate branch/PR and post-merge builds.
Implementation reaches main only through a validated PR with its tested base/tree checked.
The parity job uses the actual Git diff. Push events compare before/after commits;
PR events compare the merge base to the PR head. Rename detection is disabled so
moving a file out of a GPU crate still triggers parity. Initial pushes compare to the
empty tree. Invalid commit metadata fails CI. GPU jobs require a configured self-hosted
GPU runner; this scaffold does not substitute CPU execution for hardware evidence.

The required native job uses `scripts/gates/native.sh` for the digest, control and
accounting union. All actual validators run once; standalone gates stay self-contained.
Quick tooling tests use `python3 scripts/ci_tests.py`. The manual `exhaustive` workflow
partitions copied-source mutation tests into independent jobs. Run all tooling tests locally with:

```sh
python3 -m unittest discover -s scripts/tests -v
```

Tests invoke the shell entry points from outside the checkout and mutate isolated copies.

The control gate also runs actual Merkle root/path/batch tests against RFC-0012 A3
vectors and regenerates those vectors with the independent Python tree oracle.
Root-comparison and batch-authentication bypass mutants fail this gate. Merkle
membership does not certify PCS encoding, query scheduling or a profile budget.

RFC-0006 A7 replaces only the GKR arithmetic scaffold guard: the real six-kind,
120,000-point differential suite runs in both control/accounting gates. A closed
file inventory, exact arithmetic-only module entry and field-only dependency
manifest continue to reject unwired GKR stage/source/transcript additions.
This earns no NC-0203, source authentication or stage accounting coverage. The
bootstrap snapshot is not refreshed; E3-06 still requires its full producer.

RFC-0010 A9 source parsing replaces only the PCS empty-crate guard with actual
native/Python codec and policy checks. Its closed public declaration inventory
rejects new accepting methods and trait conversions inside the existing module;
new consumers need their real validators and controls. Parsed wire bytes carry
no authentication or PCS coverage. Verifier/reductions and other guards remain.

RFC-0012 A10 adds local hash-work observations, including failures. The transcript
and Merkle validators require the actual usage, overflow and byte-vector tests;
successful execution with those tests omitted fails. These counters do not
establish adversarial query caps, PCS correctness or a complete FS/H budget.

The A9 producer validator also executes native source preparation against all
six independent full-wire fixtures. It requires the preparation controls and
each compile-fail API boundary explicitly. Adding an accepting method or trait
conversion to the preparation module still rejects before execution. Preparation
and byte authentication do not supply a verified registration certificate.

The certificate producer consumes the four registered certificate labels and
must match all six native/Python wire fixtures and actual continuation draws.
The hash gate requires capped-sampler threshold, attempt-64, exhaustion,
invalid-domain, failed-attempt and full-ratchet checks. The PCS validator still
rejects accepting APIs or trait conversions in every admitted producer module.
These tests confer no native verification or negative-control coverage.

The certificate verifier validator requires both-field complete-wire/ID and
continuation parity, canonical and authentication-order rejections, and bounded
malformed-wire mutation/truncation sweeps. The private-handle compile-fail check
replaces the former absent-verifier check. Closed API inventories reject digest
constructors, authority-bearing public fields and extra trait conversions;
these inventories complement actual verification tests and code review.
Six native certificate controls run through the existing control harness. No
opening or inference acceptance is admitted by these validators.

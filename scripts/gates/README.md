# CI gate contracts (RFC-0020 §5, E0-02)

`cargo fmt`, Clippy, workspace tests, and dependency bans execute directly in CI.
`rfc-status.sh` checks every Rust RFC citation against a unique Accepted document.
`docs-links.sh` checks inline Markdown local file targets in README, docs, and agents;
it does not validate remote URLs or heading fragments. Fenced examples are excluded.

The negative-control gate now validates the suite layout, runs harness tests, and
executes registered controls before reporting catalog coverage. The stub self-control
has no NC id and receives no inference coverage credit. Protocol source guards remain
until actual controls accompany the first implementations. Undeclared control source
files and `done` rows without an executable registration fail CI.

The remaining protocol gates cannot validate proofs before their producers exist.
They may print `nothing to check` only when the relevant crate files exactly match the
empty bootstrap snapshots and no corresponding artifacts exist:

| Gate | Replacement task | Required validator |
|---|---|---|
| digest | E8-06 | Generate fixed W8 proofs and compare reference digests |
| negative-controls | E8-04 | Expand the E0-03 harness to actual protocol bindings |
| soundness-accounting | E2-01, E8-05 | Compare transcript challenges to ledger enumeration |
| parity | E10-01 | Compare real CPU/CUDA bytes on the GPU runner |
| ledger-validate | E0-05 | Parse benchmark ledgers and reject disabled bindings |

`bootstrap-sources.json` fingerprints empty crate manifests and sources. These are
**not proof digests**. Do not refresh this file to accept new protocol behavior.
Implement the validator with its producer, remove the corresponding bootstrap guard,
and replace its scaffold tests with honest acceptance and rejection controls in that task.
Deleted files, added files, and unrecognised artifacts fail closed. There is no bypass flag.

The artifact locations are `tests/digests/`, `tests/negative-controls/`, `tests/soundness/`,
`tests/parity/`, and `bench/ledger/`. `README.md`, `catalog.md`, and `.gitkeep` alone do
not constitute runnable artifacts. The glossary linter remains assigned to E0-04.

CI runs on pull requests and pushes to main, avoiding duplicate branch/PR builds.
The parity job uses the actual Git diff. Push events compare before/after commits;
PR events compare the merge base to the PR head. Rename detection is disabled so
moving a file out of a GPU crate still triggers parity. Initial pushes compare to the
empty tree. Invalid commit metadata fails CI. GPU jobs require a configured self-hosted
GPU runner; this scaffold does not substitute CPU execution for hardware evidence.

Run gate regression tests with:

```sh
python3 -m unittest discover -s scripts/tests -v
```

Tests invoke the shell entry points from outside the checkout and mutate isolated copies.

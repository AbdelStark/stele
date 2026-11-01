# CI execution policy

Required PR checks focus on implemented native behavior. CI runs on PR events,
including readiness transitions, and does not repeat the same checks after merge.
Before merging, compare the tested PR merge tree with the current main base;
update and revalidate if that base changed. Direct implementation pushes to main
are forbidden by the repository workflow. This is currently a procedural rule;
GitHub branch protection is not configured.

 A ready PR runs format,
Clippy, workspace and example tests, dependency policy, independent digests, the
actual negative-control catalogue, soundness accounting, and repository checks.
`scripts/gates/native.sh` executes the union of digest/control/accounting
validators once. Each standalone gate remains complete.

Cargo's test profile uses optimization level 2 with debug assertions and overflow
checks explicitly enabled. Test cases, seeds, dimensions and required commands
are unchanged. The paired [E0-07 measurement](../../bench/README.md#native-test-profile-e0-07)
records compilation and execution separately; it does not measure full CI or
inference performance. Default dev and release profiles retain their existing
settings. Profile edits still follow the shared-configuration routing below.

Table parity runs when field, polynomial, SIMD or CQIS code changes, including
its test oracle. Dependency and CI routing changes also select it.
The full RFC-0021 corpus is partitioned into 28 case/field jobs, each retaining
its original seed and 10,000 points. No-argument local execution still runs all
280,000 points. A failed or missing shard fails the aggregate. The matrix uses available runner concurrency.

Research, harness and formal changes normally select every research group in
`scripts/research-checks.json`. Research runner, inventory, workflow and shared configuration changes do so as well.
The exact root Cargo.lock path and field/CQIS source changes select the
`native-comparisons` group: seven existing Python-to-Rust comparisons plus their
two pinned checkpoint downloads. Any broad trigger selects all 75 groups instead.
The normal inventory retains the same 176 commands exactly once. This scope
also covers deletions and both names of renamed files; it does not infer scope
from changed lockfile entries. The mandatory native job and all table rules remain.
The exact `formal/stacked-runtime.md`, `formal/stacked-ownership.md` and
`formal/stacked-statement.md` paths select `stacked-gkr`. Combined with native
triggers they select the ordered union of `native-comparisons` and `stacked-gkr`;
any broad trigger still takes precedence. Neighbouring formal paths stay broad.
Matrix generation validates explicit all/native/stacked/native-stacked/none selection; an unknown mode
or missing selected group fails the plan. Default and exhaustive matrices stay complete.
The only research-path exceptions are `research/merkle-oracle/check_field_wire.py`,
`research/stacked-gkr/check_native_wire.py` and their `.lock` files: the mandatory
native gate runs both locked byte oracles and rejects failure or missing output.
Shared oracle modules and all other research paths
retain normal selection. The research matrix uses the available runner concurrency.
Downloads stay ordered with their consumers. Each command retains shell error
and pipeline failure propagation. Native-only changes use their independent
reference checks in the native gates; review must add any affected research
campaign that a new native contract requires.

The manual `exhaustive` workflow retains full-size research experiments in
`scripts/research-full-checks.json`, isolated gate mutations, upstream Poseidon2
regeneration and SIMD throughput ledgers. Run a relevant full-size experiment
before claiming its Draft task or resource criterion complete. Moving an
experiment out of the required merge path supplies no evidence for it. Existing
original proof processes and their source-qualified results remain valid only
for their recorded source and scope.

Quick script tests use `python3 scripts/ci_tests.py`. Full local tooling tests
remain available through `python3 -m unittest discover -s scripts/tests -v`.
The removed positive all-gates regression duplicated the real native job;
all copied-source rejection tests remain in the exhaustive workflow.

The required `gates` job rejects failed, cancelled, missing or unexpectedly
skipped checks. A scoped check may be skipped only when a successful plan
explicitly excludes it. Draft runs never provide merge evidence. GPU changes
still require the actual GPU runner. Dependency/build caches store no pass
receipts, and every selected check executes again.

E0-06 replaces the former policy of making every accumulated research campaign
mandatory on every PR. The integration retains all published source histories
and the complete inherited command union, including local committed research.
No protocol behavior, soundness term, cost-model constant, weight pass or native
sample count changes with this scheduling decision.

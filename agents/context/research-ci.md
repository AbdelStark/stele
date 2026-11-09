# CI execution policy

Required PR checks focus on implemented native behavior. CI runs on PR events,
including readiness transitions, and does not repeat the same checks after merge.
Before merging, compare the tested PR merge tree with the current main base;
update and revalidate if that base changed. Direct implementation pushes to main
are forbidden by the repository workflow. This is currently a procedural rule;
GitHub branch protection is not configured.

A ready PR starts two mandatory jobs after the plan. `native` runs format,
Clippy, workspace and example tests, dependency policy, quick tooling tests,
scoped feature checks, native SIMD parity and repository checks. `native-union`
runs the unchanged `scripts/gates/native.sh` digest/control/accounting union,
including the actual negative-control catalogue. Neither job depends on the
other; both check out the same event merge source and perform their own locked
dependency fetch. Each standalone gate remains complete.

The two jobs use separate Cargo cache keys and restore prefixes. Caches contain
dependencies and build outputs only; a cache hit never skips validation. Separate
runners can duplicate setup and compilation, and runner queues can delay either
job. Job scheduling alone does not establish a measured latency improvement.

Cargo's test profile uses optimization level 2 with debug assertions and overflow
checks explicitly enabled. Test cases, seeds, dimensions and required commands
are unchanged. The paired [E0-07 measurement](../../bench/README.md#native-test-profile-e0-07)
records compilation and execution separately; it does not measure full CI or
inference performance. Default dev and release profiles retain their existing
settings. Profile edits still follow the shared-configuration routing below.

All five direct `stele-controls --coverage` callers select this existing test
profile for the ordinary binary, preserving default features and runtime checks.
The gates still execute the complete catalogue and propagate failures. Fraction
and streaming benchmark preflights use the same selection outside their timed
workers. The [E0-09 pair](../../bench/README.md#control-coverage-profile-e0-09)
records cold compilation and direct execution separately on identical source.

The gate launches the lookup parity corpus with dev-profile optimization level 2,
debug assertions and overflow checks explicitly enabled in that child process.
These match the checked test-profile settings while preserving the pinned oracle
source and its Cargo command. Other gate subprocesses retain their environment.
All 88 requests, independent expectations, comparisons and failure handling remain.
The [E0-10 measurements](../../bench/README.md#lookup-corpus-profile-e0-10)
separate cold-build and execution costs; they do not measure full CI.

Table parity runs when field, polynomial, SIMD or CQIS code changes, including
its test oracle. Dependency and workflow changes also select it.
The full RFC-0021 corpus is partitioned into 28 case/field jobs, each retaining
its original seed and 10,000 points. No-argument local execution still runs all
280,000 points. A failed or missing shard fails the aggregate. The matrix uses available runner concurrency.

Research, harness and formal changes normally select every research group in
`scripts/research-checks.json` and `scripts/model-contract-checks.json`.
The inherited research inventories, workflow and shared configuration changes do so as well.
The exact root Cargo.lock path and field/CQIS source changes select the
`native-comparisons` group: seven existing Python-to-Rust comparisons plus their
two pinned checkpoint downloads. Any broad trigger selects all 76 groups instead.
The normal inventory retains the inherited 176 commands exactly once and adds
the bounded RFC-0024 algebra checker to `algebra` (177 inherited commands).
E15-04 adds the R-BF16 reduction and cost checkers to `algebra` (179 commands).
E4-01 adds the one-sided v2 distance estimate to `code` (180 commands).
RFC-0010 A3 adds the exact v2 expander query-policy checker to `algebra` (181 commands).
The separate model-contract inventory adds one locked regression command. This scope
also covers deletions and both names of renamed files; it does not infer scope
from changed lockfile entries. Both mandatory native jobs and all table rules remain.
The exact `formal/stacked-runtime.md`, `formal/stacked-ownership.md` and
`formal/stacked-statement.md` paths select `stacked-gkr`. Combined with native
triggers they select the ordered union of `native-comparisons` and `stacked-gkr`;
any broad trigger still takes precedence. Neighbouring formal paths stay broad.
Changes under `research/cqis-model-contract/`, its `docs/rfcs/full-model-*`
appendices, RFC-0025 and its separate inventory select `model-contract`.
Its independent oracles cover all nineteen bound schemas and the complete
source/numerical/outer-identity joins on bounded regression cases. They invoke
no historical campaign main. The original full qualifications and named-model
delivery criteria remain separate; a short regression grants neither credit.
Changes to imported checkpoint/table helpers still select every research group.
Native, stacked and model selections compose as an ordered union, with broad
triggers taking precedence. The inherited inventories and commands are unchanged.

Planner/runner/aggregate edits (`ci_scope.py`, `research_ci.py`, `ci_result.py`)
run their mandatory tooling tests without invalidating numerical corpora merely
because routing code changed. These tests check all selection unions, broad
precedence, deleted/renamed paths, exact inherited inventories, failure propagation
and missing/skipped results. A change to an actual shared input still selects
its numerical checks. Neither native job nor a selected check can use cached success.

Matrix generation validates explicit all/native/stacked/model/none and union selections; an unknown mode
or missing selected group fails the plan. Default and exhaustive matrices stay complete.
The additional research-path exceptions are `research/merkle-oracle/check_field_wire.py`,
`research/stacked-gkr/check_native_wire.py` and their `.lock` files: the mandatory
native gate runs both locked byte oracles and rejects failure or missing output.
Shared oracle modules and all remaining research paths
retain normal selection. The research matrix uses the available runner concurrency.
Downloads stay ordered with their consumers. Each command retains shell error
and pipeline failure propagation. Native-only changes use their independent
reference checks in the native gates; review must add any affected research
campaign that a new native contract requires.

The manual `exhaustive` workflow retains full-size research experiments in
`scripts/research-full-checks.json`, isolated gate mutations, upstream Poseidon2
regeneration and SIMD throughput ledgers. E5-05 adds `cqis-torch-parity`: the
1000-model torch-executor parity check, kept out of the merge path because it installs
torch. Run a relevant full-size experiment
before claiming its Draft task or resource criterion complete. Moving an
experiment out of the required merge path supplies no evidence for it. Existing
original proof processes and their source-qualified results remain valid only
for their recorded source and scope.

Quick script tests use `python3 scripts/ci_tests.py`. Full local tooling tests
remain available through `python3 -m unittest discover -s scripts/tests -v`.
The removed positive all-gates regression duplicated the real native job;
all copied-source rejection tests remain in the exhaustive workflow.

The required `gates` job requires success from the plan and both native jobs and
rejects failed, cancelled, missing or unexpectedly skipped checks. A scoped check
may be skipped only when a successful plan
explicitly excludes it. Draft runs never provide merge evidence. GPU changes
still require the actual GPU runner. Dependency/build caches store no pass
receipts, and every selected check executes again.

E0-06 replaces the former policy of making every accumulated research campaign
mandatory on every PR. The integration retains all published source histories
and the complete inherited command union, including local committed research.
No protocol behavior, soundness term, cost-model constant, weight pass or native
sample count changes with this scheduling decision.

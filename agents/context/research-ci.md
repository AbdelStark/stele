# Research CI

RFC-0020 §5 requires the repository gates to reject failed checks. E5-03 adds
full-table and range consumers to a serial job that already approaches the
GitHub-hosted [six-hour job limit](https://docs.github.com/en/enterprise-cloud%40latest/actions/reference/limits).
Splitting execution must preserve the complete check inventory and fail closed.

Before implementation, the migration requirements are:

- Preserve all 109 research/harness/download commands from main at
  `b6560ce508cae728931419433ad9662281afe233`, including every argument,
  pinned checkpoint revision and quoted RUNNER_TEMP path.
- Keep download/consumer sequences in one group and in their existing order.
- Retain the native gates, exact upstream Poseidon check, SIMD throughput and
  GPU scope logic. Pin the same Rust/Python/uv setup for research jobs.
- Keep `gates` as the required aggregate check. It must fail for failure,
  cancellation, skipping or missing results in planning, native or research jobs.
- Generate the complete research matrix from the inventory, reject empty or
  duplicate entries, and bound job concurrency without cancelling other groups
  when one fails. A failing command stops its group and fails the aggregate.

The original sorted command inventory has SHA-256
`951c0646ac98a6267f8e8d02d2dee672c993b3857ae68607b325c02553e10eb2`.
Tests must verify this independent migration snapshot, real shell failure and
environment behavior, command ordering, and aggregate success/failure states.
This changes CI orchestration only; protocol behavior, soundness terms,
production controls and model weight passes are unchanged.

`scripts/research-checks.json` now assigns those commands to eleven groups.
`scripts/research_ci.py` validates the inventory, emits the matrix, and runs each
group in order with Bash error and pipeline failure propagation. The workflow
runs at most four research groups concurrently. The required `gates` job checks
the results of planning, native checks and the complete research matrix.

Local migration tests preserve the command digest, exercise real shell failure,
check inherited paths containing spaces, and reject every incomplete combination
of the three prerequisite results. A structural comparison against the original
workflow preserves native steps, setup pins and the other jobs exactly, with
scope detection moved to `plan`. These checks establish orchestration behavior;
they do not measure prover performance or predict hosted execution time.

To add a research check, add its exact command to the inventory and explicitly
update the tested count and digest. Keep fixture downloads with their consumers.
Split heavy groups when necessary; every resulting group remains mandatory.

All nine targeted CI tests and the seven real algebra commands passed.
All required local repository gates passed. The full scripts test suite is
still running; hosted validation remains pending. Full proving,
native/private inference and the original E5-03 acceptance criteria remain open.

Draft PRs now defer expensive jobs. The plan job runs for ready PRs and main
pushes; independent full-size jobs and the upstream reference job depend on
that plan. Native and research jobs already have this dependency. No command,
matrix mode or required success assertion is removed.

The aggregate still runs with `always()` and fails when any prerequisite is
skipped, including a draft's skipped plan. A draft run is not merge evidence.
Both `ready_for_review` and `converted_to_draft` trigger a run, alongside the
original opened/synchronize/reopened events. Ready PRs run the full inventory.
Readiness transitions do not themselves cancel older runs; reconciliation
must compare actual head/base/event before accepting or retiring evidence.

Tests first reproduced the missing readiness event and independent-job
dependency. The corrected workflow tests reject a draft's skipped results
and each incomplete prerequisite; existing inventory and aggregate tests
remain mandatory. This schedules validation and does not grant acceptance
to unvalidated work.

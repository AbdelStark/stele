# Research CI

RFC-0020 §5 requires the repository gates to reject failed checks. E5-03 adds
full-table and range consumers to a serial job that already approaches the
GitHub-hosted [six-hour job limit](https://docs.github.com/en/enterprise-cloud%40latest/actions/reference/limits).
Splitting execution must preserve the complete check inventory and fail closed.

Before implementation, the migration requirements are:

- Preserve all109 research/harness/download commands from main at
  `b6560ce508cae728931419433ad9662281afe233`, including every argument,
  pinned checkpoint revision and quoted RUNNER_TEMP path.
- Keep download/consumer sequences in one group and in their existing order.
- Retain the native gates, exact upstream Poseidon check, SIMD throughput and
  GPU scope logic. Pin the same Rust/Python/uv setup for research jobs.
- Keep `gates` as the required aggregate check. It must fail for failure,
  cancellation, skipping or missing results in either native or research jobs.
- Generate the complete research matrix from the inventory, reject empty or
  duplicate entries, and bound job concurrency without cancelling other groups
  when one fails. A failing command stops its group and fails the aggregate.

The original sorted command inventory has SHA-256
`951c0646ac98a6267f8e8d02d2dee672c993b3857ae68607b325c02553e10eb2`.
Tests must verify this independent migration snapshot, real shell failure and
environment behavior, command ordering, and aggregate success/failure states.
This changes CI orchestration only; protocol behavior, soundness terms,
production controls and model weight passes are unchanged.

Implementation and hosted validation are pending. Full proving, native/private
inference and the original E5-03 acceptance criteria remain separate requirements.

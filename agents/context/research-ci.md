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

The range-capacity continuation preserves122 research/harness/download commands
in24 mandatory groups, with inventory SHA-256
`2be86f40afb3532b80c7a1116b54226f0713079db84e494b495f6f3e2d3a01c7`.
All33 native/setup steps and four independent jobs remain unchanged. The three
standalone full-capacity jobs (wide, signed, normxy) retain their exact commands,
setup and unconditional matrix. The required aggregate now also waits for that
entire matrix and rejects missing, skipped, cancelled or failed capacity results.
Ten targeted CI tests passed, including all625 prerequisite-result combinations
and the three full-job inventory. Local implementation gates were already passed
and were not repeated for this CI-only merge. Hosted validation and the remaining
local maximum signed32/xy proofs are pending; no verifier or proof check changed.

The norm-product continuation retains the122 inherited commands and adds one
normal product group, giving123 commands in25 groups. The complete16384-row
product runs in its own unconditional required job; the other six CLI modes
remain in the normal group. An AST-based inventory check requires every script
mode to appear in one of these paths. All three capacity jobs and all33 native/
setup steps are unchanged. The aggregate also requires norm-product-full.
Eleven targeted tests passed, including success and each failure/cancellation/
skip/missing result for every prerequisite, plus joint outcomes. This keeps the
failure checks linear as required full-row jobs are added. Implementation and
full-row proof gates had already passed; hosted validation remains pending.

The norm-sign continuation adds one normal group, for 124 commands in 26
groups, with inventory SHA-256
`256119419ab91d62fedf2cc7eca169361865176d5a71414d0c7d205c228ac542`.
Its five normal modes and separate required norm-sign-full job cover every
CLI mode. All inherited jobs and 33 native/setup steps remain unchanged.
The aggregate also requires sign success and rejects failure, cancellation,
skip or missing results. Eleven targeted tests passed. The existing full-row
sign proof remains running; hosted checks and that result remain pending.
Implementation gates had passed and were not repeated for this CI-only merge.

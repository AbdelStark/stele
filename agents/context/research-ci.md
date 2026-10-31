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

The full-row norm-statistic continuation adds one group, for 125 commands in
27 groups, with inventory SHA-256
`ff69c32483b95bd63979af1752ee9e8e40b298885a94b97a58396746749d6d65`.
Its six normal modes and separate required norm-statistic-full job cover every
CLI mode. All inherited jobs and 33 native/setup steps remain unchanged.
Eleven targeted tests passed, including every prerequisite's non-success
results. The statistic's local matrix, full 16384-element proof and required
implementation gates had already passed; those were not repeated for this
CI-only merge. Hosted checks remain pending.

The quotient-product continuation adds one group, for 126 commands in 28
groups, with inventory SHA-256
`fc8e27d3c5d048ac58b9d19b5e220b9a70683e7b47cfa2f60b22d1dec41f67b7`.
The six normal modes include the four intermediate-width proofs. A separate
required norm-quotient-product-full job retains the complete 16384-row proof
with a 90-bit divisor. All inherited jobs and 33 native/setup steps are
unchanged. Eleven targeted tests passed, including exact CLI-mode coverage
and every prerequisite's non-success results. Local implementation gates
had passed; the existing maximum proof continues. Hosted checks remain pending.

The norm-bias continuation adds one group, for 127 commands in 29 groups,
with inventory SHA-256
`6f3256cc047a148e3fd81dd6851ee7211d0332f193f17540584b689e9df31c91`.
Five normal modes and the separate required norm-bias-full job cover every
CLI mode. All inherited jobs and 33 native/setup steps remain unchanged.
Eleven targeted tests passed, including prerequisite failures and missing
results. Local implementation gates had passed; the existing full-row proof
continues. Hosted checks remain pending.

The norm-division continuation adds one group, for 128 commands in 30 groups,
with inventory SHA-256
`5e8840bfaf6d53ddd01448f45f40f43976f00f9b2f523e8727248c66a4c27fc5`.
The six normal modes retain the explicit alias and 75-transition controls.
A separate required norm-division-full job covers the complete row. All
inherited jobs and 33 native/setup steps remain unchanged. Eleven targeted
tests passed, including every CLI mode and non-success prerequisite result.
Local implementation gates had passed; the existing full-row proof continues.
Hosted checks remain pending.

The norm-left continuation adds one group, for 129 commands in 31 groups,
with inventory SHA-256
`73fb20b44999e1f4d1a7647246ebb7d8dfc8b8c617a49027a6a67311a01db14d`.
Five normal modes and two unconditional full-row matrix jobs cover every CLI
mode. Both maximum and full-nonzero are required, with fail-fast disabled.
The CLI inventory test first rejected an omitted full-nonzero mode; all 11
targeted tests then passed with both jobs present. All inherited jobs and 33
native/setup steps remain unchanged. Local implementation gates had passed;
the original sequential full-row run continues. Hosted checks remain pending.

The signed-output continuation adds one group, for 130 commands in 32 groups,
with inventory SHA-256
`51764b8cfc293ff23d61911befcc85284d632d7d7676f2069d8c6eee6efe830b`.
Six normal modes retain the explicit rounded-zero controls. A separate
required full-row job completes CLI coverage. Both inherited left-factor
full-row jobs and every other job remain unchanged, including 33 native/
setup steps. All 11 targeted tests passed. Local implementation gates had
passed; the original full-row proof continues. Hosted checks remain pending.

The configured-output continuation adds one group, for 131 commands in 33
groups, with inventory SHA-256
`4deb7856d3f10b01ebc3093950c7ce15949eeff4a96dd02db4a89671d5bccdd9`.
Four normal modes and three unconditional full-row matrix jobs cover every
CLI mode: maximum, full-left and full-right. All three results are required
and fail-fast is disabled. Every inherited job and all 33 native/setup steps
remain unchanged. All 11 targeted tests passed. The original local gate run
and sequential full-row proofs continue; hosted checks remain pending.

The normalization-composition continuation adds five groups, for136 commands
in38 groups, with inventory SHA-256
`9f7e9822e357a8c82b8b30897a9283b7ed72581799ef5a77ea18671915448d7a`.
The corpus and controls share one group; each field/repetition combination
has its own required group. Three unconditional full-row jobs cover maximum,
full-left and full-right. Every proof retains the complete reciprocal table.
All inherited jobs and33 native/setup steps remain unchanged. Eleven targeted
tests passed, checking every CLI mode and every non-success prerequisite
result. Local matrix/gate runs continue; full-row cases remain queued behind
the matrix. Hosted checks remain pending.

The residual-alignment continuation adds one group, for137 commands in39
groups, with inventory SHA-256
`5d8985d1837ccded0032f019328a3dbb097f9187e72ad47ebddf2429497ae560`.
Five normal modes retain the four no-carry proofs and their original-value
controls. A separate unconditional residual-aligned-full job requires the
complete row. Every inherited command/job and33 native/setup steps remain
unchanged. All11 targeted tests passed, including exact CLI coverage and
non-success prerequisite rejection. The original full-row proof continues;
local gates are queued behind normalization composition. Hosted checks remain
pending.

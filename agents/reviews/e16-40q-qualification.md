# E16-40q source qualification — prepared, not submitted

Source `6034113f67ace10258b48c90e973db291a0a4d99`; implementation
[reviews](e16-40q-resident-source.md) pass. Both fresh capture reviews approve
preparation readiness. No E16-40q job has been submitted; accepted actual m then n
qualification evidence must precede submission.

Independent `resident_capture_spec_review` (owning lane E) and
`resident_capture_standards_review` (lane B) verified source/archive identity,
all package hashes, exact test selection and fail-closed receipts. The archive
contains 2,404 files and 226 directories, with paths, modes and bytes matching Git.
Both reviewed bounded commands, case progress and process-group cleanup.
The standards reviewer independently mutation-tested the old machine/host receipt
collision; the regression rejects it.

The frozen release build selects three test binaries. Six exact tests cover host
payload parity, invalid payloads, complete host material, thread-count parity,
required resident CUDA responses and required complete-material CUDA parity.
Device receipts require all 1,000 resident start/pass pairs and 8,000 requests,
plus the existing complete-material corpus. Missing/duplicate artifacts, empty
inventories, skips and altered counts reject. Machine metadata remains separate
from the CPU command receipt.

The scheduler requests one H100, 16 CPUs, 64 GiB, two hours and no requeue.
The campaign deadline is 6,600 seconds, with bounded individual commands and a
120-second resident-case deadline. Failure output and manifests are preserved.
Linux Python 3.12.3 passed all six capture controls, zero skips; preflight log
SHA-256 `dce701621736b0c94d20bcc5e7800212dc52724ba2a4b778fd8d0c4247a72cf4`.

[Pins](e16-40q-qualification-pins.json) SHA-256:
`f441c73f4790ff0eb3e818e79b2a64e68fa961d594347b0af71959d9b2564a9d`.
Package and review receipt:
`/Users/abdel/dev/stele-validation/e16-40q-qualification/`.
An equal remote package is staged under `~/stele-codex/e16-40q-qualification`;
no execution directory exists.

Actual H100 evidence, fresh evidence review and mandatory gates on current main's
intended merge tree remain required. This approval grants no GPU proof,
performance, full device-memory or ADR-127 GO credit.

## Terminal auditor readiness

The [terminal auditor record](e16-40q-terminal-audit.json) pins the external
auditor and its three passing synthetic controls. Independent owning-lane E
`resident_terminal_spec_review` and lane-B `resident_terminal_standards_review`
both PASS at those hashes. Each independently ran the tests and checked the pins.
The approved E16-40n auditor is adapted only for this package's paths, pins,
third binary, build flag and expected counters. Its strict timing, scheduler,
manifest, archive and current-readback checks remain intact. Capture pins have
not changed. This records readiness to audit a future completed job; it is not
actual hardware evidence, and no terminal audit has been run on an actual archive.

## Strict GNU timing revision

The [GNU timer revision](e16-40q-gnu-time-audit.json) supersedes the auditor hashes
above. Review of the sibling GKR auditor found that the shared parser could
prefer appended BSD timing or the first of duplicate GNU fields. The auditor
now rejects mixed formats and requires unique, anchored GNU wall/RSS fields.
Four resealed mutation cases failed before this fix; all four auditor tests now
pass. Fresh `gkr_terminal_spec_review` and `gkr_terminal_standards_review` approve
the same limited fix in m/n/q and independently ran every package's tests.
Capture, source, commands and package pins remain unchanged. Actual m evidence
has passed both reviews; q submission still waits for accepted actual n evidence
from its single submitted job **6772**.

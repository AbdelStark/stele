# E16-40n boundary qualification — submitted

Pinned source: `e192fe0b6d4ec604c4d8e922c187532049c8a5dc`.
The [implementation reviews](e16-40n-implementation.md) and both fresh capture
reviews pass. Job **6772** was submitted after E16-40m's actual qualification
evidence passed both independent reviews. Actual n evidence remains pending.

Independent reviewers `boundary_capture_spec_review` and
`boundary_capture_standards_review` verified every package hash and all 2,389
archived entries against Git, including file types and modes. They checked exact
binary/test selection, complete canonical/raw coverage, original source-material
comparisons, fail-closed receipts, deadlines and descendant cleanup.

The frozen release build selects the library and `source_material` test binaries.
Four exact tests cover the host boundary corpus, production source material, H100
boundary operations, and the original complete-source H100 corpus. Hardware tests
are explicitly executed with `--ignored`, and missing, duplicate, skipped or
altered success records fail. Boundary coverage requires every one of 1,000 cases,
eleven operations and both field representations. The source test compares all
original 1,000 cases with production preparation: roots, every payload, every
sibling path and the existing payload-tampering control.

Linux Python 3.12.3 passed all five capture controls without skips, including
nonzero-command rejection, case/campaign deadlines and descendant termination.
The command, boundary-case and campaign limits fit inside the scheduler limit;
there is no retry/requeue. The script permits only the inventoried H100 NVL/SXM
hosts and requires H100 identity. Partial output, failures, command metadata and
hash manifests are retained.

Current [pins](e16-40n-qualification-pins.json) SHA-256:
`90ac22ed5e35f88b29288576eb1d26f7b442591ec53bdee59d8f72eef5d1fab6`.
The replayable capture package and review receipt are retained at
`/Users/abdel/dev/stele-validation/e16-40n-qualification/`; the Linux preflight log
is the sibling `e16-40n-linux-preflight.log`. A staged remote copy exists, but it
has no scheduled job.

Actual hardware qualification, mandatory native/parity/ladder gates and
current-main/intended-merge-tree CI remain pending. Capture approval supplies no
integrated GPU-proof, performance, complete-memory or ADR-127 GO credit.

## Machine-metadata collision repaired before execution

The CPU command labeled `host` writes `host.json`, which previously overwrote
the machine metadata under the same name. The metadata now uses `machine.json`;
all command receipts keep their existing names. No source, archive, kernel,
command, corpus, process runner, scheduler script or deadline changed.

Original capture/test/pins/review files are preserved locally and remotely in
`before-machine-receipt-fix/`. The new regression exercises actual `capture.main`,
writes the host command receipt through a synthetic runner, then raises. It
checks both records and their hashes remain in the failed manifest. It failed
against both original captures and passes after the filename fix.

Fresh `machine_receipt_spec_review` (owning GPU) and
`machine_receipt_standards_review` (lane B) both PASS this limited repair.
Linux preflight passed all 6 capture controls without skips, with remote pin
equality checked. [Repair receipt](e16-40n-machine-receipt-repair.json) records
old/new pins, reviews and the preflight hash. No hardware evidence is claimed.

This preparation preceded submission; the accepted E16-40m evidence and actual
submission are recorded below.

## Terminal auditor prepared and independently reviewed

The local-only `verify.py` and `test_verify.py` now have three passing synthetic
controls. They cover exact command/resource/test records, resealed semantic
tampering, safe archive membership, and the full terminal/readback path including
an unchanged repeated audit. GNU time's recorded command must match the expected
executable and arguments. These controls never supply hardware evidence.

Fresh `boundary_terminal_spec_review` and `boundary_terminal_standards_review`
identified two gaps: a no-restarts record could belong to another job, and
recorded deadline overruns were not bounded. New regressions failed before the
fixes and pass afterward. The auditor now requires exactly one single-line
`scontrol show job -o JOB` record with the requested JobId and unique zero-valued
Requeue/Restarts fields. It bounds command and campaign elapsed time, checks
UTC/monotonic agreement and separately bounds GNU wall time. Cleanup allowance
covers the process runner's two bounded waits plus polling/bookkeeping.

Both reviewers independently reran the controls and approved the revised
auditor; the standards reviewer also rejected a coherent GNU-wall overrun.
[Audit receipt](e16-40n-terminal-audit.json) pins scripts, the preserved original
auditor, red/green logs and review outcomes. Capture pins, source archive,
commands and scheduler are unchanged. Actual execution, terminal collection and
fresh hardware evidence review remain pending.

## Strict GNU timing and submission

The [GNU timer revision](e16-40n-gnu-time-audit.json) supersedes the auditor hashes
above. Review of the sibling GKR auditor found that the shared parser could
prefer appended BSD timing or the first of duplicate GNU fields. The auditor
now rejects mixed formats and requires unique, anchored GNU wall/RSS fields.
Four resealed mutation cases failed before this fix; all four auditor tests now
pass. Fresh `gkr_terminal_spec_review` and `gkr_terminal_standards_review` approve
the same limited fix in m/n/q and independently ran every package's tests.
Capture, source, commands and package pins remain unchanged.

Both fresh [E16-40m actual evidence reviews](e16-40m-h100-review.md) accepted job
6733 before submission. Remote n pins were rechecked; no earlier run, campaign
log or submitted-job record existed. The single submitted n job is **6772**;
its readback confirms one H100, 16 CPUs, 64 GiB, the existing two-hour limit,
feature constraint `h100|h100nvl`, zero requeues/restarts and the pinned campaign.
`stele-validation/e16-40n-submission.log` retains that readback. Actual n terminal
evidence, fresh review and mandatory merge gates remain pending.

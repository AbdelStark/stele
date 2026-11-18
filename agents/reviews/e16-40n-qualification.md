# E16-40n boundary qualification — prepared, not submitted

Pinned source: `e192fe0b6d4ec604c4d8e922c187532049c8a5dc`.
The [implementation reviews](e16-40n-implementation.md) and both fresh capture
reviews pass. No E16-40n hardware job has been submitted. Submission waits for
E16-40m's actual qualification and accepted evidence.

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

No job has been submitted; E16-40m qualification and accepted evidence still precede submission.

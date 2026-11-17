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
`155b99f11cbf581d261c9429a46c84ed1fb413220cc15908340fd58d4cd7648b`.
The replayable capture package and review receipt are retained at
`/Users/abdel/dev/stele-validation/e16-40n-qualification/`; the Linux preflight log
is the sibling `e16-40n-linux-preflight.log`. A staged remote copy exists, but it
has no scheduled job.

Actual hardware qualification, mandatory native/parity/ladder gates and
current-main/intended-merge-tree CI remain pending. Capture approval supplies no
integrated GPU-proof, performance, complete-memory or ADR-127 GO credit.

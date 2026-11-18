# E16-40m bounded GKR qualification — queued

Source `86d503b3edbc3379a5887d656b858c1e334d09fd` has the
[implementation reviews](e16-40m-implementation.md). The single submitted
Lucid job is **6733**. No hardware result is available yet.

Fresh capture reviewers `gkr_capture_spec_review` and
`gkr_capture_standards_review` both passed the qualification package. They checked
all 2,381 archived entries against Git, exact command selection, complete ordered
receipts, fixture-derived geometry and independent transfer/capacity accounting.
The expected corpus has 2,728 genuine GKR steps, each in canonical and raw lazy
form, with all 1,000 ordinary CPU proofs verified. Every compact slot is checked
before expansion and routing. The H100 capture runs honest, malformed/storage and
device controls and rejects absent CUDA, skips or incomplete cases.

The candidate has command/case/campaign deadlines, isolated process groups with
TERM/KILL cleanup, persistent failure metadata, and no retry/requeue. Linux
Python 3.12.3 passed all seven capture controls without skips before submission.

## Allocation change before execution

Both H100 NVL nodes were administratively drained. Job 6733 remained pending with
zero runtime, unknown start, no allocation and zero restarts. The job was held;
the original capture and pins were retained under `allocation-nvl/`. Only the
capture's host policy changed: it accepts the three inventoried H100 NVL/SXM
hosts and still requires the actual CUDA device to identify as H100.

Both capture reviewers passed this delta, and all seven Linux controls passed
again. The same queued job now has an empty required-node list and feature
constraint `h100|h100nvl`; it was released after the effective request was read
back. CPU count, memory, all deadlines, source, corpus, commands and stored batch
script are unchanged. This is one submission with no execution or retry yet.
The submitted script's original node directive is superseded by the recorded
scheduler override. No other user's allocation or reservation was changed.

Current [pins](e16-40m-qualification-pins.json) SHA-256:
`7878bd1e3f338a751d4af8bb77f52d27c8182e17b568cae1347d6f9cb732da93`.
The replayable package, saved original pins, reviewed allocation record and
preflight evidence are retained at
`/Users/abdel/dev/stele-validation/e16-40m-qualification/`. Scheduler readbacks are
sibling `e16-40m-{held-allocation,allocation-override,released-allocation}.log`.

Actual H100 qualification and mandatory current-main/intended-merge-tree gates
remain pending. This supplies no integrated GPU proof, performance, complete
pipeline-memory or ADR-127 GO credit.

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
Linux preflight passed all 8 capture controls without skips, with remote pin
equality checked. [Repair receipt](e16-40m-machine-receipt-repair.json) records
old/new pins, reviews and the preflight hash. No hardware evidence is claimed.

Job 6733 was held while still unstarted, with zero runtime and no allocation.
After both reviews, a live check verified every remote pin, the held state and
absence of a run directory. The same job was released; readback remained pending,
with zero runtime, no allocation and zero restarts. No resubmission occurred.
The release readback hash is retained in the repair receipt.

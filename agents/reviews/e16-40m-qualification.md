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
`46eb856bade23cccb0d4906331484231ab69956270a832b63ab2b72e32413e6b`.
The replayable package, saved original pins, reviewed allocation record and
preflight evidence are retained at
`/Users/abdel/dev/stele-validation/e16-40m-qualification/`. Scheduler readbacks are
sibling `e16-40m-{held-allocation,allocation-override,released-allocation}.log`.

Actual H100 qualification and mandatory current-main/intended-merge-tree gates
remain pending. This supplies no integrated GPU proof, performance, complete
pipeline-memory or ADR-127 GO credit.

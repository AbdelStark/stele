# E16-40l fixed-code qualification

Lucid job **6732** completed successfully on H100 NVL. Source
`753020550ba21a6d803dba3fc39105f448179543` is the single reviewed candidate;
there was one submission, no requeue and no restart. The
[pins](e16-40l-qualification-pins.json) and [receipt](e16-40l-h100.json)
identify the source archive, capture, device, binaries and raw evidence.

## Before submission

Fresh owning-GPU/spec and another-lane standards reviewers
`descriptor_capture_spec_review` and `descriptor_capture_standards_review`
both passed the capture package. Each checked every archived entry against Git,
the original inventory, strict receipts, process-group cleanup and source pins.
The implementation reviews are [recorded separately](e16-40l-implementation.md).
Linux Python 3.12.3 preflight passed all seven controls with no skips, including
descendant termination. The script has no retry path and disables requeue.

## Observed result

- Original CPU and GPU inventory: all 1,000 cases, with initial tables, every
  polynomial and every folded table equal. The complete CPU case digests match
  the unchanged reference from failed job 6730.
- Explicit production shapes 9 and 11: construction, preparation, rounds and
  folds equal. Both earlier preparation failures are covered.
- Representative relation/GKR rounds at the original 8/12/16/20 exponents pass.
- Fixed descriptor path: 1,000 canonical and 1,000 raw lazy cases, including
  coefficients, mixed storage, masks, repeated factors and empty products.
- Resident batch path: all existing canonical/raw construction and dense
  round/fold cases pass, including the claimed-value near miss.
- Descriptor uploads, round pointer/type transfers and retained capacities
  match independently derived geometry for every original inventory case.

The coordinator verified all 50 manifest payload hashes, exact commands,
successful sequential completion, test receipts and the current remote binary
hashes. The actual incomplete/duplicate-case mutations are rejected. Evidence
manifest SHA-256 is
`442b0b388ce59b7786825d8564dd342f66e96ddafabd64342368722119a06f7f`.
Raw files and the replayable verification script are retained at
`/Users/abdel/dev/stele-validation/e16-40l-qualification/`; scheduler and binary
readback are in the sibling `e16-40l-terminal.log`. Independent post-execution
review and mandatory current-main/intended-tree gates remain pending.

This closes the original reduced-inventory preparation question for this source.
The old failures remain evidence; neither archived failed candidate was retried.
E16-40d, E16-40k and E16-40l stay in progress until their remaining merge
requirements are met. There is no compact-final, actual-size, integrated-proof,
performance, complete pipeline memory or ADR-127 GO claim. The full goal still
requires actual integrated GPU proving and 50 complete CPU/GPU proof pairs.

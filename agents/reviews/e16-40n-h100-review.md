# E16-40n actual H100 boundary qualification review

Development research, lane V. The single Lucid job **6772** completed `0:0`
on H100 NVL with zero requeues/restarts, after E16-40m evidence was accepted.
Source `e192fe0b6d4ec604c4d8e922c187532049c8a5dc`; unchanged pins
`90ac22ed5e35f88b29288576eb1d26f7b442591ec53bdee59d8f72eef5d1fab6`.
The [hardware receipt](e16-40n-h100.json) preserves all 38 payload hashes,
resource records and source/archive/manifest/executable identities.

## Spec — owning GPU lane

`boundary_actual_spec_review`: PASS. Independently matched all 2,389 source files
and their modes/types to Git; checked every pin and evidence payload, both current
executable readbacks, exact commands, chronology, deadlines and actual H100 identity.

All four exact tests pass without skips. Source and ordered receipts establish
1,000 seeds across eleven operations in both canonical/raw representations,
plus all 1,000 original complete-source comparisons. Coverage includes mask
ordering, duplicate halves, transpose, bit reversal including fixed points,
Circle arithmetic and leaf/node hashing. Field canonicalization preserves
full-width keys and child digests. Production roots, every payload/path and the
payload-tampering rejection agree. Compression remains unchanged.

## Standards — lane B

`boundary_actual_standards_review`: PASS. Independently verified the source
archive, package/evidence hashes and two release test executables. Scheduler,
machine and CUDA-context identities agree; GNU timings, monotonic durations and
command deadlines agree, and commands fit the scheduler interval at its recorded
precision. No documented-standard violation or actionable heuristic smell remains.

Both reviewers reran the corrected auditor and all four synthetic controls with
Python 3.12. Current head `a29eda5f` preserves the qualified kernels, fixtures and
reference source; the deferred construction accessor is unused by these tests.
The collector and terminal readbacks remain in `stele-validation/`.

Both reviews accept this evidence for E16-40q submission. Mandatory native,
parity, ladder and current-main/intended-merge-tree gates still precede n merge.
This supplies scoped kernel/source qualification, with no integrated-proof,
performance, complete pipeline-memory or ADR-127 GO credit.

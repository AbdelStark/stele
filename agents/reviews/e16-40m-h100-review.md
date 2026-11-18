# E16-40m actual H100 qualification review

Development research, lane V. The single Lucid job **6733** completed `0:0`
on H100 NVL with zero requeues/restarts. Source
`86d503b3edbc3379a5887d656b858c1e334d09fd`; unchanged package pins
`7878bd1e3f338a751d4af8bb77f52d27c8182e17b568cae1347d6f9cb732da93`.
The [hardware receipt](e16-40m-h100.json) preserves all 38 payload hashes,
resource records, manifest/archive hashes and the source/binary identities.

## Spec — owning GPU lane

`gkr_actual_spec_review`: PASS. Independently matched all 2,381 source-archive
entries, modes and symlinks to Git, and checked package, evidence and current
binary readbacks. Every command falls within the successful scheduler interval;
selection, sequence, deadlines and GNU timing agree.

Independent fixture and source inspection confirms 1,000 genuine CPU proofs,
2,728 GKR steps, 5,456 canonical/raw states and 25,800 rounds. Ordinary CPU proofs
verify; initial tables, every polynomial/fold, compact slots before expansion,
expanded finals and routed claims are checked at actual transcript challenges.
The changed compact-slot control rejects. Independently recomputed input,
descriptor, round, raw-injection, table-transfer and retained-capacity counts match.

## Standards — lane B

`gkr_actual_standards_review`: PASS. Independently checked source and payload
identity, the single release CUDA binary, all four exact tests with zero skips,
complete ordered receipts, actual CUDA-context H100 identity, machine/scheduler
agreement, command chronology and timing bounds. No documented-standard breach
or actionable heuristic smell was found.

Both reviewers reran the corrected terminal auditor and all four synthetic
controls successfully. The terminal collection script and readbacks remain in
`stele-validation/e16-40m-qualification/` and the sibling
`e16-40m-terminal-6733.log`. The collector checked all remote package pins and
read the current executable digest after completion.

## Applicability and remaining gates

Current stack head `b003ea21` preserves the qualified research runtime and pins.
The intervening bench construction interface adds a deferred accessor that this
consumer never calls; the native inventory repair changes only gate/tests/docs.
Both reviewers found no qualification-relevant change requiring another campaign.

This accepts the actual qualification evidence and permits E16-40n submission.
Mandatory current-main/intended-merge-tree gates still precede E16-40m merge.
CPU construction/packing/expansion/routing, staging and excluded allocator/context
costs remain explicit. This grants no integrated GPU proof, actual stories42M
cost, complete pipeline-memory budget, performance result or ADR-127 GO credit.

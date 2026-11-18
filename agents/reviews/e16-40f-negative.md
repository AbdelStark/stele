# E16-40f negative experiment and rollback review

Independent Spec and Standards agents reviewed
`d54aeff848c8482088d58059915fa832635ced95...ffd06eef6dbefa1937d09eb758b5cdc30913284a`.
Both PASS with no actionable findings. This supersedes the candidate's pending
keep/revert decision; mandatory merge gates remain separate.

## Spec

The original predicate is unchanged: assembly must be at least twice as fast and
whole-command wall time lower in every pair. All three pairs fail the assembly
condition. Retaining the six negative ledgers and reverting follows Workflow 09.
The reviewer independently checked the pinned importer
`06bef87cbbeee3efb0d7753a54fb9a88791d8593f81a3512227f0a789b078262`, all 64
payload hashes, chronology, exact CUDA receipts, paired roots and provenance.
All six records match regenerated importer output and the native-validated copies.
The required 1,000-case device test and three full-shape comparisons preceded
measurement. Both runtime files exactly match `458186d9^`; stronger thread tests
and the one-word `RootMismatch` control remain. No integrated-proof, speed-gate,
complete-device-budget or security claim is introduced.

## Standards

The reviewer independently regenerated all six records, checked both archive
pins and the importer hash, and confirmed the exact rollback. No actionable
documented-standard breach or Fowler smell remains; generated ledgers preserve
independent evidence. The complete-source honest/tamper test passes. Importer
controls reject an omitted CUDA receipt, forged successful hypothesis and altered
parsed timing. Challenges, claim consumers, static bounds, padding, masks,
commitments, verifier independence, proof format and error handling are unchanged.
The failed source-assembly cost hypothesis is retained without an acceleration
claim. Schema `standard` does not grant inference admission.

Neither review ran repository-wide suites or hardware jobs. Current-main and
intended-merge-tree gates, including applicable parity, remain merge prerequisites.

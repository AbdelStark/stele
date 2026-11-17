# E16-40b specification review — owning lane E

Reviewed PR #396 at `59f9a18ba0db3dd096912bbe4fa130f25fddad16` against
`b8e89a376b5e10dbefa3848636f0ea9ff853102c` using the three-dot diff and commit log
(`526b3910`, `95ac6e4b`, `59f9a18b`). Independent specification review under
Workflow 03/12 and `cuda-kernel-author`; no implementation edits.

**Code approval; task acceptance remains incomplete.** No missing, incorrect,
or extra implementation scope found. Every encoded value and Merkle node is
retained; payload/path indexing and host salt regeneration agree with production.
Root-only GPU command/kernels remain scoped. Shape validation precedes allocation,
noncanonical downloaded words reject, and the explicit device test requires CUDA
and exactly 1,000 completed comparisons. Storage and transition accounting includes
live metadata and root download exactly once; labels correctly exclude runtime
allocations and make no complete-device-peak or GO claim.

Pending acceptance: “measure … on the same H100 allocation as the CPU reference;
preserve all samples and validate ledgers.” The actual 1,000-case H100 result,
paired measurements and fresh current-base/current-tree CI must pass before merge.
This review approves neither hardware results nor integrated backend parity.

I tried to break it by changing one encoded payload word, and the control in
`matches_reference_complete_source_material` rejected it with ordinary
`merkle::Error::RootMismatch`.

Independent checks passed: complete CPU material parity/tamper test;
`rejects_incomplete_or_noncanonical_material`; CPU-only `source_material 3 9 gpu 1`
exited unsuccessfully with `gpu/check requires --features cuda`.

Workflow 03 checklist:

1. Public items: material/response implement RFC-0010 A9/A15 and RFC-0012 A3;
   preparation/timing implements RFC-0014 §4/A1.
2. Challenges: none added; production transcript unchanged.
3. Claims/consumers: no protocol claim or certificate authority added.
4. Binding: per-case payload-word tamper rejects as above.
5. Accounting: no soundness ledger changes; mandatory gates remain merge conditions.
6. Bounds: no new integer relation; checked shapes/storage arithmetic.
7. Padding/masks: supported source leaves are all real; canonical production salts.
8. Determinism: fixed column/level order; no timing-dependent values.
9. Parity: CPU complete-source comparison passed; H100/full-proof gates unclaimed.
10. Cost: measures source `c_c`/transfer/assembly `T_misc`; no measured gain asserted.
11. Verifier: unchanged, including independence and `no_std`.
12. Glossary: no conflict found.
13. Tier: research only; no security/profile promotion.
14. Commit rule: no new committed/virtual column.
15. Plain checker: unchanged; not rerun in this isolated review.
16. Segments: no segment access changes.
17. Proof bytes: core/reference untouched; digest gate remains required.
18. Ladder: pending current-tree mandatory gates and validated paired evidence.

Skipped duplicate workspace/native gates and hardware execution. Merge risk remains
unresolved until the pending evidence covers the intended merge tree.

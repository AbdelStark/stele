# E16-40k: reject the inline-suppression candidate

Qualification job 6730 is terminal `FAILED`, scheduler exit `1:0`, on immutable
source `0dd0818f562fc667f851f43b1e8d58ceab9e63bd`. The CPU completed all 1,000
original inventory cases. The case-9 preparation regression and representative
masked relation/GKR comparisons passed. The complete GPU inventory passed only
cases 0–10, then exceeded its case deadline after starting case 11. No build/
prepare completion was emitted for case 11; no arithmetic mismatch was reported.

The outcome fails the original complete-inventory acceptance. All 42 payload
hashes, completed test receipts, CPU case sequence, completed GPU case digests,
exact last receipt and timeout classification were verified. The root agent
separately retained the terminal scheduler state and rehashed the remote inventory
binary and manifest. Pins are in
[e16-40k-qualification-failure.json](e16-40k-qualification-failure.json). Raw files
remain under `stele-validation/e16-40k-qualification/run-6730` and the same named
remote staging directory. No success or performance ledger is imported.

The failure was reported before further work. Under Workflow 09's keep-or-revert
rule, the experimental `round_mul` generator change is reverted exactly to
`cb46de3c`. The diagnostic, immutable candidate archive, regression fixture and
ignored actual-path test remain as evidence. This preserves the original known
preparation limitation; the ignored regression is not claimed to pass after the
revert. No new optimization or hardware retry is authorized by this exhausted
candidate budget.

The failed public geometry has 1,851 factors and 3,454 terms, degree 4 and mask
coordinates 0 and 1, reduced from five variables to three. These are inventory
counts, not performance measurements. The case receipt does not localize its
stall between construction and preparation. The evidence establishes that keeping
QM31 products out of line is insufficient for the required inventory; it does
not establish a complete cause for case 11.

E16-40d and E16-40k's complete qualification remains unmet. Any successor must
retain all original shapes, seeds, masks, terms, outputs and fail-closed checks,
and must be separately scoped and reviewed. No core GPU backend, full-proof
parity, complete memory-budget or ADR-127 GO credit follows.

## Independent negative-result review

`/root/prepare_fix_spec_review` and `/root/prepare_fix_standards_review` both
**PASS the failure classification and rollback**, with no actionable finding.
Each independently checked all 42 payload hashes, input/evidence/terminal pins,
completed CPU/GPU case sequences and matching digests, passing intermediate test
receipts, exact case-11 timeout and geometry, and absence of campaign success.
The Standards reviewer passed the actual incomplete output to the validator;
it rejected it. Both verified that restored `gpu.rs` equals `cb46de3c` exactly.
Neither grants complete qualification. Post-rollback CUDA all-target Clippy,
research formatting and docs links pass; mandatory full merge gates remain open.

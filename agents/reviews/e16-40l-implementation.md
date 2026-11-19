# E16-40l implementation review before hardware

Base `ba0c3024ce689ced68247e2fabe27e7a3bd70061`; implementation
`700be72c2c0671ce180a10738cdb78c6c8391c09`. Fresh independent reviewers applied
the two-axis code-review skill. This is permission to qualify the research
candidate, not merge or device-parity credit.

## Spec — owning GPU

`descriptor_spec_review`: PASS before hardware. No incorrect implementation or
scope addition found. Checked descriptor bounds (including zero coefficients),
empty/repeated products, mask coordinates, mixed coefficients, interpolation,
canonical readback, fixed reduction, unchanged folds and the resident batch
caller. Verified both failing-shape fixtures against the original inventory.
Independently ran six focused host tests and inspected red/green evidence.

The original complete inventory, both regressions, representative larger rounds,
canonical/lazy descriptor cases, resident batch path and mandatory merge gates
remain required. Retained buffers are not a complete device budget.

## Standards — another lane

`descriptor_standards_review` (lane B): PASS before hardware. No blocking
documented-standard violations or warranted smell refactors. Independently ran
four descriptor/expression/near-miss tests. Research scope, determinism, unsafe
contracts, cost reporting and absence of protocol/interface changes were checked.
One nonblocking stale `kernels.cu` prologue was corrected to name the fixed code.

Both reviews exclude H100 execution, capture implementation and full mandatory
current-main/intended-tree gates. CPU-only all-target tests and CUDA all-target
Clippy passed locally; these do not establish CUDA launch correctness.

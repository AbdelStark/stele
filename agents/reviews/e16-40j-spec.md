# E16-40j independent Spec review

Reviewer: `batch_device_spec_review`, owning GPU/spec perspective, fresh context.
Final reviewed SHA `ffdf611cb3a38dfcc5a1bdae478d708ad5e5be94`, against base
`aa4d518a0d4da32f2e4e9996dcae0b6ce3ea3d6c`. Implementation approved; merge pending.

Initial P2 at 726ab66b: only claims/coefficients varied across the thousand cases;
the face kernel repeatedly received one source. This did not meet RFC-0014 §5's
per-kernel seeded coverage. Fixed in ffdf611c: every case creates a newly seeded
message and prepared hiding source, and an actual data-face input distinctness
check requires all cases to differ. The H100 receipt includes source_cases=1000.

No other implementation or scope finding. Stable CSR preserves claim order and
rejects invalid positions even with zero weight. Weight/face kernels preserve
extension coefficients, the zero w=1 half, row/column/mask layout and canonical
output. The buffers become the real DeviceMasked state; the face stays M31 until
its first fold. Construction overlap, first-fold peak and retained capacities
match allocation lifetimes. Real BatchInputs, Dense and RoundSumMismatch are the
oracles; the existing internal dev-dependency is appropriate.

The reviewer independently reran all three focused batch tests and CUDA-feature
test compilation at the fixed revision, using Rust 1.90.0. Tests-first failure
log was inspected. No remaining finding. H100 receipts, full mandatory gates,
current-main and merge-tree validation remain prerequisites; host/compile success
establishes neither device parity nor complete masked-batch/proof performance.

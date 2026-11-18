# E16-40i independent Spec review

Reviewer: `lookup_device_spec_review`, owning GPU/spec perspective, fresh context.
Reviewed `b6f094b297e687cd7901fcb693437e9ef663bbd9` against
`a08512dcb23db091ef0ecb0bc45724887d376b19`. Implementation approved; merge pending.

No blocking implementation finding or scope creep. Kernels preserve production
leaf order, selectors, shifts, padding, compression, parent recurrence and h=p/q
(RFC-0008 A7 items 2/3 and implementation notes). Checked geometry bounds allocations
and indexing. The quadratic-norm inverse follows RFC-0003's tower. Stored limbs are
canonical and zero flags propagate DenominatorZero. Explicit buffer accounting
correctly excludes infrastructure and the complete pipeline (RFC-0014 A1).

The reviewer independently passed four focused CPU lookup tests on Rust 1.90.0,
including actual CUDA expressions executed as C++, raw lazy kernel inputs,
production fixtures, malformed shapes, near misses and the million-case inverse.
CUDA-feature lookup tests compile. Tests ran against 0cb94dfd; b6f094b2 only adds
the governing RFC citation to host_probe.rs.

H100 receipts and mandatory stack-order gates remain outstanding. Host execution
and compilation are not device parity. No full-proof GPU, performance,
complete-device-budget or ADR-127 GO credit follows.

# Fixed-code masked rounds (E16-40l)

Research only under ADR-123 and proposed ADR-137. The question is whether one
fixed CUDA program can finish the original E16-40d production inventory after
the shape-generated programs failed preparation at shapes 9 and 11. The
unchanged inventory, seeds, coefficients and reference checks are required.
This candidate has one reviewed implementation and one bounded H100 campaign;
failure must be reported before another optimization. The one H100 qualification
passed at source `75302055`; its [receipt and scope](../../agents/reviews/e16-40l-qualification.md)
retain the exact original inventory and affected-path checks. Mandatory merge
gates remain pending. No performance result or complete-proof parity is claimed.

`round.rs` checks node/count/index bounds before device allocation, including
indices in zero-coefficient terms. Offsets preserve empty and repeated products.
`round.cuh` evaluates those descriptors with the existing field helpers, and
`round.cu` retains the existing per-node entry order, block tree and final
reduction. Interpolation at node `t` uses `a + t*(b-a)`; the mask contributes
`t*(1-t)*r(t)` only at its original coordinate. Folding and canonical readback
are unchanged. Resident claim-batch rounds use the same code and must be
requalified. No production crate imports this prototype.

The cost tradeoff concerns `c_sc` and `T_misc`. Code size is independent of the
number of terms and factors. Each term occurrence now reads its factor's two
table entries at each node, including repeated factors and zero coefficients.
Active masks add two reads per occurrence at nodes above one. These are logical
reads, not measured HBM traffic; caching does not justify counting fewer reads.
Offsets, indices, pointer/type descriptors and coefficients add traffic. The
candidate makes no speedup hypothesis.

The inventory records one-time offset/index/coefficient upload bytes and
per-round pointer/type upload bytes. Its initial and post-fold buffer counts
include retained table capacities, descriptors, coefficients and reduction
scratch; empty descriptors use explicitly counted dummy allocations. These are
retained capacities, not a complete peak: staging overlap, first-fold allocation
overlap, context, module, driver and allocator overhead remain separate. Batch
construction's existing first-fold/retained accounting includes the new buffers.

`gpu_setup_ns` includes cold context creation and fixed-module compilation/loading;
`gpu_prepare_ns` now covers only function resolution. Table staging/upload is in
`gpu_upload_ns`; construction and descriptor upload are in `gpu_build_ns`.
Descriptor validation and host vectors precede those phases. Whole-command time
also includes reference construction, checks, transfers and readback, so phase
timers cannot be substituted for it. Performance publication still requires a
validated ledger; reduced inventory parity supplies no compact-final, actual-size,
complete-memory-budget, integrated-proof or ADR-127 GO credit.

Tests first: the descriptor stub failed its honest cases; the actual CUDA
expression stub failed the CPU differential and changed-constant control.
Host tests execute the actual expression as C++, using seeded storage/mask
combinations, canonical/lazy limbs and both failing production shapes. Required
H100 tests execute the actual round/fold launches on canonical and lazy tables
and coefficients, the original complete inventory, both preparation regressions,
larger masked rounds and the affected resident batch path. Capture rejects
missing/skipped cases and kills process groups on deadlines.

# Lookup tree/top qualification (E16-40i)

Question: do the production-normalized inputs of `LookupCase` suffice for exact
CUDA leaf construction, every retained tree layer, and committed-top division?
The risk is untested GPU behavior (`docs/plan.md` §9), concerning `c_lu` and
`T_misc`. This is an ADR-123 research experiment; ADR-127 remains NO-GO.

The work budget is one bounded implementation and one H100 qualification
campaign. A device divergence, compile failure or allocation failure stops the
campaign for a report before another optimization. No speed hypothesis is tested
here. Recommendation: continue with exact H100 qualification, then paired
whole-operation cost measurements; do not graduate a core backend from this note.

`masked::gpu_lookup::prepare` accepts the merged production `LookupInputs<QM31>`.
It stages shifted tuples, table denominators, original multiplicities, compression
powers and alpha in that order. Selectors have their own buffer. A single retained
tree holds root-first numerator/denominator pairs. Each parent combines adjacent
children in the production order; the top kernel computes `h=p/q` using quadratic
norms in the RFC-0003 tower. Each top entry writes its own zero flag. There are no
atomics, floating-point operations, transcript calls or protocol changes.

The result contains every layer plus all three top columns. Downloaded limbs must
be canonical. Malformed geometry rejects before allocation; any zero top
denominator returns `gpu::Error::Lookup(lookup::Error::DenominatorZero)`. The
research caller must propagate this abort. This is not a verifier or proof API.

The host tests compile the actual CUDA expressions as C++ and compare all layers
and top values with the unchanged production `LookupCase::reference`. Fixtures
cover heterogeneous members, selectors, shifts, extension compression, padding,
a single changed multiplicity, malformed geometry and the zero-denominator abort.
Raw lazy inputs are injected at the leaf, each level and the top, checking the
canonical output before the next injection. A separate million-case inverse
comparison uses `stele-field`, including zero and every lazy-range boundary.
These host executions establish no CUDA or H100 parity.

The two explicit H100 tests require CUDA/NVRTC and an H100 by name. One compares
1,000 seeded complete results and near misses, then separately uploads raw lazy
inputs to every leaf/level/top kernel. The other exercises the actual top kernel
on one million denominators and checks its inverse and zero flags. Run exactly:

```sh
cargo test --manifest-path research/gpu-gating/masked/Cargo.toml --features cuda --release --lib gpu_lookup::tests::matches_reference_lookup_trees_on_h100 -- --ignored --exact --nocapture
cargo test --manifest-path research/gpu-gating/masked/Cargo.toml --features cuda --release --lib gpu_lookup::tests::matches_reference_lookup_inverse_on_h100 -- --ignored --exact --nocapture
```

H100 execution and mandatory stack-order gates are pending. No ledger, timing,
speedup, full-proof GPU parity or completed task is claimed by this implementation.

Future timing must charge `LookupCase` construction separately and `inputs()` to
the GPU path. The CPU reference already includes normalization. The returned phase
timers cover staging, upload/output allocation, all tree kernels, top division,
download, and canonical host assembly. Account separately for cold context/module
setup, whole-process wall time, host RSS and actual device peak. Adding these
kernels to the shared NVRTC module also changes cold compilation work.

`upload_bytes` counts staged values and selectors; `download_bytes` counts every
tree pair, h entry and flag. All these device buffers coexist, so their sum is the
complete explicit buffer peak for this operation. Retained field material is the
tree plus h (p/q already appear in the tree). CUDA context, module, allocator
retention and other pipeline allocations are excluded. This count is not the
RFC-0014 A1 complete device budget and cannot establish its 40% limit.

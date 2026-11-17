# Claim-batch CUDA qualification (E16-40j)

Question: can device weight and Y=0 face construction match the merged production
BatchInputs reference and feed the existing GPU dense rounds without reuploading
the generated tables? This addresses the untested-GPU risk in docs/plan.md §9,
concerning c_sc and T_misc. ADR-123 research scope applies; ADR-127 remains NO-GO.

The work budget is one bounded implementation and one H100 qualification campaign.
A compile, allocation or device comparison failure stops for a report before any
further optimization. Recommendation: continue with H100 qualification, followed
by paired whole-operation measurements. This note tests no speed hypothesis and
does not authorize a core backend.

`gpu::batch::prepare` consumes an actual prepared hiding source, claims and
supplied benchmark coefficients. It validates the source, message dimensions,
coefficient count and every position before staging. Off-data-face positions
reject even if their weight is zero. A counted prefix table groups occurrences
by position while preserving claim order. Each device thread accumulates one
weight entry; no atomics or host multiplication of those contributions is used.
The full w=1 half is explicitly zero. A second kernel gathers the Y=0 columns of
every row, including mask rows, at M31 width. The cheap claimed sum remains on the
host, in the unchanged production order.

The resulting buffers become the existing DeviceMasked state with two unmasked
factors and degree two. They feed actual GPU rounds and folds directly. This is
the underlying Dense summand of RFC-0013 A5 item 5; the A4 bound mask and source
opening are not supplied by this experiment. Table or dense parity cannot prove
a complete masked batch or inference. No transcript challenge is generated here.
No production crate, production dependency graph, binding or proof format changes.
The existing stele-sumcheck crate is a research dev-dependency solely to use the
production Dense reference; no external package is added.

Host tests compile the actual CUDA construction expressions as C++ and compare
all outputs with BatchInputs on 1,000 deterministic cases, each canonical and raw
lazy. They cover repeated/cancelling positions, extension coefficients, empty
claims, zero coefficients, field boundaries and row/data-face boundaries.
Malformed source/shape/count/position controls reject. A changed claimed value
fails ordinary stele_sumcheck::prove with RoundSumMismatch.

The explicit H100 test additionally compares every round, every folded table and
final values with production Dense and the reference fold. Raw words are injected
into each construction kernel and before each resident round/fold; every returned
live limb must be canonical. Absence of CUDA or a non-H100 device fails the test:

```sh
cargo test --manifest-path research/gpu-gating/masked/Cargo.toml --features cuda --release --lib gpu::batch::tests::matches_reference_batch_on_h100 -- --ignored --exact --nocapture
```

H100 execution and mandatory stack-order gates are pending. Host execution and
Rust compilation establish no device parity, performance or full-proof result.

Staging time includes ordered grouping and packing. Upload time includes explicit
output allocation; build time covers both kernels, and round setup covers the
existing descriptors, coefficient and scratch buffers. Uploaded source, pairs and
offsets coexist with the two output tables, then are dropped before round setup.
Initial round buffers include all retained table and scratch capacities. The
first M31 face fold temporarily retains its old buffer and its new QM31 buffer;
subsequent folds retain those allocated capacities. Reported byte counts describe
these explicit lifetimes; CUDA context, module and allocator retention are separate.

Later measurements must charge source preparation, cold shared-module compilation,
host scratch/CSR construction, round compilation, every download, whole-process
wall/RSS, observed device peak, bound masks and authenticated openings. Host tests
reuse one prepared source across coefficient cases solely to qualify kernels;
that reuse supplies no source-preparation or lifetime-policy performance credit.
No complete pipeline memory budget or RFC-0014 A1 40% claim follows from these
operation buffer counts.

# Masked-round shape qualification (E16-40d)

The existing CUDA benchmark constructs two synthetic shapes. The merged
[E16-40a inventory](../../bench/ledger/e16-40a-dev-zk-stories42m-t32-h100-0.json)
contains additional first, interior and compact-leaf terms, degrees and mask
coordinates. This experiment checks those recorded structural cases against the
unchanged production `Masked` round/fold implementation. It uses no proof,
witness value, mask seed or transcript challenge from the measured inference.

```sh
python3 research/gpu-gating/masked_inventory.py bench/ledger/e16-40a-dev-zk-stories42m-t32-h100-0.json > /tmp/stele-masked-shapes.txt
cargo test --manifest-path research/gpu-gating/masked/Cargo.toml --locked
cargo build --manifest-path research/gpu-gating/masked/Cargo.toml --example inventory --release --features cuda --locked
research/gpu-gating/masked/target/release/examples/inventory /tmp/stele-masked-shapes.txt cpu
research/gpu-gating/masked/target/release/examples/inventory /tmp/stele-masked-shapes.txt check
```

The exporter checks weighted shape counts against the declared plan and rejects
duplicates, disabled bindings, unknown fields and unsupported challenge fields.
The Rust harness independently checks the declared nonempty record count and
every term/mask index. Its bounded input contract supports at most 256 shapes,
4096 factors and 8192 terms per shape, original exponents through 32, degrees
through 31 and reduced exponents through 8. Unsupported input fails explicitly.
These limits apply only to this experiment.

Each reduced domain retains original coordinate zero, every mask coordinate,
each mask's immediate predecessor, and the last original coordinate. Sorting and
deduplicating this list preserves mask order, simultaneous mask events, whether
the first round is masked, and an unmasked round before a later mask when one
exists. All other coordinates are omitted. Every case logs both exponents.
This is structural code-generation coverage, not a run at the original size.

Exactly 1,000 cases cycle through every shape and base, extension and mixed
factor storage. Distinct odd seeds avoid `Rng::new`'s low-bit aliasing. Inputs
include canonical zero, one and `p-1`, plus synthetic random values; raw lazy
limbs are not exercised. Coefficients cover one, minus one and general extension
values. Mask tables exclude their vanishing coordinate. These synthetic tables
need not form an honest inference or satisfy the original degree bound as a
formal polynomial: the test compares the requested node evaluations and folds.
Compact flags are retained as metadata; compact-final expansion is not called.

The device campaign uses one fresh CUDA context. Every case compares all built
factor/mask entries, each round polynomial, and all entries after every fold.
Missing CUDA, an unequal value, compilation or allocation failure fails the
command. The final success marker requires all cases. CPU-only and device-check
campaign digests must agree, but the direct field-element comparisons establish
parity; the FNV receipt is not an authentication mechanism.

The campaign parent includes cold context/module setup, all kernel preparation
and cache misses, synthetic host preparation, CPU reference work, transfers and
comparisons. Per-case preparation/upload/build fields are nested within it.
Consequently its wall time is qualification cost, not GPU speedup. Retain full
process time/RSS and raw case receipts with source, inventory and host hashes.
No device-memory budget is inferred from those observations.

Work budget: one CPU campaign and one H100 campaign before reporting. Any
divergence, unsupported generated kernel or allocation failure ends this
candidate campaign with a recorded failure. Production kernels and interfaces
remain unchanged; a fix, alternative generator or selective dispatch requires
a subsequent scoped task. Hardware execution and a validated evidence ledger
are pending. ADR-127 remains NO-GO; full-size factors, tree/top, claim routing,
source policy, accepted backend design and full-proof parity remain required.

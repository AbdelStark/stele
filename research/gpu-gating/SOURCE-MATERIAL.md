# Complete source-material measurement (E16-40b)

The existing `source` command measures a root-only device preparation. It drops
encoded symbols and intermediate Merkle levels; that output cannot supply later
certificates or openings. Its command, kernels and root-only retention schedule
remain unchanged.

The `source_material` example retains every encoded symbol and every Merkle
level, downloads them, then assembles canonical salted column payloads on the
CPU. Salt regeneration is deliberately charged to `host_assemble_ns`. A real
backend may choose another storage policy after this cost is measured; this
research path makes no core API or protocol change.

```sh
cargo test --manifest-path research/gpu-gating/masked/Cargo.toml --locked
cargo check --manifest-path research/gpu-gating/masked/Cargo.toml --features cuda --all-targets --locked
cargo test --manifest-path research/gpu-gating/masked/Cargo.toml --features cuda --test source_material --release --locked -- --ignored --nocapture
cargo run --manifest-path research/gpu-gating/masked/Cargo.toml --example source_material --release --features cuda --locked -- 3 9 check 1
```

The explicit device test requires CUDA/NVRTC and executes exactly 1,000 seeded
source preparations in one context. It compares every salted payload and every
authentication path with ordinary `PreparedSource`, includes canonical field
edges and multi-chunk leaves, and changes one payload word to require the ordinary
Merkle verifier's `RootMismatch`. It cannot succeed by skipping absent CUDA or
by running an empty case list. This checks the complete source operation; it is
not the integrated backend's per-kernel or full-proof parity gate. The standard
CPU test runs separately; the device test is ignored unless explicitly selected.

For paired measurements use the example with identical `ell`, `m` and seed and
mode `cpu` or `gpu`, on one allocation with recorded affinity and thread count.
Only synthetic benchmark data is used. Allowed benchmark dimensions are
`3 <= ell <= 11`, `9 <= m <= 17`; unsupported modes, malformed arguments and absent
CUDA fail. `check` retains both results and compares every column/path, so its
memory footprint and wall time are not a performance sample.

`gpu_setup_ns` includes context creation and cold NVRTC/module setup. There is
no warm-up preparation. `gpu_material_ns` surrounds the full operation, including
host preparation, device allocation and destruction, downloads and host assembly.
Its inner upload/encode/Merkle/download/assembly laps are disjoint children;
unattributed work remains in the parent. Merkle time includes the root's initial
32-byte download; the remaining complete material download is separate. Total
download bytes count that root once. CPU preparation and certificate production
plus verification are separate fields. The GPU command produces no certificate;
future models must keep certification, openings and self-verification costs.

`device_retained_bytes` counts encoded symbols and all nodes before download.
`device_buffer_peak_bytes` additionally includes live input buffers, twiddles,
keys and descriptor prefixes, and the maximum transition overlap. These are
explicit allocation sizes, not the complete RFC-0014 A1 device peak: driver,
module, allocator and runtime allocations are excluded. Host vector capacities
and process RSS are also not device memory. The host input, conversion buffers,
downloaded words and assembled material overlap; retain whole-process RSS and
wall time in the hardware evidence. No 40% budget or integrated backend approval
follows from these counters.

Hardware measurements, validated ledgers and review remain pending. No source
preparation speedup, GO decision or integrated GPU proof is claimed.

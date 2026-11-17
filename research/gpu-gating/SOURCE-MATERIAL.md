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

## H100 measurements

Lucid job 6607 passed the explicit 1,000-case complete-source device test and
the small full-material example on `h100-nvl-1-1-cc` (H100 NVL). Job 6609 then
ran three large full-material checks and three paired CPU/GPU repetitions per
shape on the same host, with 16 pinned CPU threads and Rayon threads. All nine
paired roots matched. The source was `59f9a18b`; each timed command used a new
process, including cold CUDA/NVRTC setup. CPU/GPU order alternated by repetition.

Every sample and the separate checks are retained in the validated
[first](../../bench/ledger/e16-40b-source-material-h100-1.json),
[second](../../bench/ledger/e16-40b-source-material-h100-2.json) and
[third](../../bench/ledger/e16-40b-source-material-h100-3.json) records.
These are microbenchmarks, outside the inference ladder; the scoreboard contains
inference records only. Ranges below span all three repetitions, in seconds;
`ell = 11` throughout.

| m | CPU preparation | GPU material | Cold GPU setup | CPU process | GPU process |
|---|---:|---:|---:|---:|---:|
| 15 | 9.101–9.585 | 8.127–8.164 | 4.822–5.149 | 10.89–11.66 | 18.33–19.12 |
| 16 | 18.773–19.702 | 15.898–15.983 | 5.094–5.132 | 22.20–23.32 | 27.84–28.03 |
| 17 | 38.762–38.887 | 31.667–31.768 | 5.076–5.128 | 45.47–45.56 | 46.84–47.10 |

The standalone GPU commands are slower in every pair despite short device
encoding and Merkle times. Complete download and CPU assembly matter: at
`m = 17` they take 6.980–7.052 s and 20.497–20.640 s respectively, both already
inside GPU material time. That parent excludes cold setup; whole-process time
also includes input generation, allocation and cleanup. CPU process time includes
certificate production and verification, which the GPU command does not perform;
this difference favors the GPU in the displayed process comparison. No omitted
certificate/opening cost is treated as accelerated.

This candidate's full download/assembly policy does not establish an integrated
source-stage speedup. Retained or selectively gathered device responses remain
an unmeasured alternative requiring a reviewed storage interface and complete
allocation-lifetime accounting. In particular, the buffer counters above do not
establish the RFC-0014 A1 budget. ADR-127 remains NO-GO.

The raw measurement archive has SHA-256
`4501130f791bdb5f4f3436c4508dc8a866d32bd61fd8530c6f9b8da597dbbbc8`.
All 85 payload hashes were verified after download; the ledgers also identify
the source, binary, capture script, host, load observations and parity manifest.
No integrated certificate path or full CPU/GPU proof parity is claimed.

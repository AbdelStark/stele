# dev-zk GPU decision: re-profile and device source preparation (task E16-36)

Status: measurement report for ADR-127, the final dev-zk GPU decision that ADR-123
deferred.

Ledgers:
- `bench/ledger/e16-36-dev-zk-stories42m-t32-mac.json` (the profile);
- `bench/ledger/e16-36-dev-zk-gpu-sources.json` (the device runs).

Raw outputs: `masked/results36.txt`. Sources: `masked/src/source.rs`, `masked/src/source.cu`,
`masked/src/gpu_source.rs`.

## 1. Profile on current main

One dev-zk byte-4 prove of stories42M at `T = 32` (checked `23..32`) on `8aa97af` (after
E16-34), with `STELE_STAGE_TIMES=1`, on the M4 Max:
- one run, started at 1-minute load 2.77; other agents' sessions raised the load during
  the prove;
- the proof verifies, and a pin to another model digest is refused.

| Stage | E16-22 (before E16-34) | E16-36 |
|---|---:|---:|
| witness, plain checks, capture | 47.1 s | 30.9 s |
| source messages (mask streams) | 21.6 s | 20.7 s |
| **source preparation and certification** | **103.5 s** | **28.3 s** |
| LogUp trees and tops | 25.0 s | 7.4 s |
| relations (masked sumchecks) | 35.2 s | 22.5 s |
| **ZK-GKR** | **173.2 s** | **153.2 s** |
| claim batches and openings | 21.4 s | 9.3 s |
| self-verify | 30.6 s | 20.1 s |
| **prove wall** | **465.7 s** | **306.2 s** |

In ADR-120's split:
- the offloadable work is 220.7 s: `M` = relations + ZK-GKR, 175.6 s; source
  preparation, 28.3 s; LogUp trees and claim batches, 16.7 s;
- the residual `r` is 85.4 s, which includes source messages (20.7 s), self-verify
  (20.1 s) and the witness.

Source preparation fell from 103.5 to 28.3 s between the two profiles. Both are single
runs on a shared host, and this task did not attribute the change. Most of the remaining
offloadable time is in the masked rounds, which ADR-123 showed the device handles.

## 2. Source preparation on the device

- **What runs on the device.** `M'` (`2R × 2C`) is uploaded and transposed to
  symbol-major order. Each row is Circle-encoded (RFC-0010 A2): inverse levels on the
  first `2C` symbols, bit reversal and the `1/n` scale, then forward levels over `8C`
  symbols. Twiddles come from the host, computed as `stele-code` computes them.
- **Leaves and tree.** One thread hashes each leaf `salt || column` with BLAKE3 under the
  RFC-0012 A3 domain. The salts are the keyed-XOF bytes, computed on the device. The
  tree is built one launch per level, and only the 32-byte root comes back.
- **Certificate.** It stays on the CPU; it takes 1–2% of the stage.
- **Bit equality.** The device root equals the production `PreparedSource` root, so
  every encoded symbol, salt and digest is the same:
  - `tests/source_parity.rs` at `(ell, m)` = (4, 10), (6, 12), (11, 16);
  - the check mode at (11, 15), (11, 16), (11, 17);
  - on the Mac, `source.rs` runs the same algorithm in plain Rust. Its test
    (`matches_reference_prepared_source_root`) matches the production root before any
    GPU runs.
- **Shapes.** stories42M has two large hiding sources with row exponent 12 (`ell = 11`)
  and three small ones (row exponents 4, 7 and 4). The witness is `C = 2^16`.

Box: RTX 4090 (PCIe 4.0 x16) with an AMD EPYC 7C13 (61 threads). Medians of three.

| `ell = 11`, `m` | CPU prepare + certificate | GPU encode + Merkle | upload phase | prepare only | stage (certificate on CPU) | stage with upload |
|---|---:|---:|---:|---:|---:|---:|
| 15 | 8.33 + 0.08 s | 0.28 + 0.02 s | 0.76 s | 28.4× | 22.2× | 7.4× |
| **16 (witness)** | 16.32 + 0.15 s | 0.58 + 0.04 s | 1.53 s | 26.4× | **21.5×** | 7.2× |
| 17 | 33.20 + 0.31 s | 1.24 + 0.07 s | 2.99 s | 25.4× | 20.7× | 7.3× |

- On the Mac (the laps host), the witness source prepares in 11.53 + 0.27 s, which is
  **13.3×** the device time.
- The upload phase moves `M'` (2 GiB at `m = 16`) through the bench's host staging. The
  bus moves 1 GiB in 60.9 ms from pageable memory and 40.3 ms from pinned memory.

## 3. Masked rounds on current main (box CPU)

The E16-35 kernels, re-timed against E16-34's CPU on this box (rounds only, production
code on both sides):
- relation: 57.7×, 34.6× and 31.7× at `2^24`, `2^26` and `2^27`;
- GKR layer: 18.4×, 17.0× and 15.9×.

The Mac calibration of these rounds did not run: the host's load stayed at 8–11 for more
than 30 minutes. The ceiling below takes `s_M` against the box CPU. In E16-35 the Mac ran
these rounds slower than such a box, so this understates the device's gain. The cap in §4
does not depend on it.

## 4. Ceiling

`T' = r + M/s_M + S/s_src + L/s_L` over the laps of §1 (306.16 s), where `r` = 85.44 s,
`M` = 175.64 s, `S` (source preparation) = 28.34 s and `L` (LogUp trees and claim
batches) = 16.74 s.

| Assumption | Ceiling |
|---|---:|
| every offloadable stage free | 3.58× |
| `M` and `S` free, `L` on the CPU | **2.996×** |
| **measured:** `M` at 15.9–57.7×, `S` at 13.3×, `L` on the CPU | **2.65×–2.85×** |
| `L` at E16-21's rounds-only ratios (25.4–76.1×; not measured for `L`) | 3.08×–3.37× |
| `L` at E16-21's upload-inclusive ratios (2.9–15.9×; not measured for `L`) | 2.93×–3.34× |

- **The measured resident ceiling is 2.65×–2.85×, below 3×.** Even with an infinitely
  fast device for everything this task measured, the ceiling is capped at 2.996×.
- Reaching 3× would need LogUp trees and claim batches on the device at **≥ 4.9×**, a
  stage no task has measured.
- Outside ADR-120's offloadable set, the largest CPU stages are source messages (20.7 s
  of keyed-XOF mask draws) and self-verify (20.1 s). These, not the GPU-shaped work, now
  set the ceiling.

## 5. Reproduce

```sh
cd research/gpu-gating/masked
cargo test                                        # CPU: the source reference root test
STELE_E16_36_SOURCES=4:10,6:12,11:16 cargo test --release --features cuda -- --nocapture
cargo run --release --features cuda -- source 11 16 check    # or cpu, gpu
bash run36.sh; python3 summarize36.py out macout   # the box run (expects ~/tree)
STELE_STAGE_TIMES=1 target/release/stele prove-dev --zk ...   # the §1 laps (docs/development-e2e.md)
```

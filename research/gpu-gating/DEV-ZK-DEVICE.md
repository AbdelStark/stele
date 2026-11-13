# dev-zk masked and ZK-GKR rounds on a device (task E16-35)

Status: measurement report for ADR-123. It answers ADR-120's open question: with
resident, device-built tables, do the dev-zk masked and ZK-GKR rounds move the
stories42M ceiling past ADR-103's 3× gate?

Ledger: `bench/ledger/e16-35-dev-zk-gpu-masked.json`. Raw outputs:
`masked/results.txt`. Sources: `masked/` (a research crate outside the workspace).

## 1. What was built

- **Kernels** (`masked/src/kernels.cu`, `masked/src/gpu.rs`): one `Occurrences` round
  (RFC-0013 A5 item 2) for any term list, generated per round shape and compiled by
  NVRTC at run time. M31 factors are stepped and multiplied in M31 and applied once
  to the QM31 product, as the CPU does since E16-34. Folds run in place; an M31 table
  becomes QM31 at its first fold. Each round copies back only the round polynomial.
  Reductions are a fixed-order block tree and a block-order sum, no atomics.
- **Device-built tables:** `eq` (head, selected claims, relation `τ`), tiled blocks,
  the duplicated layer halves and every mask table `r̃(X_u)` are built on the device.
  Only the committed columns, the layer halves, points, periods and blocks are
  uploaded.
- **Shapes** (`masked/src/lib.rs`):
  - `relation`: an identity step `Σ eq(τ, x)·(V̇_a·V̇_b − V̇_c)`, degree 4;
  - `gkr`: a ZK-GKR layer step (RFC-0008 A7 item 4; `zk_lookup` `factors` and
    `terms`), nine inputs, five terms, degree 5.
- **CPU reference:** the production summand, through a new off-by-default
  `stele-reductions` feature `bench` (`zk::claims::bench::Masked`, `mask_table`).
  Nothing in `crates/` changes behaviour.
- **Opt-in:** CPU only by default; `--features cuda` adds the device path. cudarc
  0.19.10 with `dynamic-loading` opens the driver and NVRTC at run time, so the crate
  builds without CUDA and the device test skips without a driver.
- **Why not `crates/stele-gpu`:** that crate is the empty scaffold under the parity
  gate's guard (`scripts/gates/check.py`, task E10-01), and touching it schedules the
  self-hosted `gpu-parity` CI job. A GPU binding belongs there after a GO and E16-21a's
  harness; the benchmark follows E16-21's precedent in `research/gpu-gating/`.

## 2. Bit equality

Every round polynomial and every folded table (after every round) equals the CPU
summand's, element for element:
- `tests/parity.rs` (`matches_reference_masked_rounds_on_device`) at `2^20`, `2^22`,
  `2^24`, `2^26` and `2^27` entries, both shapes: 10 of 10 pass;
- the bench's `check` mode, same sizes and shapes: 10 of 10 `bit_equal=true`;
- the FNV of the round polynomials and finals agrees between the GPU, main's CPU and
  PR #364's CPU in every timed run.

## 3. Measurements

Host: Vast.ai RTX 4090 (24 GB, PCIe 4.0 x16) with an AMD EPYC 7B13; the process sees
61 threads. Medians of three runs. A full sumcheck is every round and fold
(`n` rounds). "Build" is table construction from the inputs; on the CPU it is the
production `eq_table` and `block_table`.

CPU is PR #364's tree (base-field rounds, lazy QM31 product), faster than main's in
every cell; ratios use the faster of the two.

| Shape, entries | CPU build + rounds | GPU rounds | GPU build | GPU upload (measured / bus-bound) | rounds-only | build + rounds, bus-bound upload |
|---|---:|---:|---:|---:|---:|---:|
| relation `2^24` | 1.353 + 0.457 s | 11.9 ms | 6.2 ms | 153 / 11 ms | 38.3× | 61× |
| relation `2^26` | 5.307 + 1.760 s | 53.5 ms | 25.1 ms | 607 / 45 ms | 32.9× | 57× |
| relation `2^27` | 10.53 + 3.42 s | 110 ms | 51 ms | 1255 / 91 ms | 31.3× | 56× |
| gkr `2^24` | 2.629 + 0.721 s | 43.8 ms | 11.4 ms | 398 / 30 ms | 16.5× | 39× |
| gkr `2^26` | 10.25 + 2.70 s | 173 ms | 46 ms | 1543 / 121 ms | 15.6× | 38× |
| gkr `2^27` | 20.36 + 5.03 s | 340 ms | 94 ms | 3099 / 242 ms | 14.8× | 38× |

Per round, against main's CPU: round 0 (M31 tables) runs 47–73× faster for `relation` and 24–29× for
`gkr` at `2^24..2^27`; round 1 (QM31) 38–46× and 23–31×. All per-round times are in
the ledger and `results.txt`; `2^20` and `2^22` are there too.

- **Upload.** The measured upload phase includes the bench's host staging (vector
  copies and allocation) and runs at about 1.3 GB/s. The bus itself moves 1 GiB in
  60.6 ms pageable (17.7 GB/s) and 40.2 ms pinned (26.7 GB/s). "Bus-bound" charges the
  uploaded bytes at the pageable rate.
- **CPU construction dominates the CPU stage.** `block_table` is sequential; table
  construction takes 2–4× the CPU rounds. The device builds the same tables in
  milliseconds.
- **Mac calibration.** E16-22's laps come from an Apple M4 Max (16 threads). On it the
  same CPU benchmark is slower in rounds and faster in construction than on the box.
  Stage speedups against the Mac CPU at `2^24..2^27`: 39.7–83.4× rounds-only,
  26.6–41.8× build + rounds with bus-bound upload, 5.0–7.2× with the measured upload
  phase. The Mac's `gkr 2^27` CPU run (19 s) is memory-bound on 48 GB.

## 4. Ceiling (Amdahl, E16-22 laps)

`T' = r + M/s + R/s_rest`, from `bench/ledger/e16-22-dev-zk-stories42m-t32-mac-after.json`:
- `M` = masked relations + ZK-GKR = 35.17 + 173.24 s (measured here);
- `R` = LogUp trees and tops + claim batches + source preparation = 24.96 + 21.35 +
  103.53 s (not measured here);
- `r` = the rest, 107.47 s, of a 465.72 s prove.

`s` uses the Mac-calibrated stage speedups at `2^24..2^27` (the box CPU gives
slightly higher ceilings; `masked/summarize.py` prints both).

| Upload model for `M` | `R` at the same `s` | `R` at E16-21 rounds-only (25.4–76.1×) | `R` at E16-21 upload-inclusive (2.9–15.9×) | `R` on the CPU |
|---|---:|---:|---:|---:|
| resident, no upload | 4.01–4.13× | 3.93–4.14× | 2.84–3.88× | 1.78–1.79× |
| bus-bound upload | **3.85–4.01×** | **3.84–4.07×** | 2.79–3.82× | 1.76–1.78× |
| measured upload phase | 2.60–2.96× | 3.00–3.37× | 2.32–3.19× | 1.56–1.63× |

Unbounded (every offloadable stage free): 4.33×.

- The masked and GKR rounds are no longer the question: at any measured ratio they
  cost 5–8 s of device time against 208 s of CPU time.
- **The ceiling clears 3× when `R` is also on the device with resident data.** Hiding-
  source preparation (encoding and Merkle, 103.5 s) is the deciding stage: with `M`
  bus-bound at the lowest measured `s` (26.6×) and trees and batches at E16-21's
  lowest rounds-only ratio, 3× needs source preparation at **≥ 2.7×** on the device
  (≥ 4.3× if trees and batches only reach 2.9×).
- With `M` alone on the device the ceiling is 1.8×: a partial backend is a NO-GO.
- Re-uploading every stage's tables at the bench's staging rate (bottom row) leaves
  2.6–3.0×. A resident design uploads the committed witness once, through pinned
  staging.

**PR #364** (merged after this measurement; the CPU figures above already use its
tree) took the Mac stories42M dev-zk prove from
475.6 to 369.7 s (single runs) by speeding up the masked products, so it shrinks `M` on
the CPU. Its stage laps are not recorded. If the whole 106 s came out of the
offloadable stages, the unbounded ceiling falls to about 3.7× and `R` needs about 8×
on the device. That is an estimate, not a measurement: the first integration step
re-profiles on the then-current main.

## 5. Reproduce

```sh
cd research/gpu-gating/masked
cargo test                                   # CPU; the device test is not built
cargo test --release --features cuda         # device parity (skips without a driver)
STELE_E16_35_LOGN=20,22,24,26,27 cargo test --release --features cuda -- --nocapture
cargo run --release --features cuda -- gkr 24 check   # or cpu, gpu; and: h2d 28
bash run.sh   # the box run (expects ~/main and ~/pr364 trees); python3 summarize.py out [macout]
```

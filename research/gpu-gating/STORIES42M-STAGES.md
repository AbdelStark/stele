# stories42M stage profile and the GPU ceiling (task E16-22)

Status: measurement report. It answers ADR-103's open question: is the GPU NO-GO right
for a real checkpoint? It also measures one CPU change that the profile made obvious
(the parallel plain checker, ADR-120).

## 1. Method

- **Host.** Apple M4 Max (16 threads, 48 GB), macOS, release build.
  - The task named a 24-thread Linux host with `perf`. No rented host was available,
    so the owner asked for the Mac.
  - The stage shares are the Mac's. The 24-thread target would have more parallel
    headroom for the offloaded stages, so the residual share there is not smaller.
- **Wall time per stage.**
  - `parallel::Laps` (`STELE_STAGE_TIMES=1`) prints the wall time of each prover
    stage. It is off by default and touches no value, transcript or byte.
  - Laps sit at the plain-development engine steps (RFC-0026 §4), at the dev-zk claims
    steps (RFC-0013 A5), and on the witness path.
- **CPU per stage.**
  - `stage_profile.py` classifies a macOS `sample` call tree (1 ms) of one whole
    prove.
  - With `prove-dev`'s checker and engine joined (E16-23), the main thread only waits.
    Its samples no longer give stage shares (ADR-103's method). The laps replace them,
    and the samples split stages by work kind.
- **Workloads.** stories42M with the E16-11 prompt (24 tokens):
  - development, profile byte 3, `T = 64`, checked `23..64`;
  - dev-zk, profile byte 4, `T = 32`, checked `23..32`, `P = 8`.

## 2. Stage wall times

Development, byte 3, `T = 64`:

| Stage | Before (lap run) | After the parallel checker (median run) |
|---|---:|---:|
| witness: decode, extend, weights | 6.8 s | 7.2 s |
| witness: layout, capture, assign | 16.9 s | 11.4 s |
| model sources | 1.1 s | 1.2 s |
| **plain checker** (beside the engine) | **155.9 s** | **22.5 s** |
| engine: sources and counts | 14.8 s | 22.7 s |
| engine: zerocheck | 11.0 s | 11.5 s |
| engine: LogUp | 51.1 s | 46.7 s |
| engine: matmul | 1.3 s | 1.6 s |
| engine: claim batch and openings | 18.3 s | 19.1 s |
| engine total | 96.7 s | 101.7 s |
| checker ‖ engine (critical path) | 155.9 s | 102.0 s |
| **prove wall** (medians of three) | **167.6 s** | **123.6 s** |

The `T = 64` profile's surprise: the sequential plain checker, not the engine, was the
critical path. It took 156 s beside a 97 s engine.

dev-zk, byte 4, `T = 32`:

| Stage | Before | After |
|---|---:|---:|
| witness (decode, layouts, capture, assign) | 12.1 s | 12.0 s |
| witness: plain check 1 + check 2 (sequential) | 64.1 + 61.2 s | 6.6 + 6.6 s |
| source messages (mask streams) | 20.7 s | 21.6 s |
| sources: prepare (encode, salts, Merkle) and certify | 84.5 s | 103.5 s |
| LogUp trees and tops | 21.8 s | 25.0 s |
| relations (masked sumchecks) | 35.1 s | 35.2 s |
| **ZK-GKR** | **177.7 s** | **173.2 s** |
| claim batches and openings | 27.2 s | 21.4 s |
| self-verify | 31.0 s | 30.6 s |
| **prove wall** (one run each; single runs, not medians) | **562.5 s** | **465.7 s** |

The source-preparation stage was 19 s slower after (84.5 → 103.5 s). These are single
runs on a shared host. That stage runs no checker code, the proof bytes are the same,
and the checker now competes with nothing at that point, so the difference is host
noise, not a regression.

ZK-GKR is the top dev-zk stage. The masked factor products dominate it (QM31
`TermPlan::sum` in the CPU samples).

CPU samples, all threads, after:
- **Development:**
  - dense rounds 32%;
  - witness and relation tables 25%;
  - encoding 8.5%;
  - zerocheck 8.0%;
  - LogUp 7.8%;
  - Merkle 0.6%;
  - grinding < 0.1%.
- **dev-zk:**
  - masked-sumcheck products, relations and ZK-GKR, 63%;
  - encoding 10%;
  - Merkle 1.7%;
  - claim batching 1.1%.

## 3. GPU ceiling (Amdahl)

`T' = r + O/s`. `O` is the offloadable work: encoding, Merkle, dense, zerocheck,
masked and GKR rounds, LogUp levels and claim batches. `r` is the rest. `s` is a
device speedup from `bench/ledger/e16-21-gpu-gating.json`, all four sizes for both
workloads:
- rounds only (CPU total over GPU rounds): 25.4×, 41.8×, 71.9× and 76.1×;
- with the upload (CPU total over GPU total): 15.9×, 8.2×, 7.4× and 2.9×.

For development, the engine runs beside the checker, so `T' = 21.6 s + max(22.5 s,
101.7 s/s)`. 21.6 s is the witness, model sources and the rest; 22.5 s is the checker.

| Workload | Wall | Offloadable | Ceiling at `s = ∞` | At the rounds-only ratios | At the upload-inclusive ratios |
|---|---:|---:|---:|---:|---:|
| development before (checker-bound) | 167.6 s | engine (beside a 156 s checker) | about 1.0× | about 1.0× | about 1.0× |
| development after | 123.6 s | ≤ 101.7 s (the whole engine) | **2.80×** | 2.80× (checker-bound) | 2.19×–2.80× |
| dev-zk after | 465.7 s | 358.3 s | 4.34× | 3.83×–4.15× | **2.02×–3.58×** |

- **Development.**
  - After the checker change, the floor is witness, model sources, the checker (now
    22.5 s, beside the engine) and the rest: 44.1 s.
  - Even an infinitely fast device that took the whole engine stays below ADR-103's
    3× gate.
  - Before the change, a GPU would have bought nothing, because the critical path was
    the CPU checker.
- **dev-zk.**
  - The offloadable share is 77%.
  - With resident tables (rounds-only ratios) the ceiling is above 3× at every
    measured size.
  - With the measured upload cost, it is above 3× only at the smallest size's ratio
    (15.9×, `2^16` entries). It falls to 2.02× at the largest (2.9×, `2^24`), and
    stories42M's tables are near that size.
  - It also needs the masked factor tables built on the device; they are counted as
    offloadable here, which is optimistic.

## 4. CPU optimisations, by expected gain

1. **Parallel plain checker. Done (ADR-120).**
   - Development: 167.6 → 123.6 s (1.36× end to end; the checker went from 156 to
     22 s).
   - dev-zk: 562 → 466 s (1.21×, single runs; the checks went from 125 to 13 s).
2. **ZK-GKR and masked products** (dev-zk 173 + 35 s; 63% of dev-zk CPU):
   - SIMD QM31 (`stele-simd` has `PackedQM31`) in `TermPlan::sum` and the folds;
   - M31 factor tables where the values are base-field (leaf tuple and multiplicity
     columns, selectors, and round 0 of relation instances before any challenge);
   - expected 1.3×–2× on the stage.
3. **Hiding-source encoding** (dev-zk 103.5 s): SIMD M31 Circle butterflies
   (`PackedM31`); expected about 1.5× on the stage.
4. **BLAKE3.** On aarch64, blake3's build script already enables NEON. Its `std`
   feature adds runtime AVX2 and AVX-512 detection, which helps only x86_64 hosts.
5. **Development LogUp** (46.7 s, now the top development stage) and the engine's
   sources and counts (22.7 s): the leaf preparation and counts are CPU-bound table
   work.
6. **dev-zk's two plain checks** (13 s together): check the committed relation once.

## 5. Reproduce

```sh
cargo build --release -p stele-cli
STELE_STAGE_TIMES=1 target/release/stele prove-dev ... 2> laps.txt
CARGO_PROFILE_RELEASE_DEBUG=line-tables-only cargo build --release -p stele-cli
target/release/stele prove-dev ... & sample <pid> 900 1 -mayDie -file sample.txt
python3 research/gpu-gating/stage_profile.py sample.txt
```

Ledgers:
- `bench/ledger/e16-22-dev-stories42m-t64-mac-before.json`;
- `bench/ledger/e16-22-dev-stories42m-t64-mac-after.json` (median runs; the load log is
  in `host_context`).

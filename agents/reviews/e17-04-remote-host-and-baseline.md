# Review record — Task E17-04 and Issue #454 single-H100 FlashProve baseline

- **Task:** `E17-04` + Issue `#454` (Lane B · RFC-0018 §1, RFC-0027 §3)
- **Branch:** `task/E17-04-remote-host-and-baseline`
- **Tier:** Development (T0; tooling, remote runner, first-use ledgers, and external baseline documentation)

## 1. Lane P (protocol) independent review

- **Initial review:** **CHANGES REQUESTED** (`F1`–`F8`).
  - **F1:** Hardened `bench/remote.py` against shell, option, `#SBATCH`, and mount-spec injection (`IMAGE_DIGEST_RE`, `validate_host`, `validate_remote_dir`, `validate_host_mount_path`, `validate_slurm_value`, separate Apptainer `--bind` flags, `shlex.quote` for user `cargo_cache_dir`, and `--` on `ssh`/`scp`/`cp`).
  - **F2:** Extended `parse_gnu_time_with_resolution` for `>= 1 h` `h:mm:ss` outputs and trailing tab-prefixed GNU time blocks; replaced the Python fallback timer with integer centisecond `divmod` streaming stderr directly to disk; reconciled `build_inference_ledger` with exact `prove.wall_ns` and regenerated `bench/ledger/e17-04-dev-stories42m-24t.json`.
  - **F3:** Resolved relative `--out-dir`/`--ledger-out` paths before invoking `cwd=ROOT` subprocesses; added `proof.sha256`, `gate parity:` receipt, and non-empty `gpu.txt` validation to `build_gpu_parity_ledger`; recorded `uname -m` in `arch.txt` for architecture-faithful CPU device labels; guarded whitespace-only `--note-suffix` in `bench/dev_e2e.py`.
  - **F4:** Fixed case-insensitive secret-pattern assertion in `scripts/tests/test_remote.py`, added regression tests for `F1`–`F3` and baseline JSON consistency, and added `.env` to `.gitignore`.
  - **F5 & F6:** Reconciled proof byte counts (`18,776,296 B`, `18,775,825 B`, `18,790,452 B`, `18.78 MB`), rounded display metrics, decimal GB (`kib * 1024 / 10^9`) across all RSS entries, and `measure_rate.py` rate-truncation convention between `docs/research/flashprove-v016-h100-baseline.md` and `bench/baselines/flashprove-v016-maverick-h100.json`.
  - **F7:** Published verified end-to-end timings and rates (excluding and including shutdown) for batch 24 and batch 1, documented container OS and CUDA 13.2 runtime library SHA-256 digests, and fixed the preregistered `#464` sample size to `n = 4` balanced pairs `(AB, BA, AB, BA)`.
  - **F8:** Corrected RFC citations to `RFC-0017 row 4` and `RFC-0004 §5.3, A2`.
- **Second review:** **CHANGES REQUESTED** (`F9`).
  - **F9:** Fixed three numerical typos (`fit` RSS `221.15 GB`, batch-24 RSS `251,023,036 KiB`, and added upstream `cp_verify_max_rss_gb: "3.53"` + `18.40 vs ~21 s` single-thread comparison).
- **Final re-review:** **APPROVE**.
  - Verified `bench/remote.py`, `bench/dev_e2e.py`, `scripts/tests/test_remote.py` (9/9 passing), both validated first-use ledgers (`bench/ledger/e17-04-dev-stories42m-24t.json` at `$0.0373 USD` and `bench/ledger/e17-04-h100-parity-smoke.json` at `$0.5911 USD`), fresh `bench/scoreboard.md`, and complete `#454` baseline consistency.

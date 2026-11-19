# Review record — Task E17-01 (in-process stage timers and deterministic counters)

- **Task:** `E17-01` (Lane B · RFC-0018 A2, RFC-0027 §1 & §3)
- **Branch:** `task/E17-01-stage-timers-counters`
- **Measured code commit:** `f16ca0dfaf8beeefd2b352ae91a12797def6ace5`
- **Tier:** Development (T0; no security level, FS unproven, PCS conjectural, no zero-knowledge)

## 1. Lane P (protocol) independent review

- **Initial review (commit `1f073988`):** **REQUEST CHANGES** (F1–F5).
  - **F1:** `weight_reads` collapsed reduction reads and opening reads into two booleans, capping `weight_reads` at `<= 2` and hiding actual physical weight passes.
  - **F2:** `weight_elements_read` over-counted RFC-0026 A6 row-blocked matmuls (`lhs`/`rhs` skip entries outside `Ref::fixed` bits) and mixed padded source cells with unpadded column reads.
  - **F3:** `stele-cli`'s `sanitize_counter_name` could emit duplicate or empty `lookup_positions_check_*` keys on identical, sign-colliding, or punctuation-only table names.
  - **F4:** `bench/dev_e2e.py` lacked collision checks against reserved stages (`prove_dev_wall`, `model_commitment_once`) and `--zk` counters, omitted `plan` from `REQUIRED_STAGES`, needed stricter `stage_ns`/`counter` prefix checks, lookup/section cross-checks, non-empty requirement on non-`--zk` runs, and explicit handling of coarse `gnu_time` rounding.
  - **F5:** L1 pinned-hash verification, re-recorded L1 and L2a ledgers on the 24-thread host class, `bench/scoreboard.md` regeneration, and Lane V CLI sign-off were pending.
- **Re-review (commit `f16ca0df`):** **APPROVE** (Lane P scope).
  - **F1 & F2 resolved:** Replaced booleans with exact per-weight-column unpadded element counts `col_reads: Vec<u64>` across Step 3 (`lookup::counts` selected positions), Step 4 (`zerochecks`), Step 5 (`lookup::prove` `originals`), Step 6 (`matmuls`: `2^(w.n) >> fixed_bits` for `lhs`/`rhs`, `2^(w.n)` for `out`), and Step 7 (one logical unpadded opening pass per weight column in each opened model source). Verified by `matches_reference_weight_reads_for_repeated_and_row_blocked_matmuls` (single=4/16, double=5/20, 2-block split=4/16).
  - **F3 resolved:** `sanitize_counter_name` encodes `-` as `neg_` and `lookup_check_counter_name` emits `lookup_positions_check_{index}_{suffix}` (fallback `unnamed`), verified by `matches_reference_unique_lookup_check_counter_names`.
  - **F4 resolved:** `bench/dev_e2e.py` enforces `plan` in `REQUIRED_STAGES`, reserved-stage and `--zk` counter disjointness, strict prefix matching, `--legacy-no-stages`, lookup-sum and section-byte cross-checks, resolution-checked `prove.wall_ns`, and explicit fail-closed diagnostics when a stage exceeds `prover_time_ns`. Verified by `scripts/tests/test_dev_e2e_stages.py`.
  - **Workflow 03 statement:** Tested transcript isolation, `no_std` builds (`--no-default-features`), L0 pinned hashes, 1-vs-2-thread counter/proof parity, repeated and row-blocked matmuls, colliding check names, and malformed/spoofed ledger reports; every defect was rejected.

## 2. Lane V (verifier & CLI) independent review

- **Review (commit `f16ca0df`, `crates/stele-cli` scope):** **APPROVE**.
  - Verified CLI contract (`PROOF WRITTEN` final line, exit codes 0/1/2, unchanged `verify-dev`, `verify-registered`, `plan-digest`, `commit-model`, and `--zk` outputs), injective `[a-z0-9_]+` counter-key hygiene in lockstep with `bench/dev_e2e.py::parse_report`, verifier independence (`stele-verifier` untouched, INV-11), feature quarantine (`controls`/`standard-unproven`/`bench` excluded), INV-12 (`rust-policy.sh`), glossary hygiene (`glossary-lint.sh`), and thread-count determinism (`crates/stele-cli/tests/stages.rs`).

## 3. F5 Ladder Evidence & Pinned Proof Hashes

- **L1 pinned-hash verification (release, 24 pinned CPU cores, commit `f16ca0df`):**
  - `cargo test --release --frozen -p stele-prover --test development accepts_eight_layer_window -- --ignored --exact`: PASS (14.03 s)
  - `cargo test --release --frozen -p stele-prover --test development accepts_eight_layer_window_on_a14_sources -- --ignored --exact`: PASS (13.27 s)
- **Validated ledgers (24 pinned physical CPU cores, `x86_64 Intel(R) Xeon(R) Platinum 8480CL`, commit `f16ca0df`):**
  - **L1 (`dev/synthetic-8layer-t64`, T=64):** [`bench/ledger/e17-01-dev-synthetic-8layer-24t.json`](../../bench/ledger/e17-01-dev-synthetic-8layer-24t.json) — prove `12.20 s` (`5.246 tok/s`), verify `1.23 s`, proof `7.0 MB` (`7,024,521 B`), RSS `3.0 GB`, `244,033` cells/token, `234,805` lookups/token, `weight_reads = 4`, controls `4/4`.
  - **L2a (`dev/stories42m-t64`, T=64):** [`bench/ledger/e17-01-dev-stories42m-24t.json`](../../bench/ledger/e17-01-dev-stories42m-24t.json) — prove `164.28 s` (`0.390 tok/s`), verify `13.22 s`, proof `15.6 MB` (`15,554,761 B`), RSS `44.5 GB`, `3,375,921` cells/token, `4,202,085` lookups/token, `weight_reads = 5`, controls `4/4`.
- **Scoreboard:** [`bench/scoreboard.md`](../../bench/scoreboard.md) regenerated via `python3 bench/scoreboard.py --write` and verified fresh via `--check`.

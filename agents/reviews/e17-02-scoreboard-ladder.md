# Review record — Task E17-02 (scoreboard generator and ladder workloads)

- **Task:** `E17-02` (Lane B · RFC-0018 A2, RFC-0027 §3)
- **Branch:** `task/E17-02-scoreboard-ladder`
- **Tier:** Development (T0; no protocol changes, tooling/ledger validation only)

## 1. Lane P (protocol) independent review

- **Initial review:** **REQUEST CHANGES** (F1–F3 + two minor notes).
  - **F1:** `validate_ledger` accepted conflicting `model_config.rung` values on `W*` workloads, non-ladder `W2`/`W7`/`W8` workloads, and `micro` records; `render_scoreboard` omitted canonical `W1 -> L3c`, `W3 -> L4`, `W4..W6 -> L6` fallback mapping.
  - **F2:** `bench/scoreboard.py` used IEEE-754 binary64 divisions while `stele-bench scoreboard` used exact `u128` round-half-to-even (INV-12), risking future CI divergence on binary64 midpoints such as `15_650_000 / 1e6`, `2_675_000_000 / 1e9`, and `1 / 80`.
  - **F3:** Missing negative-control and edge-case tests for the 60-hash pre-E17-02 allowlist (1-byte tamper rejection), invalid ledger rejection inside `render_scoreboard`, empty and fully populated rung directories, `fmt_fixed_u128` midpoint and `u64::MAX` cases, `standard`/`treaty`/`micro`/`privacy` rows, `profile_byte` labels, and missing/zero/fallback counters.
  - **Minor notes:** Bound `stele-bench scoreboard --check` file read via `File::take`, and mark `--rung` required in `bench/dev_e2e.py`'s usage docstring.
- **Re-review:** **APPROVE**.
  - **F1 resolved:** Added `workload_rung` in `crates/stele-bench/src/scoreboard.rs`, enforced rung consistency in `validate_ledger` (`crates/stele-bench/src/lib.rs`), and mirrored `W1`/`W3`/`W4`–`W6` mapping in `render_scoreboard` and `bench/scoreboard.py`.
  - **F2 resolved:** Replaced binary64 divisions in `bench/scoreboard.py` with exact integer round-half-to-even `fmt_fixed` matching `fmt_fixed_u128`.
  - **F3 resolved:** Added unit tests in `crates/stele-bench/src/scoreboard.rs`, integration and negative-control tests in `crates/stele-bench/tests/ledger.rs`, and midpoint parity tests in `scripts/tests/test_scoreboard.py`.
  - **Minor notes resolved:** Bounded `--check` read to `rendered.len() + 1` bytes in `crates/stele-bench/src/main.rs` and updated `bench/dev_e2e.py` docstring.
  - **Independently verified:** Byte-identical output across all 190 ledgers (109 inference, 81 micro) between `stele-bench scoreboard`, `bench/scoreboard.py`, and committed `bench/scoreboard.md`; 60/60 exact BLAKE3 allowlist entries in `crates/stele-bench/src/legacy_rungs.rs`; INV-12 (`rust-policy.sh`), `glossary-lint.sh`, `rfc-status.sh`, `docs-links.sh`, `ledger-validate.sh`, and CI freshness tests pass.

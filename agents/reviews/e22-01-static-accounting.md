# Independent Lane B & Lane P Reviews — Task E22-01 (Static Accounting of Cells and Lookups)

## Independent Lane B Review — Tooling, Ledgers & Scoreboard

- **Task:** `E22-01` (Lane N · RFC-0027 §3, RFC-0026 §5)
- **Branch:** `task/E22-01-static-accounting` (base `task/E22-03-wide-residual-8b` @ `87705193`)
- **Reviewed commits:** `ebb63132` (Lane B pass), finalized at `dc5b85fa` (code + tests) and `bb32b60c` (ledgers + scoreboard restamped against `dc5b85fa`)
- **Reviewer:** Independent Lane B reviewer (`bb952d80-73c3-4ddf-ae2b-7b71f5afeb88`)
- **Scope:** `crates/stele-bench/src/{lib,main,accounting,scoreboard}.rs`, `crates/stele-bench/tests/accounting.rs`, `bench/scoreboard.{py,md}`, `bench/ledger/e22-01-static-accounting-{l1,l2a,l2b,l3a,l3b}.json`, `crates/stele-prover/src/{lib,accounting}.rs`, `agents/tasks/graph.yaml`
- **Tier:** Development (T0; tooling and micro ledgers only, no protocol change or security claim)
- **Verdict:** **APPROVE** (after resolving F1–F6 and N1–N5)

### Findings & Resolution

1. **F1 [High — Resolved]:** Initial `e22-01-static-accounting-l3b.json` mislabeled `T = 128` as `L3b` contrary to RFC-0027 §3 (`T = 1,024`). Replaced with the true `T = 1,024` `L3b` baseline (`120,089,426,944` cells / `117,274,831/tok`, `119,935,868,928` lookups / `117,124,872/tok`, `attention` top module at `39,755,776` cells/tok and `36,083,712` lookups/tok) and added the `L2b` baseline (`stories42m`, `T = 1,024`: `5,170,381,824` cells / `5,049,201/tok`, `4,820,997,120` lookups / `4,708,005/tok`, `attention` top module).
2. **F2 [High — Resolved]:** Initial ledgers pinned parent commit `87705193` where `stele-bench accounting` did not exist. Finalized code committed first, then all 5 ledgers regenerated against that code commit (`dc5b85fa`) and `bench/scoreboard.md` regenerated.
3. **F3 [High — Resolved]:** `account_model` previously hardcoded `Statement.next = Some(0)`, breaking valid prefix ranges (`checked.end < length`). Fixed to `next: (checked.end == length).then_some(0)` with checked `u32::try_from` bounds and regression tests in `stele-prover` and `stele-bench`.
4. **F4 [Medium — Resolved]:** `account_relation` now attributes `Compose` via `module_of(&compose.name)` (`up.composes == 0`, `gated + gated_row == 24` on L1), splits `("gated", Some("row")) => "gated_row"`, drops dead `silu/*` branches, and tests real `Layout::declare` prefixes in `accepts_normalized_module_names`.
5. **F5 [Medium — Resolved]:** `sanitize_counter_key` now matches E17-01 `stele-cli::sanitize_counter_name` (`neg_` for `-`, `"unnamed"` empty fallback), and `insert_unique` rejects duplicate sanitized counter keys.
6. **F6 [Medium — Resolved]:** Added `crates/stele-bench/tests/accounting.rs` (4 integration tests) covering CLI default/`--artifact`/`--public`/prefix-range/`--ledger-out` paths, invalid arguments and corrupted/truncated artifacts, invalid rung and duplicate sanitized key rejection, and `static_rows` scoreboard rendering and malformed-ledger rejection.
7. **N1–N5 [Low — Resolved]:** Uniform `saturating_add` on `lookups_by_width`; 49-byte CQIS artifact header (`cqis-weights-v1`, `record_count`) and `byte_length` checks matching `stele-cqis/src/model/artifact/stream.rs`; non-UTF-8 CLI rejection via `require_utf8`; explicit INV-13 `"profile": "standard"` micro-schema disclaimer in ledger `note`; updated scoreboard docstrings and `agents/tasks/graph.yaml` (`status: in_progress`, `agent`, `branch`).

### Verification Summary

- **E17-01 engine counter parity (Acceptance #2):** Verified exact 23/23 counter parity (`committed_cells`, `lookup_positions`, and all 21 `lookup_positions_check_*`) against `bench/ledger/e17-01-dev-synthetic-8layer-24t.json` (L1: `15,618,112` cells, `15,027,520` lookups) and `bench/ledger/e17-01-dev-stories42m-24t.json` (L2a: `216,058,944` cells, `268,933,440` lookups), plus live L0 `prove_window_development_measured` parity (`cargo test -p stele-prover --lib accounting`).
- **Ledger consistency & privacy (Acceptance #3, INV-14):** All 5 ledgers (`l1`, `l2a`, `l2b`, `l3a`, `l3b`) pass `stele-bench ledger validate`, balance identically across `per_module`, `per_relation_kind`, `lookups_by_width`, `lookup_positions_check_*`, `module_*`, and `width_*` counters across all 27 normalized `Layout::declare` modules (no `"other"` bucket), stamp code commit `dc5b85fa`, and contain no leaked hostnames, usernames, or local paths.
- **Scoreboard & gates (INV-12, `#![forbid(unsafe_code)]`):** Byte-identical output across `stele-bench scoreboard`, `bench/scoreboard.py`, and `bench/scoreboard.md`; `cargo test -p stele-prover --lib accounting`, `cargo test -p stele-bench`, `scripts/tests/test_scoreboard.py`, `cargo fmt --check`, `cargo clippy -p stele-prover -p stele-bench --all-targets -- -D warnings`, `rust-policy.sh`, `glossary-lint.sh`, `ledger-validate.sh`, `rfc-status.sh`, `docs-links.sh`, and `check.py` bootstrap/quarantine guards all pass.

---

## Independent Lane P Review — `crates/stele-prover` (`E22-01`)

- **Task:** `E22-01` (Lane N — Static accounting of cells and lookups per token; Lane P owning-crate review of `crates/stele-prover`)
- **Audited commit:** `dc5b85fa` (`crates/stele-prover/src/lib.rs`, `crates/stele-prover/src/accounting.rs`; baseline ledgers restamped in `bb32b60c`) on `task/E22-01-static-accounting` (base `task/E22-03-wide-residual-8b`)
- **Reviewer:** Independent Lane P reviewer (`bf85612a-c9e1-4df4-b5df-249c8046d965`)
- **Verdict:** **APPROVE** (after resolving F1–F4 from initial review of `ebb63132`)

### Findings & Resolution

1. **F1 [Medium — Resolved]:** `account_relation` initially deduplicated `lookups_by_check` by `String` check name rather than by `(TableId | Range(bits))`, diverging from `stele-reductions/src/relation.rs` (`Target::{Table(u32), Range(u8)}`) when distinct tables share a name (e.g., per-layer `"silu_q"`) or a table is named `"range_{bits}"`. Fixed in `dc5b85fa` (`accounting.rs:166-178, 192-196, 220-224, 280-283`) via a local `CheckTarget::{Table(u32), Range(u8)}` enum.
2. **F2 [Low — Resolved]:** `account_model` did not reject `length > model.shape().context() as usize` before allocating `vec![0u32; length]`. Fixed in `dc5b85fa` (`accounting.rs:405-411`) to return `Error::StatementMismatch` in parity with `Statement::validate` (RFC-0025 §2.6).
3. **F3 [Low — Resolved]:** Added unit test `accepts_distinct_checks_for_duplicate_table_names_and_range_collision`, explicit L1 check-count parity (`21` checks matching `kc`), `validate_artifact_header` short-header (`< 49` B) and corrupted `record_count` rejections, `vectors = None` placeholder accounting, and `length > context` rejection (`accounting.rs:521-591, 655-662, 717-734`).
4. **F4 [Info — Resolved]:** Aligned doc comments (`lookups_by_check`, `range:s8`/`table:<name>(<widths>)`, `G/argmax/m -> argmax`) and test function names with `AGENTS.md §6`.

### Verification Summary

- **Protocol & soundness isolation:** Confirmed zero changes to `development.rs`, `development/plan.rs`, `zk.rs`, `bundle.rs`, `registry.rs`, or `Cargo.toml`. `accounting.rs` is purely read-only `Layout::declare` + `Relation::validate` + counting under `#![forbid(unsafe_code)]`, `#![no_std]`, and zero floating-point arithmetic (INV-12).
- **Accounting accuracy & E17-01 parity:** Verified `committed_cells` (`Kind::Witness`), `lookup_positions` (`Lookup` + `Range`), static shift bounds (`<= MAX_VARS = 30` post-`validate()`), saturating summation, `CheckTarget`-keyed `lookups_by_check` order, and `module_of` attribution (`Compose` via `compose.name`, `Range` via `col.name`, `Lookup`/`Identity`/`Matmul` via constraint name; exact 27 RFC-0026 §5 modules on L3b).
- **Artifact header & 1-D vector parsing:** Verified 49-byte `cqis-weights-v1` header + LE `u16` record count + `ArtifactLayout::byte_length()` validation, `r.bits() == 16` check, and checked arithmetic/slicing in `extract_vectors_from_artifact`.
- **Statement handling & tests:** Verified `checked.end == length` vs `< length`, `u32::try_from`, power-of-two and context bounds, live L0 engine parity, L1 23/23 E17-01 counter parity, `one-layer-wide-gqa`, prefix checked range, placeholder mode, duplicate-name/range-collision check separation, and corrupted/truncated artifact rejection.
- **Sign-off:** Approved for Lane P (`crates/stele-prover`) at the development tier (RFC-0027 §2–§3, §5). No protocol behavior or profile soundness claim is introduced or altered.

## Rebase onto `main` (`ffa41fcf`) & Real-Gain L3 Refresh

- Rebased onto `main` (`ffa41fcf`, including `E18-06` and `E22-04` Gate M1) at code commit `4a41fe0c` (1-line `segment_layers: 0` initializer in `crates/stele-prover/src/accounting.rs`).
- Regenerated all 5 baseline ledgers stamped against `4a41fe0c`, upgrading `L3a` and `L3b` from placeholder 16-bit gains to real Gate M1 `public.bin` 1-D norm gains (`exact_gain_widths=true`: L3a `5,331,956,672` cells / `83,311,823/tok`, `13,815,824,896` lookups / `215,872,264/tok`; L3b `119,896,488,960` cells / `117,086,415/tok`, `119,742,930,944` lookups / `116,936,456/tok`).

# Independent Cross-Lane & Soundness Review — `task/E18-06-segments-bounded-memory`

- **Scope:** RFC-0026 A27 (`docs/rfcs/RFC-0026-development-end-to-end.md`), `docs/rfcs/RFC-0000-index-and-process.md`, ADR-148 (`agents/context/decision-log.md`), `crates/stele-ir`, `crates/stele-reductions`, `crates/stele-prover`, `crates/stele-cli`, `tests/negative-controls` (`NC-1335`, `NC-1336`), L2a unsegmented vs segmented ledger pair and regenerated `bench/scoreboard.md`
- **Lane / tier:** Lane P · development tier (RFC-0027 §2)
- **Reviewer:** Independent Lane-V/N & Soundness Auditor (`14d385be`)
- **Verdict:** **APPROVE** (after resolving initial findings F1–F5)

## Summary

- **F1 (blocker, resolved):** Rejected `public.segment_layers > 0` in `crates/stele-prover/src/development/registry.rs` (`Error::StatementMismatch`), blocking `stele plan-digest` and direct callers from hashing `v2` segmented relations into an A16 `stele-dev-plan-v1` entry, with a regression test on a segmented profile-5 `Public`.
- **F2 (minor, resolved):** Preserved both `assign_segment` and `check_segment` errors via `callback_err: Option<Error>` in `prove_inner_captured`.
- **F3 (minor, resolved):** Added multi-layer uneven segmentation coverage (`eight-layer`, `T = 4`, `profile = 5`, `segment_layers = 3` -> 4 segments `[Embed+L0..2]`, `[L3..5]`, `[L6..7]`, `[Finish]`), exercising layer-to-layer carried residual boundaries (`norm1` + `mid`), uneven `k ∤ L`, and profile-5 grinding.
- **F4 (nit, resolved):** Switched `Relation::segments()` to `m.saturating_add(1)`.
- **F5 (nit, resolved):** Aligned step comments in `crates/stele-reductions/src/relation.rs` with RFC-0026 A27 §3.

## Adversarial Check (Workflow 03)

Attempted to break the segmented protocol by reading a non-carried column of segment `s - 1` (both by clearing `carried` and by redirecting a segment-1 read), by reordering segment witness roots (and whole `(root, cert)` sections), by injecting unexpected `reductions` or cross-version `v1`/`v2` container and `v5` bundle mismatches, by checking source/instance ID bit-width collisions across segments and model sources (`1 <= S <= 65535`, `targets < 65533`), and by passing a segmented profile-5 `stele-dev-public-v5` bundle into `registry::publish`. The controls `NC-1335` (`StatementMismatch` / `Invalid::Segment`), `NC-1336` (Policy 1: `RootMismatch`; Policy 2: `GrindMismatch`), `verify_segmented` shape checks, and `registry::publish` (`StatementMismatch`) rejected every attack while unsegmented v1 proofs remained byte-identical.

## Verification

- `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test -p stele-ir`, `cargo test -p stele-reductions --lib relation`, `cargo test -p stele-prover --test development`
- `cargo test -p stele-negative-controls --all-features --test catalog` (152/248 controls including `NC-1335` and `NC-1336`)
- `scripts/gates/rfc-status.sh`, `scripts/gates/glossary-lint.sh`, `scripts/gates/rust-policy.sh`, `scripts/gates/docs-links.sh`
- Remote CPU L2a (`stories42m`, `T = 64`) unsegmented vs `--segment-layers 1` ledger pair and 1-vs-24-thread determinism verification

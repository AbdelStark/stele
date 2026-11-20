# Independent Lane V review — `task/E18-06b-proof-container-v2`

- **Scope:** `crates/stele-proof/src/development.rs`, `docs/rfcs/RFC-0026-development-end-to-end.md` (A26), `docs/rfcs/RFC-0000-index-and-process.md`, `agents/context/decision-log.md` (ADR-147)
- **Lane / workflow:** Lane V interface preparation for task E18-06 (Workflow 12 item 2; development-tier amendment under RFC-0027 §2)
- **Reviewer:** Independent Lane V reviewer (`a0d44e2c`)
- **Verdict:** **APPROVE** (after resolving initial findings F1–F4)

## Summary

- **F1 (blocker, resolved):** Renumbered the new decision-log entry to `ADR-147` (reserving `ADR-146` for E22-03 above existing `ADR-145` on `main`), eliminating a duplicate ADR ID collision.
- **F2 (minor, resolved):** Tightened RFC-0026 A26 to state the exact `< 18` byte `Header` rule (matching A15 §4), `18..` `ProofShape` truncation, `remaining >= 4 && S <= (remaining - 4) / 28`, fallible reservation, inherited `count <= remaining / 4`, cells/lookups/proof-bytes delta (`12 + 28 * (S - 1)` bytes over v1), controls, tier, and `Decision: ADR-147`.
- **F3 (minor, resolved):** Replaced `Vec::with_capacity(seg_count)` with fallible `try_reserve_exact` in `decode_v2` to eliminate 32-bit `usize` capacity-overflow panics on `#![no_std]` targets.
- **F4 (nit, resolved):** Added symmetric `decode_v2(&sample().encode()) == Err(Error::Header)`, high-byte `version[17]` mutation tests, minimal 118-byte 1-segment empty v2 container round-trip, empty section inside a non-empty v2 list, `decode_any` prefix truncation (`..16`, `..17`), and inflated inner list count / section length rejection tests.

## Adversarial check

Attempted to break parsing with truncated v2 headers (`0..18`) and bodies (`18..len`, including `86..90` to probe unsigned underflow in `remaining - 4`), cross-version magic/version swaps including high-byte `u16` mutations, zero segments (`S = 0`), trailing bytes, and `u32::MAX` / `max_segs + 1` inflated segment counts, inner list counts, and section lengths. Every malformed input rejected with the specified `Error::Header` or `Error::ProofShape` variant while `stele-dev-e2e-v1` remained byte-identical.

## Verification

- `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test -p stele-proof` (4/4 pass)
- `scripts/gates/rfc-status.sh`, `scripts/gates/glossary-lint.sh`, `scripts/gates/rust-policy.sh`, `scripts/gates/docs-links.sh`
- `scripts/gates/check.py` `development_surface` check on `crates/stele-proof`

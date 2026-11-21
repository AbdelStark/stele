# Independent `soundness-auditor` review — `task/E19-03-recursive-opening-fresh`

- **Scope:** `crates/stele-hash/src/{lib,tests}.rs`, `docs/security/transcript-labels.json`, `crates/stele-code/src/lib.rs` (`CircleCoeff`), `crates/stele-pcs/src/{lib,recursive}.rs`, `crates/stele-pcs/{tests/recursive.rs,examples/recursive_oracle.rs}`, `tests/negative-controls/{src/pcs_recursive.rs,src/lib.rs,catalog.md,harness/catalog.rs}`, `research/rfc0029-pcs/{verify_recursive.py,verify_recursive.py.lock,REPORT.md}`, `scripts/gates/check.py`, `scripts/tests/test_rfc0029_policy3.py`
- **Lane / workflow:** Lane C, Workflow 03 (`soundness-auditor`), development tier (RFC-0027 §2)
- **Reviewer:** Independent `soundness-auditor` (`92507d93`)
- **Verdict:** **APPROVE** (on `1be9380231ca97e330848457521b91382786e2fd`, base `70209217`, after resolving Findings 1–3)

## Findings resolved

1. **Finding 1 (blocking, INV-4 — resolved):** Replaced hardcoded `[0, running, running]` / `u_2 = 0` in the `L = 2` variant of `NC-0630` (both `tests/negative-controls/src/pcs_recursive.rs` and `crates/stele-pcs/tests/recursive.rs`) with a genuine residual-propagating malicious prover parameterized by `u_1_cand`. Verified: (a) non-vacuity — uncorrupted `u_1` (`delta == 0`) is accepted by `verify_fresh_at_point`; (b) single-entry tamper `u_1'[3] += 1` rejects with `ColumnMismatch` (scalar-forged `u_2`) and `ValueMismatch` (honest `u_2`); (c) `PcsLevelBeta`-only tamper `u_1''` preserving `⟨eq(r_col0), u_1''⟩ == value` identically rejects with `ColumnMismatch`, proving non-vacuous coverage of `ChallengeLabel::PcsLevelBeta`.
2. **Finding 2 (medium — resolved):** Enforced `ell <= MAX_DOMAIN_BITS` (`30`) inside `RecursivePlan::fresh_for_size::solve` and replaced `?` with `let Some(...) else { continue; }` so overflowing candidates never abort feasible DP searches; added regression coverage for `total_bits in [35, 38, 40]`.
3. **Finding 3 (low — resolved):** Switched `absorb_opening_statement` and `absorb_claims_header` to checked `u32::try_from`, `mul_usize`, `add_usize`; mirrored `open_fresh_at_point`'s `# Security Invariant` doc comment on `verify_fresh_at_point`; matched Rust bounds (`1 <= target_bits <= 256`, `1 <= level_count <= 30`, `1 <= ell <= 30`) in `research/rfc0029-pcs/verify_recursive.py::parse_source`.

## Adversarial check

Traced every transcript absorb/challenge order (`FieldSources`, `Batch`, `BatchCoefficient`, `Instance`, `Round`, `Sumcheck`, `Final`, `Opening`, `PcsLevelRoot`, `OpeningColumn`, `OpeningColumns`, `PcsLevelBeta`), MSB-first algebra (`CircleCoeff`, `fill_basis_table`, `WeightTerm::fold_prefix`, degree-2 Lagrange interpolation), canonical limb decoding under zero weights, `m = 0` / duplicate-query edge cases, exact `#![no_std]` `BigUint` arithmetic, and `RecursiveLedger` accounting. Attacked the `L = 2` cross-level consistency binding with single-entry and `PcsLevelBeta`-only tampers, swapped/tampered level-0/level-1 columns, tampered final `u_L` and scalar claims, mismatched plan headers, and substituted opening points outside the batching sumcheck's `r*`. Every attack was rejected for its exact RFC-0029 §6 error (`NC-0630..0634`), cross-checked by independent Python `verify_recursive.py` (10/10 vectors).

## Verification

- `cargo fmt --check`, `cargo clippy -p stele-hash -p stele-code -p stele-pcs -p stele-negative-controls --all-targets -- -D warnings`
- `cargo check -p stele-hash -p stele-code -p stele-pcs --no-default-features`
- `cargo test -p stele-hash --all-features`, `cargo test -p stele-code --all-features`, `cargo test -p stele-pcs --test recursive` (default & `--all-features`)
- `cargo test -p stele-negative-controls --features "controls standard-unproven" --test catalog` (8/8, 155/252 controls including `NC-0630..0634`)
- `uv run --locked --offline --script research/rfc0029-pcs/verify_recursive.py` (10/10 vectors)
- `scripts/gates/rust-policy.sh`, `scripts/gates/rfc-status.sh`, `scripts/gates/docs-links.sh`, `scripts/gates/glossary-lint.sh`, `scripts/gates/digest.sh` (4/4 pinned L0/L1 proofs unchanged)

# Soundness Audit Review — Task E19-05 (Certified mode for model sources)

- **Task:** `E19-05` (Epic `E19`, Lane C)
- **Branch:** `task/E19-05-certified-model-sources`
- **Audited Commit:** `84758dc4` (initial review on `61cdc923`, re-audit after findings resolved on `84758dc4`; base `05f565fa`)
- **Reviewer:** Independent `soundness-auditor` subagent (`92507d93`)
- **Governing Specs:** `RFC-0029` §§1.3, 2, 3, 5, 6; `RFC-0010` A9, A10, A17; `RFC-0012` A10, A20; `RFC-0027` §2
- **Tier:** Development tier (promotion to `standard` / `treaty` is a separate Workflow 10 task)
- **Verdict:** **APPROVE**

## Scope Reviewed

- `crates/stele-code/src/lib.rs`: zero-per-row-allocation `CircleCoeff::encode_into(&self, row, out)`.
- `crates/stele-pcs/src/recursive.rs`: `CertifiedPlan`, exact `#![no_std]` `BigUint` `policy3_certified_queries` and `least_q_pow2_denom`, `CertifiedSource<K>` (version `4`, layout `1`, Policy `3`, canonical round-trip `from_bytes`, zero ZK reservations), `CertifiedModelSource<K>` (`stored_codeword_bytes == 0`, streaming `recompute_queried_columns`), `ColumnFunctional::{Tensor, Dense}`, `WeightTerm::Dense`, opaque `VerifiedCertifiedSource<K>`, `CertificateLedger` (including `transcript_usage` and `non_transcript_usage`), `verify_certified_registration`, and `verify_certified_opening`.
- `crates/stele-pcs/tests/recursive.rs`: `2^33` certified query receipt parity, QM31/OM31 `L = 1, 2, 3` `Tensor` and `Dense` functional openings, streaming-memory invariant (`stored_codeword_bytes == 0`, `peak_codeword_bytes * 32 < full_codeword_bytes`), `NC-0635` (`CertificateContext`), and `CertifiedPlan` field-cap regression tests.
- `tests/negative-controls/{src/pcs_recursive.rs,src/lib.rs,catalog.md,harness/catalog.rs}` and `scripts/gates/check.py`: actual-verifier `NC-0635` registration (`156/252` executed controls; all six RFC-0029 controls `NC-0630..0635` complete).

## Initial Audit Findings & Resolution

1. **Finding 1 (BLOCKING — higher-level and non-final `PcsLevelBeta` caps in `CertifiedPlan::new`) — RESOLVED in `84758dc4`:**
   - Enforced `BigUint::fits_cap(u64::from(q_i), &cap)` for every non-final level `i + 1 < levels.len()` (including level-0 `q_open`), and `BigUint::fits_cap(2 * ell_i * (e_i + 1), &cap)` with checked multiplication for every fresh level `i >= 1`.
   - Added three regression tests in `crates/stele-pcs/tests/recursive.rs` covering higher-level proximity overflow at `T = 100`, combined overflow at `T = 120`, and pure `PcsLevelBeta`-only overflow at `T = 120`.
2. **Finding 2 (BLOCKING — registration transcript hash usage in `CertificateLedger`) — RESOLVED in `84758dc4`:**
   - Added `pub transcript_usage: HashUsage` to `CertificateLedger`, populated from `t.usage()` after `AbsorbLabel::CertificateColumns`, preserving full H-line accounting alongside `non_transcript_usage` (INV-2, `RFC-0012` A10).
   - Asserted non-zero `transcript_usage` and `non_transcript_usage` in `crates/stele-pcs/tests/recursive.rs`.
3. **Finding 3 (LOW — infallible `.to_vec()` calls in `#![no_std]` certified path) — RESOLVED in `84758dc4`:**
   - Added fallible `clone_vec<T: Copy>` backed by `reserve_vec` + `extend_from_slice` and replaced all six `.to_vec()` calls across `evaluate_functional`, `open_certified_measured`, and `verify_certified_opening`.

## Verification Gates Passed

- `cargo fmt --check`
- `cargo check -p stele-pcs --no-default-features`
- `cargo clippy -p stele-pcs --all-targets -- -D warnings`
- `cargo test -p stele-pcs --test recursive` and `--all-features --test recursive` (4/4 passed)
- `python3 -m unittest scripts/tests/test_rfc0029_policy3.py scripts/tests/test_field_source_gate.py` (21/21 passed)
- `cargo test -p stele-negative-controls --features "controls standard-unproven" --test catalog` (8/8 passed)
- `scripts/gates/digest.sh` (4/4 pinned L0/L1 proofs unchanged)
- `scripts/gates/rust-policy.sh`, `rfc-status.sh`, `docs-links.sh`, `glossary-lint.sh`

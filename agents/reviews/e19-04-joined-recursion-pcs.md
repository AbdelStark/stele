# Soundness Audit Review — Tasks E19-06 & E19-04 PCS Core (ZK Reservation & Joined Multi-Source Recursion)

- **Tasks:** `E19-06` (`80bdbeb6`) & `E19-04` PCS core (`9195aaff`), Epic `E19`, Lane C
- **Branch:** `task/E19-04-joined-recursion` (stacked on approved `E19-05` `cacc253d`)
- **Audited Commits:** `cacc253d..80bdbeb6` (`E19-06`), `80bdbeb6..9195aaff` (`E19-04` PCS core; initial review on `479d2c5d`, re-audit on `9195aaff`)
- **Reviewer:** Independent `soundness-auditor` subagent (`92507d93`)
- **Governing Specs:** `RFC-0029` §§1.3, 2, 5, 6, 7; `RFC-0010` A17; `RFC-0012` A20; `RFC-0027` §2
- **Tier:** Development tier (promotion to `standard` / `treaty` is a separate Workflow 10 task)
- **Verdict:** **APPROVE**

## Scope Reviewed

- **`E19-06` (`cacc253d..80bdbeb6`):** `accepts_zero_zk_reservation_pinned_bytes_and_rejects_nonzero` in `crates/stele-pcs/tests/recursive.rs`, pinning five BLAKE3 digests (fresh & certified version-4 source contexts, registration certificate, fresh & certified opening proofs) at `randomisers = 0, mask_rows = 0` and verifying nonzero rejection in plan constructors and wire `from_bytes` parsers.
- **`E19-04` PCS core (`80bdbeb6..9195aaff`):**
  - `crates/stele-pcs/src/recursive.rs`: `WeightTerm::{scale, pad_msb_zeros}`, `PendingLevel1Prover<K>`, opaque `PendingLevel1Verifier<K>`, `PreparedRecursive::{close_fresh_level0_at_point, close_fresh_level0_claims}` (consuming `self` by value to drop level-0 matrices and codewords immediately), `verify_fresh_level0_{at_point, claims}`, `CertifiedModelSource::close_certified_level0` (streaming column recomputation), `verify_certified_level0`, `JoinedTailPlan`, `JoinedTailLedger`, `VerifiedJoinedTail<K>`, `prove_joined_tail`, and `verify_joined_tail`.
  - `crates/stele-pcs/tests/recursive.rs`: `accepts_joined_multi_source_recursion_and_rejects_composed_tampers` covering 5 heterogeneous joined sources (`k = 5` non-power-of-two + `k = 1`, mixed batched fresh, unequal-`m_0` padded fresh, Tensor certified, padded Dense certified across 1-level & 2-level tails in QM31 & OM31), memory-drop verification, determinism, cap regressions, and non-vacuous joined negative controls (`PcsLevelGamma`-only, `NC-0630`, `NC-0631`, `NC-0632`, `NC-0633`, `NC-0634`, `NC-0635`).

## Initial Audit Findings (`479d2c5d`) & Resolution (`9195aaff`)

1. **Finding 1 (BLOCKING — `NC-0635` radius check order in `verify_certified_level0`) — RESOLVED:** Checked version/tag and `proof_radius != plan.certified_radius()` (`CertificateContext`) before `proof.len() != expected_len` (`ProofShape`), with zero transcript mutation; verified via composed wrong-radius level-0 proof test (`pr2_wrong.len() != pr2.len()`).
2. **Finding 2 (BLOCKING — non-vacuous joined `NC-0630`, `PcsLevelGamma`-only control, and non-vacuous joined `NC-0632`) — RESOLVED:** Added residual-propagating 2-block adversarial builder (`build_joined`) on one continuous transcript verifying non-vacuity baseline (`Ok`), joined `NC-0632` (`u_L[0] += 1` before `PcsLevelRoot` -> `ColumnMismatch`), joined `NC-0630` (`u1_0[3] += 1` -> `ColumnMismatch` / `ValueMismatch`), and `PcsLevelGamma`-only cancelling residuals (`+1` and `-1`, `res0 + res1 == 0` -> `ColumnMismatch` / `ValueMismatch`).
3. **Finding 3 (MEDIUM — preflight cap ordering & strong-FS tail statement binding) — RESOLVED:** Moved `prox0 <= cap && q0 <= cap` preflight checks before transcript mutation in `close_fresh_level0_claims` and `verify_fresh_level0_claims` (with zero-usage regression test); bound `(source_id, opening_id, root_1, beta, claim)` in `absorb_joined_tail_statement` and added same-transcript `# Security Invariant` docs on `prove_joined_tail` / `verify_joined_tail`.

## Verification Gates Passed

- `cargo fmt --check`
- `cargo check -p stele-pcs --no-default-features`
- `cargo clippy -p stele-pcs --all-targets -- -D warnings`
- `cargo test -p stele-pcs --test recursive` and `--all-features --test recursive` (6/6 passed)
- `python3 -m unittest scripts/tests/test_field_source_gate.py` (17/17 passed)
- `scripts/gates/digest.sh` (4/4 pinned L0/L1 proofs unchanged)
- `scripts/gates/rust-policy.sh`, `rfc-status.sh`, `docs-links.sh`, `glossary-lint.sh`

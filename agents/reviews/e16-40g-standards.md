# E16-40g independent Standards review

PR #402, lane B. Fixed base `67d7f8459761a0c15a1c16b1e2765ef36ef66595`; original head `a661cae2e53ad99a0397f8b0d84a935ca25baf9a`; final checked head `178139d119bc5d5859ab0688ab5b79df680d6cc6`. Read-only worktree; no source changes.

**Final verdict:** Standards review passes at the final checked head. The P2 below is resolved; no remaining actionable standards or maintainability finding. Mandatory merge gates remain pending.

**Original documented breach — P2, resolved: preserve the lifetime disclosure rejection.** Original `crates/stele-reductions/src/zk_gkr_bench.rs:94` returned `prove_observed` directly. Unlike `prove_lifetime` (`zk_claims.rs:3456`), it accepted a lifetime request whose source has no claims, returning no disclosure. Reproduction: retain the simple lookup fixture on source 0, add an unused two-element column on source 1, and use balanced `Lifetime { source: 1, proofs: 1, index: 0, blocks: vec![0] }` with its valid root. With proof seed `[17; 32]` and model seed `[91; 32]`, ordinary `prove_lifetime` returned `Error::Statement`; `observe_gkr` succeeded with `None` and four callbacks. Its proof verified: API acceptance parity, not a demonstrated verifier soundness failure.

Rule: task acceptance requires “retain ordinary validation” (`agents/tasks/graph.yaml:5279`); the public contract promises `prove_lifetime` semantics (`zk_gkr_bench.rs:80`). Workflow 01 requires every acceptance line to be checked.

**Resolution/evidence.** Fix `89096668fef1e46314a5c71b34a52ff5bd9b75d3` preserves the ordinary missing-disclosure postcondition. Independently passed the focused `rejects_lifetime_observation_without_disclosure` regression at final head with Rust 1.90.0, bench enabled, `CARGO_INCREMENTAL=0`, and isolated `/tmp/stele-e16-40g-standards-target`. Recompiled and reran the exact `e16-40g-unused-lifetime.rs` reproducer (retained in coordinator evidence): its old success expectation now fails with `Statement`, while the ordinary rejection assertion passes. The original two GKR tests passed independently at the original head. Final documentation accurately requires round and every folded-factor parity before compact expansion; mask coordinates are identified as original coordinates.

**Heuristics, separate from rules.** No actionable smell finding. Small adapters reuse production helpers; no abstraction-only rewrite warranted. Reviewed complete original/follow-up diffs, callers, exports, tests, specified repository rules and RFC sections. No CONTRIBUTING/CODING_STANDARDS files found. No new dependency, GPU code, challenge, binding or performance claim.

Skipped repeated fmt/clippy/no_std checks, full workspace/native/L0/L1 suites, hardware and current-main/intended-merge-tree validation as directed. Those gates remain required; this report grants no merge, GPU parity or ADR-127 GO approval.

Coordinator note: the external reproducer has SHA-256 `5786f87dce6dc025dff6f406a4f266c81cfb975f2f64dd5a5b0970f0343c9419`. The missing-disclosure case is also retained in the [committed regression](../../crates/stele-reductions/tests/gkr_bench.rs). The external-file link was normalized for this repository copy; findings are unchanged.

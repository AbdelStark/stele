# E16-10b3 standards review

Reviewer: Codex, independent lane B reviewer of lane V work.
Fixed base and verified merge base: `685258d2d7820aba20b790eebfa478bee538783f`.
Reviewed head: `7a95d79e74ca3ba995f8fa103873a2d930421df8`.
Diff: `git diff 685258d2...7a95d79e`; commits `4604549a`, `7a95d79e`.

## Disposition and findings

I approve the standards axis of this development-tier producer interface.
No documented-standard violations or discretionary smell findings. Owning lane P
review and integration gates remain separate requirements.

Read AGENTS.md, the task and dependencies, invariants, glossary, code/forbidden/
security/soundness/review-checklist guardrails, Workflows 01/03/10/12,
the soundness-auditor skill, RFC-0026 §2.3/§4/A18, RFC-0027 §5 and the
two-axis code-review skill. No CONTRIBUTING or CODING_STANDARDS file was found.
The supplied smell baseline was applied as judgement subordinate to repository
rules; tooling-enforced concerns are excluded from findings.

`Forge::column_claim`, its private plan field and mutation helper are all gated
by `controls`. The public field documents A18; the helper uses the existing
`bits_point` mapping and validates its exact mutation and restoration. Selection
rejects missing, public, weight, terminal and unequal adjacent columns; combined
mutations are refused. The helper rejects an unused selection. All `Forge`
callers were inspected: both explicit production-control literals were updated,
and default-based callers retain their old behavior. No verifier predicate,
proof container, catalog status, dependency or ordinary claim mapping changes.

I tried to break it by routing the first claim of an equal-valued adjacent witness
column under source profiles 3 and 5, and the control
`rejects_forged_column_claim_with_unchanged_sources` rejected it with exactly
`Sumcheck(RoundSumMismatch)`. Its honest/default proofs match, its unchanged
sections compare equal, and the private helper asserts one-prefix mutation and
complete restoration. Invalid and unused-selector tests also passed. The
plain checker's honest cases and identity/lookup/matmul near-miss cases passed.

The isolated interface precedes composed-control integration, as Workflow 12
requires. This review grants no NC-1308 catalog execution or other-profile credit.

## Repository checklist

- [x] Public items: `Forge::column_claim` implements RFC-0026 A18's producer selector.
- [x] Challenges/absorbs: no new draws; the ordinary batch absorbs its full descriptor before `BatchCoefficient`, round messages precede sumcheck challenges, and `BatchFinal` follows the final equation (RFC-0006 A2).
- [x] Claims/consumers: only the adversarial source-claim prefix changes; `Opening::prove` generates the genuine batch and PCS opening. The unchanged verifier derives its own points and passes the emitted claim directly to `verify_point`; roots precede claim-point challenges.
- [x] Bindings/controls: no new verifier binding; the engine test exercises the existing descriptor binding. Composed NC-1308 remains E16-10b work.
- [x] Ledger: no changed accounting lines; accounting-union gate not rerun in this targeted review.
- [x] Bound certificates: no new instances; static `Relation::validate` remains mandatory.
- [x] Padding/masks: unchanged; successor selection uses the real group-column list, excluding padding.
- [x] Determinism: existing ordered vectors and deterministic fixture; no new randomness or unordered iteration.
- [x] Parity: no backend changes; GPU parity not rerun or credited.
- [x] Cost model: no production term moves or benchmark claim.
- [x] Verifier: unchanged source and dependencies; assertions are confined to the controls-only producer helper. Default/no_std gate evidence remains integration work.
- [x] Glossary: no forbidden synonyms introduced.
- [x] Tier: development only; no security level, zero-knowledge or promotion claim.
- [x] Commit rule: no new committed or virtual columns.
- [x] Plain checker: independently ran all 27 relation tests, including honest and near-miss cases; passed.
- [x] Segments: no relation changes or cross-segment reads.
- [x] Proof bytes: default selector matches ordinary proof bytes; routed pre-opening sections remain equal. Honest pins are unchanged; the A18 adversary regenerates dependent openings.
- [x] Ladder: no independent L0/L1 run or performance comparison; mandatory ladder and current-main merge-tree evidence remain integration work.

## Checks run

- `cargo test -p stele-reductions --features controls relation::tests:: --locked --offline`: 28 passed.
- `cargo test -p stele-ir relation::tests --locked --offline`: 27 passed.
- `git diff --check 685258d2...7a95d79e`: passed.

Skipped duplicate full-workspace/native gates, ladder replay and GPU checks.
Remaining risk: owning lane P approval and passing current-main merge-tree gates are still required; no catalog execution credit follows from this review.

# E16-10b2 standards review

Reviewer: Codex, independent lane B reviewer of lane V work.
Fixed base and verified merge base: `e78345d33d7c14fabdb7848537e7004872b6cc94`.
Inspected head: `548ae5494977a7c2478afeff913dfa52df0e0254`.
Diff: `git diff e78345d3...548ae549`; commits `4cf6bd84`, `548ae549`.

## Decision

I approve RFC-0026 A18 as a development-tier amendment under Workflow 02.4.
No documented-standard violations or discretionary smell findings. This is
standards approval, not completion of the acceptance updates or integration gates.

Read AGENTS.md, invariants, glossary, all guardrails, Workflows 02/03/08/10/12,
the RFC-author and soundness-auditor skills, amendment templates, RFC-0000,
RFC-0027 §2/§5, RFC-0030 (Draft), RFC-0026 §2.3/§4/§9/A4/A18 and RFC-0006 A2.
No CONTRIBUTING or CODING_STANDARDS file was found. The supplied smell baseline
was applied as judgement subordinate to repository rules.

A18 and ADR-136 preserve the complete base text byte for byte before appending
(Workflow 02.1; forbidden rule 6). A18 contains motivation, exact replacement,
soundness, cost/encoding effects and control obligations (Workflow 02.4).
The replacement explicitly covers only source profiles 3 and 5 and preserves
the prior contract elsewhere. No production code, catalog status, verifier
predicate, ledger line, security claim or promotion changes (INV-1/2/4/13).

The isolated patch changes one selected claim's Boolean prefix, retains its
tail/value, checks equal adjacent real columns and asserts complete restoration.
Ordinary batch production and PCS opening generation remain intact. I checked
the external harness, producer diff, patch checksum, all artifact hashes and
public-input equality, plus the recorded library/CLI verdicts. The reference
checkout is pristine at `6f7182b9`. A2 absorbs the full derived point/value list
before its coefficient; the verifier still derives that list, checks all round
and final equations, then authenticates its emitted claim through PCS.
Qualification is expressly distinct from NC-1308 execution and PCS
value-authentication coverage; no benchmark credit follows (INV-4/14).

I tried to break it by running identity, lookup and matmul near-miss cases,
and the control tests `rejects_identity_tamper`, `rejects_lookup_tamper` and
`rejects_matmul_tamper` rejected it. These plain-checker cases earn no composed
control credit. All 27 relation tests passed.

The Git stack is in lane V, based on E16-10b1 after E16-10b0; it must merge
bottom-up (Workflow 12). Qualification uses the pristine reference, not that
unmerged producer interface. E16-10b depends on E16-10b2 and remains blocked on
A18. Index/ADR/catalog acceptance updates, the catalog snapshot check and final
merge-tree gates remain required; NC-1308 remains `todo`.

## Repository checklist

- [x] Public items: no new API; RFC-0026 A18 replaces only §9 NC-1308 for profiles 3/5.
- [x] Challenges/absorbs: unchanged; complete Batch descriptor precedes BatchCoefficient, Round precedes Sumcheck, BatchFinal follows the final equation (RFC-0006 A2).
- [x] Claims/consumers: unchanged; verifier-derived stacked claims feed mode 1 and its emitted point/value feed `verify_point` against the fixed source certificate.
- [x] Bindings/controls: no new binding; exact one-prefix tamper is qualified, while NC-1308 execution remains pending E16-10b.
- [x] Ledger: no changed lines; accounting-union gate not rerun in this targeted review.
- [x] Bound certificates: no new instances; static `Relation::validate` is unchanged.
- [x] Padding/masks: unchanged; the selected neighbour is real, not padding.
- [x] Determinism: no new production ordering or randomness; deterministic fixtures and exact restoration are required.
- [x] Parity: no backend change; CPU/SIMD/CUDA parity not rerun or credited.
- [x] Cost model: no term moves, benchmark numbers or performance comparison.
- [x] Verifier: no code, dependency, `no_std`, length-check or error-path change.
- [x] Glossary: no forbidden synonyms introduced.
- [x] Tier: development only; no security level, zero-knowledge or promotion claim.
- [x] Commit rule: no new committed tensor, advice or virtual column.
- [x] Plain checker: independently ran the 27 relation tests, including honest and near-miss cases; all passed. Qualification retains the honest witness.
- [x] Segments: no changed relations or cross-segment reads.
- [x] Proof bytes: production code and pins unchanged; qualification regenerates only dependent opening sections after the declared tamper. Artifact hashes match the report.
- [x] Ladder: inspected L0/T16 and L1/T64 qualification evidence for profiles 3/5; no independent ladder or performance run, ledger comparison or other-profile credit.

Check command: `CARGO_TARGET_DIR=/tmp/stele-e16-10b2-standards-target cargo test -p stele-ir relation::tests --locked --offline`.

Skipped full gates, GPU checks and proof/CLI replay; inspected the recorded qualification instead.
Remaining risk: acceptance bookkeeping and current-main merge-tree gates must complete; this review grants no catalog execution credit.

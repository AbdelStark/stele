# E16-40e standards review — PR #400, lane B

Reviewed `git diff 8a3ac05133ebefff220d640b49367ff2fb68ba59...947efb52936bdf23e3ae970e949efd915e47d8d3`;
commits `b2ff4e27`, `947efb52`.

**Hard violations: none found. Judgement calls: no actionable baseline smell.**
Standards approved at this head. The wrapper intentionally exposes private
production builders; extracting another abstraction would undermine that purpose.
Validation precedes the zipped claimed sum; existing ordering and errors survive.

Read AGENTS, invariants, glossary, code/forbidden/review-checklist/soundness
guardrails, Workflows 01/03/04/09/12, benchmark-runner, task acceptance,
RFC-0013 A5, RFC-0014 §§1/5/A1 and RFC-0026 §7. No CONTRIBUTING or
CODING_STANDARDS exists. Repository rules override baseline heuristics;
tooling-enforced style is excluded.

Independent checks, with isolated `CARGO_TARGET_DIR=/tmp/stele-e16-40e-standards-target`
and `CARGO_INCREMENTAL=0`, all `--locked --offline`:

- `cargo test -p stele-reductions --features bench --test batch_bench`: 3 passed.
- `cargo test -p stele-ir relation::tests`: 27 passed, including honest and +1 cases.
- `cargo check -p stele-reductions --no-default-features --features bench`: passed.

I tried to break it by changing one claimed value by one, and the control in
`matches_reference_batch_tables_rounds_and_finals` rejected it with
`RoundSumMismatch`; malformed sources, counts and positions returned `Statement`.

## Workflow 03 checklist

1. Public items: documented; RFC-0013 A5 item 5.
2. Challenges: supplied synthetic coefficients; transcript untouched.
3. Claims: none emitted or moved.
4. Bindings: none new; one-value control passed.
5. Accounting: unchanged; gate not rerun.
6. Bounds: no new integer identity or certificate.
7. Padding/masks: production face retained; all `w=1` weights zero, tested.
8. Determinism: ordered vectors; no concurrency change.
9. Parity: CPU tables/rounds/finals tested; no GPU credit.
10. Cost: no term moves; source/table/transfer/round/opening charges distinguished.
11. Verifier: untouched; bench-only export; no_std check passed.
12. Glossary: no forbidden synonym introduced.
13. Tier: development qualification interface; no security/promotion claim.
14. Commit rule: no committed or virtual column added.
15. Plain checker: honest and near-miss cases ran successfully.
16. Segments: unchanged.
17. Proof bytes: production algorithms unchanged; digest gate remains required.
18. Ladder: no rung or paired ledger run here.

Skipped workspace/native/parity gates and duplicate style checks. Risk: owning-lane
approval and mandatory current-main L0/L1 gates must cover the intended merge tree;
this review grants no GPU, proof-parity or GO credit.

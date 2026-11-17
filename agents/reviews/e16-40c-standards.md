# E16-40c standards review — PR #398

Independent lane B review. Base: `1cfd0fed0f8b26b63c3e70d5857302bb52523796`.
Head: `01596788c847819ee3ef64f70444547d41310348`.
Diff: `git diff 1cfd0fed0f8b26b63c3e70d5857302bb52523796...01596788c847819ee3ef64f70444547d41310348`.
Commits: `0dfb5c05`, `48d1e2bd`, `01596788`.

**Documented violations: none found. Baseline heuristics: no actionable finding.**
Standards approved at this head; this is not merge approval. The deliberate
wrapper exposes private production helpers without duplicating their algorithms.
No consumer, dependency, protocol or speculative configuration was added.

Read AGENTS, invariants/glossary, all guardrails, Workflows 01/03/09/12,
benchmark-runner, task acceptance, RFC-0008 A7, RFC-0014 §§1/4/5/A1 and RFC-0026 §7.
No CONTRIBUTING/CODING_STANDARDS file exists. Repository rules override heuristics;
tooling-enforced style is excluded.

Independently ran:

- `cargo test -p stele-reductions --features bench,std --test lookup_bench --release`: five passed.
- `cargo test -p stele-ir relation::tests --release`: 27 passed.

Inspected supplied red-first, green-final, Clippy, no_std, default and docs logs;
those logs alone do not authenticate their commands or commit provenance.

I tried to break it by selecting an absent lookup, shortening columns, supplying
selector value 2 and forcing a zero denominator, and the controls
`rejects_lookup_bench_invalid_input` and `rejects_lookup_bench_zero_denominator`
rejected it with `Statement` and `DenominatorZero`, respectively.

## Workflow 03 checklist

1. Public items: documented; RFC-0008 A7 items 2/3 and implementation notes.
2. Challenges: synthetic inputs only; no transcript change.
3. Claims: none emitted or moved.
4. Bindings: none new; multiplicity near-miss changes the root numerator.
5. Accounting: unchanged; gate not rerun.
6. Bounds: existing planner reused; no new certificate.
7. Padding/masks: production normalization preserved and tested.
8. Determinism: ordered vectors; production helpers unchanged.
9. Parity: CPU semantics tested; no SIMD/CUDA path.
10. Cost: no moved term claimed; setup/transfer/assembly charges explicit.
11. Verifier: untouched; both exports bench-gated. Constructor checks lengths after
    planning; existing planner allocation/panic limits are not independently certified.
12. Glossary: no forbidden synonym.
13. Tier: development research; no qualification/promotion claim.
14. Commit rule: no new committed/virtual column.
15. Plain checker: honest/near-miss tests passed above.
16. Segments: unchanged.
17. Proof bytes: production algorithms unchanged; digest gate remains required.
18. Ladder: no rung/paired ledger run here; current-main L0/L1 evidence remains required.

Skipped duplicate workspace/native/accounting suites and GPU runs. Risk: owning-lane
approval and mandatory gates must cover the intended merge tree; no GPU GO credit.

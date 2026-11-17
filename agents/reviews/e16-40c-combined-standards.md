# Combined production reference standards review

Independent lane B review. Base `4954247f0d67c73f2bc0badc205491bdee93f8bf`; head
`6df54c87c47162b158270980f50ace6b3d1c7d25`; three-dot diff.

**PASS: no remaining documented-standard violation or actionable heuristic smell.**
This is standards approval, not merge approval.

Read AGENTS, invariants, glossary, supplied guardrails/workflows, benchmark-runner,
both method documents and governing RFC sections. Tooling-enforced issues excluded.

The initial two-active-task packaging conflicted with `agents/guardrails/code.md`'s
“one task per PR.” The final graph resolves it: E16-40c carries both acceptance
contracts; E16-40e retains its history, blocked rather than falsely completed.
RFC-0027 §6's closure condition remains explicit. E16-35 is a transitive dependency
through E16-36. No acceptance obligation disappeared.

Workflow 12 is satisfied structurally: one lane-V interface change, owning-lane P
review required, both device consumers deferred until merge. Deliberate production
wrappers are appropriate; no duplicated algorithm or speculative hook was added.
The approximate size guideline's excess is retained review evidence.

Verified `git diff 29852a45 6df54c87 -- crates research` is empty. Independently ran
on `eec847e6`, with identical code, Rust 1.90.0, isolated assigned target directory,
`CARGO_INCREMENTAL=0`, and `--locked --offline`:

- `cargo test -p stele-reductions --features bench --test batch_bench --test lookup_bench`: eight passed.
- `cargo test -p stele-ir --lib relation::tests::`: 27 passed.
- `cargo check -p stele-reductions --no-default-features --features bench`: passed.

I tried to break it by changing one claimed value by one, and the control
`matches_reference_batch_tables_rounds_and_finals` rejected it with `RoundSumMismatch`.

Workflow 03 checklist:

1. Public items: RFC-0008 A7 items 2/3; RFC-0013 A5 item 5.
2. Challenges: synthetic arguments; transcript unchanged.
3. Claims: no protocol claim added/moved.
4. Bindings: none new; malformed/denominator controls pass.
5. Accounting: unchanged; gate deferred.
6. Bounds: existing planner/source validation reused.
7. Padding/masks: production layout retained, tested.
8. Determinism: ordered vectors; helpers unchanged.
9. Parity: CPU reference tests only; no GPU implementation.
10. Cost: no measurement claimed; host/transfer charges documented.
11. Verifier: untouched; no_std passes.
12. Glossary: no forbidden synonym introduced.
13. Tier: development research; no promotion claim.
14. Commit rule: no column added/reclassified.
15. Plain checker: honest/near-miss cases pass.
16. Segments: unchanged.
17. Proof bytes: algorithms unchanged; digest gate deferred.
18. Ladder: no rung/paired-ledger execution here.

Skipped workspace/native/L0/L1 and GPU campaigns as assigned.
Risk: mandatory gates must cover current main and the intended merge tree; no GPU GO credit.

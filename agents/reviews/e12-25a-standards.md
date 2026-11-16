# E12-25a Standards review

Reviewed PR #386 at `1651697b`, against `2358906eb5b6a455d6fbddeaf2d7ea8910d7498a`,
plus the subsequent helper rename in the working tree.
Verdict: standards approved; no outstanding findings. Integration gates remain the primary agent's responsibility.

**Hard documented-standard violations:** none found.

**Resolved heuristic:** possible Mysterious Name in `crates/stele-cli/tests/secret_ownership.py:12`:
`def reader(fifo, process):` returns an `os.O_WRONLY` descriptor, consumed as
`writer = reader(fifo, first)`. The working tree now calls it `open_fifo_writer`,
which states its purpose. No further baseline smells warrant changes.

The `main.rs` hunks retain private temporary creation, file sync, atomic rename,
directory sync and propagated errors. Both callers retain the sidecar handle
through persistence and publication. The `zk.rs` and user-documentation hunks
clarify ownership without changing the protocol. `graph.yaml` reconciles four
already-merged tasks and claims only E12-25a; no unrelated implementation enters.

I tried to break it by accessing one locked state through file and directory
aliases, and the control using real CLI processes rejected it. Each command
returned `secret state is locked` before reading an invalid commitment;
releasing ownership allowed the expected commitment-read error.

Review checklist (`agents/guardrails/review-checklist.md`):

1. Public items: existing `Persist`/`prove_next` documentation; RFC-0013 A6.5.
2. Challenges/absorb order: unchanged.
3. Emitted claims/consumers: unchanged.
4. Binding control: alias-ownership rejection above; primary process harness passed.
5. Accounting ledger: unchanged; accounting gate delegated.
6. Bound certificates: no additions.
7. Padding/masks: unchanged.
8. Determinism: no proof arithmetic or reduction-order changes.
9. CPU/SIMD/CUDA parity: no backend changes; not rerun here.
10. Cost model: no performance claim; retires concurrent mask-reuse risk.
11. Verifier: untouched; no new dependencies, panics or lengths.
12. Glossary: no forbidden synonyms introduced.
13. Tier: development; no promotion or new security claim.
14. Commit rule: columns unchanged.
15. Plain checker: unchanged; primary validation pending.
16. Segments: unchanged.
17. Proof bytes: encoding unchanged; digest gate delegated.
18. Ladder: primary L0/L1 validation pending; no benchmark comparison claimed.

Skipped duplicate full gates and tooling-enforced style checks. Copied/restored
state and live namespace mutation remain documented caller responsibilities.

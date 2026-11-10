# Workflow 01 — Implement a task (a vertical slice)
Preconditions: the task is in an epic of `program.active_epics` (or in `program.legacy_active`); all `depends` are
`done`; status `ready`; your lane has no other open change (RFC-0027 §5).
Read-only review may run in parallel. Never queue cumulative per-branch gate suites while a change awaits validation.

1. Claim: `status: in_progress`, `agent:`, `branch: task/<id>-<slug>` in `graph.yaml` (one commit, "tasks: claim <id>").
2. Read the task's `rfc` sections end to end; read the named `skill`; read `agents/context/invariants.md`.
   Know the tier you are working in (RFC-0027 §2). New capability lands in the development tier.
3. State the slice before coding, in the PR draft: which ladder rung it runs on, which scoreboard cell it moves or
   which risk of `docs/plan.md` §9 it retires, and how that will be measured.
4. Write the tests first:
   - `accepts_*` (honest prover) and the plain checker on honest values;
   - near-miss tests (output ±1, the other rounding direction) for any module change (RFC-0026 §5.2);
   - `rejects_*` controls for every binding the task adds (Workflow 08);
   - `matches_reference_*` when a reference exists (Python oracle, scalar path).
5. Implement in the crate the task names; module doc comment cites the RFC section; public items have docs.
6. If the implementation shows the RFC is wrong or incomplete → stop, run Workflow 02, mark `blocked`.
7. Keep the ladder green: L0 in the test suite always; L1 when the change touches the engine, a module or a
   commitment; the rung the task names for its acceptance.
8. Run the gates (AGENTS.md §3.7). Record a ledger for every number the PR states (Workflow 04). A change that
   alters proof bytes names the amendment that allows it and re-records the pinned digests.
9. PR using `agents/templates/pr.md`. Review as AGENTS.md §3.9.
10. Address review; merge; set `status: done`; append an ADR if a decision was taken; regenerate the scoreboard if a
    ledger changed; update `docs/cost-model.md` constants only via `stele-bench fit`.

Definition of done = every acceptance line checked by a test, a control or a ledger; the ladder green; the gates green.
A task that cannot name the cell it moves or the risk it retires is malformed: fix the task first.

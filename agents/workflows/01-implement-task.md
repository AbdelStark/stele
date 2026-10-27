# Workflow 01 — Implement a task
Preconditions: all `depends` done; task `ready`.
1. Claim: `status: in_progress`, `agent:`, `branch: task/<id>-<slug>` in `graph.yaml` (one commit, "tasks: claim <id>").
2. Read the task's `rfc` sections end to end; read the named `skill`; read `agents/context/invariants.md`.
3. Write the tests first: `accepts_*` (honest prover), `rejects_*` (controls listed in the task), `matches_reference_*` (parity).
4. Implement in the crate the task names; module doc comment cites the RFC section; public items have docs.
5. If the implementation reveals the RFC is wrong or incomplete → stop, run Workflow 02, mark `blocked`.
6. Run all gates (AGENTS.md §3.5). Record bench ledgers if the task has a performance acceptance line.
7. PR using `agents/templates/pr.md`; request `soundness-auditor` review for the crates listed in AGENTS.md §3.7.
8. Address review; merge; set `status: done`; append ADR if a decision was taken; update `docs/cost-model.md` constants only via `stele-bench fit`.
Definition of done = every acceptance line in the task checked by a test or a ledger, and the gates green.

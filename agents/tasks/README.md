# Task graph

`graph.yaml` is the single source of truth for work. A task is `ready` when every `depends` is `done`.
Agents claim the lowest-id ready task (or any ready task matching their skill), follow Workflow 01, and set
`done` only when every `acceptance` line is backed by a test, a control, or a ledger. There are no dates.
Epics are ordered by dependency, not priority; research tracks (E15) run in parallel and never block E0–E14.
Status values: `ready | in_progress | blocked(<amendment id>) | done`.

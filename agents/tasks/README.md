# Task graph

`graph.yaml` is the single source of truth for work. There are no dates.

**What to pick.** A task is pickable when its epic is in `program.active_epics` (or its id is in
`program.legacy_active`), its `status` is `ready` and every `depends` is `done`. Pick the lowest-id pickable task
**in your lane** (`lane:` field; RFC-0027 §5). One open line of work per lane: a change, or a stack that merges
in order.

**What a task is.** A vertical slice: it ends with `prove → verify` passing on the ladder and a scoreboard cell
moved or a named risk retired (Workflow 01). Set `done` only when every `acceptance` line is backed by a test, a
control or a ledger.

**Epics.** E16 stays active for development-profile work; its tasks carry no `lane:` and belong to the lane that
owns the crates they touch. E17 to E23 are the build program: E17 measurement (lane B), E18 relation IR v2 (P), E19 commitment
scheme v3 (C), E20 engine and GPU (E), E21 verifier and admission (V), E22 numerics and models (N), E23 zero
knowledge (Z). Gate tasks carry `gate: M<n>`; `program.gates` maps each gate to its task.

**Legacy epics.** E3 to E15 hold the first design's remaining tasks, with their acceptance text intact, as the
treaty backlog. RFC-0027 §6 says what supersedes, parks or resumes each. A parked or superseded task that would
otherwise be pickable has status `blocked(RFC-0027 §6 …)`.

Status values: `ready | in_progress | blocked(<amendment or RFC-0027 §6 disposition>) | done`.
Research tasks (E15 and the spikes inside E22 and E23) state a kill criterion and never block a gate unless the
gate lists them.

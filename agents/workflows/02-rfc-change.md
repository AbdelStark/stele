# Workflow 02 — Change or add an RFC
1. Never edit Accepted text in place. Add an entry to the RFC's "Amendment log" with: date-free id `A<n>`, motivation,
   exact replacement text, impact on the soundness ledger, impact on cost-model terms, affected tasks.
2. A new RFC uses `agents/templates/rfc.md`; status `Draft`; it is not referenced by code until `Accepted`.
3. Review requires: `soundness-auditor` sign-off (error terms named, theorem cited, proven/conjectural labelled), one
   `rfc-author` for consistency with the glossary and claim graph, and the owner of each affected crate.
4. On acceptance: update RFC-0000 index, `agents/context/decision-log.md` (ADR), affected tasks in `graph.yaml`, and
   `tests/negative-controls/catalog.md` (every new binding ⇒ new control id).
   After catalog changes, update its exact reservation/coverage snapshot and run
   `cargo test -p stele-negative-controls --test catalog --locked --offline` before publication.
   A reservation alone never marks a control done.

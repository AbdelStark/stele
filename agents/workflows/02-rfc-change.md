# Workflow 02 — Change or add an RFC
1. Never edit Accepted text in place. Add an entry to the RFC's "Amendment log" with: date-free id `A<n>`, motivation,
   exact replacement text, impact on the soundness ledger, impact on cost-model terms, affected tasks.
2. A new RFC uses `agents/templates/rfc.md`; status `Draft`; it is not referenced by code until `Accepted`.
3. **Full path** (anything a `standard` or `treaty` proof depends on, and every change to
   `stele-{sumcheck,gkr,lookup,pcs,hash,verifier}` semantics). Review requires: `soundness-auditor` sign-off (error
   terms named, theorem cited, proven/conjectural labelled), one `rfc-author` for consistency with the glossary and
   claim graph, and the owner of each affected lane.
4. **Development-tier path** (RFC-0027 §2). A protocol change used only by development-tier proofs is an amendment
   from `agents/templates/amendment-short.md`: motivation, exact change, a soundness note that names every new
   round and its error, the effect on cells, lookups and proof bytes, and the control ids. One reviewer from another
   lane accepts it. The amendment says "development tier" in its status line. It grants no `standard` admission;
   Workflow 10 does that, on the full path.
5. On acceptance: update RFC-0000 index, `agents/context/decision-log.md` (ADR), affected tasks in `graph.yaml`, and
   `tests/negative-controls/catalog.md` (every new binding ⇒ new control id).
   After catalog changes, update its exact reservation/coverage snapshot and run
   `cargo test -p stele-negative-controls --test catalog --locked --offline` before publication.
   A reservation alone never marks a control done.
6. A Draft RFC is direction. Code follows the Accepted text until the draft is accepted, even when the draft is
   obviously better.

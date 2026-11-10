# Workflow 12 — Lanes and integration
Lanes and their crates: RFC-0027 §5. This workflow keeps parallel work from colliding.

1. **One open change per lane, based on `main`.** No stacked changes. If your next task needs an unmerged change of
   your own lane, finish and merge that first.
2. **Interfaces move first.** The interfaces are `stele_ir::relation`, the `stele-pcs` source context and opening
   API, the `stele-kernels` backend trait, the ledger schema and the proof container. A change to one is a small
   change of its own, reviewed by the lane that owns it, merged before any work that needs it.
3. **Before you start,** read the open changes of the lanes whose interfaces you call. If one will move under you,
   wait for it or coordinate in the task.
4. **Rebase, do not merge forward.** After another lane lands, rebase and rerun the ladder rungs your change
   touches. Proof bytes that moved because of the other lane are re-recorded by the lane that moved them.
5. **The integrator** (skill `integrator`) owns: the required-CI ladder smoke, the digest gate, the scoreboard, and
   the milestone gate tasks. It may revert a change that breaks L0 on `main` without asking (INV-15), and reports
   the revert in the task.
6. **A gate task** (M1 to M7) is run by the integrator when its dependencies are done: rerun every listed rung on
   the named host class, check every acceptance line against a ledger or a control, and write the result as an ADR.
   A gate that fails names the failing line and the lane that owns it.
7. **Conflict rule.** If two lanes need incompatible changes to one interface, the question goes to an amendment
   (Workflow 02), not to whoever merges first.
8. **Fallback.** Bet B5 of `docs/plan.md` §2 states when protocol crates return to a single queue.

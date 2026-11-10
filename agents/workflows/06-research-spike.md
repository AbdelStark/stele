# Workflow 06: Research spike (RFC-0019 tracks)
1. Before starting, write in the task or the track: the question; the cost-model term, scoreboard cell or security
   property at stake; the **kill criterion** (the result that ends the spike); and the work budget (how many
   experiments or prototype steps before a report is due).
2. Prototype in `research/<track>/` (not in `crates/`), any language; results reproducible by a script.
3. Deliverable: a note `research/<track>/REPORT.md` with method, numbers (ledger if performance), soundness argument or
   counterexample, and a recommendation: *amend RFC-xxxx* / *drop* / *continue with question Qn*.
   A met kill criterion ends the spike with "drop" and triggers the fallback named in `docs/plan.md` §2.
4. Graduation = an amendment through Workflow 02. Nothing from `research/` is imported by `crates/`.
5. Fixture and frozen-digest edits are executable changes: run the affected checker entrypoints before carrying earlier proof results forward.
6. Numerics spikes follow Workflow 11 as well. Cryptography spikes state which theorem each claim rests on and mark
   anything unproven as unproven.

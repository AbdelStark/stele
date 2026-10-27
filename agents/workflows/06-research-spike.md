# Workflow 06 — Research spike (RFC-0019 tracks)
1. State the question, the cost-model term or security property at stake, and the kill criterion before starting.
2. Prototype in `research/<track>/` (not in `crates/`), any language; results reproducible by a script.
3. Deliverable: a note `research/<track>/REPORT.md` with method, numbers (ledger if performance), soundness argument or
   counterexample, and a recommendation: *amend RFC-xxxx* / *drop* / *continue with question Qn*.
4. Graduation = an RFC amendment through Workflow 02. Nothing from `research/` is imported by `crates/`.

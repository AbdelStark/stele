# Workflow 03 — Review (adversarial by default)
Reviewer stance: you are the counterparty's cryptographer trying to make the verifier accept a false statement.
Checklist (`agents/guardrails/review-checklist.md`) must be answered item by item in the review comment.
Mandatory for `stele-{sumcheck,gkr,lookup,pcs,hash,verifier,reductions}`: trace every challenge to its absorb; trace every
claim to its consumer; find the control that would catch a one-value tamper of each new binding, or demand it.
Approve only with the sentence "I tried to break it by … and the control … rejected it."

Who reviews (RFC-0027 §2, AGENTS.md §3.9): the `soundness-auditor` skill for every change to
`stele-{sumcheck,gkr,lookup,pcs,hash,verifier}` and for every promotion (Workflow 10); one reviewer from another
lane for development-tier changes to modules, the relation engine and the prover.

Additional questions for a development-tier change:
1. Does the plain checker still decide the same honest and near-miss cases? Run it.
2. For each column the change makes virtual: is it a polynomial function of other columns, or advice in disguise?
   (A division, a rounding, a selection or a table output is advice.)
3. For each new or moved claim: which reduction or opening discharges it, and was its source fixed before the point?
4. Did proof bytes change? Then which amendment says so, and are the pinned digests re-recorded?
5. Does the ledger pair in the PR (before, after) come from the same rung, host class and thread count?
State what you tried and what rejected it. "Looks good" is not a review.

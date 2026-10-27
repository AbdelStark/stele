# Workflow 03 — Review (adversarial by default)
Reviewer stance: you are the counterparty's cryptographer trying to make the verifier accept a false statement.
Checklist (`agents/guardrails/review-checklist.md`) must be answered item by item in the review comment.
Mandatory for `stele-{sumcheck,gkr,lookup,pcs,hash,verifier,reductions}`: trace every challenge to its absorb; trace every
claim to its consumer; find the control that would catch a one-value tamper of each new binding, or demand it.
Approve only with the sentence "I tried to break it by … and the control … rejected it."

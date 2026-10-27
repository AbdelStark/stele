# E3-01 delivery audit

Reviewer: codex-root, also the author; same-author benchmark-runner,
negative-control-author and soundness-auditor passes, not an independent audit.

Acceptance evidence:
- Honest/negative cases: real Rust/Python corpus gate covers 196 cases across both
  fields, degrees 0..4, dimensions 0..3, empty inputs and malformed boundaries.
- NC-0200/0201/0205/0800/0802: registered real-prover/public-verifier controls in
  both fields. One-value hooks assert exactly one changed scalar and exact error.
- SC: actual producer receipts agree with Python and verifier-owned descriptors;
  Final-label and numerator mutants fail the gate. No full profile is certified.
- Final absorption: canonical chained byte vectors, corpus and NC-0802.
- Reference: production prove reproduces accepted corpus proofs; both-field
  canonical message payloads, derived points, final claims and SC rows agree.
- Baseline: bench/ledger/e3-01-dense-sumcheck.json names the clean measured commit,
  frozen QM31 plan, CPU/toolchain, all samples, logical working table payload and
  measured process RSS. Every timed proof is verified after timing. First-sample
  variance is retained; no fit, optimization, GPU or inference performance claim.

I tried to break it by changing an unused final evaluation under constant P, and
NC-0205 rejected it with ClaimMismatch through the production public consumer.
The inventory now executes six controls, including the existing configuration-only
NC-0801; two broad catalog binding categories have proof controls. This is not a
complete claim graph or complete control coverage. Q12, PCS consumers, ZK and the
remaining task DAG still apply. Cost-model constants were not hand-edited; fitting
belongs to E9-03. No new protocol decision or amendment is introduced here.

# E3-03 complete-cost harness review

Reviewer: codex-root, also the author. Same-author soundness-auditor,
sumcheck-prover-engineer and benchmark-runner passes; not independent audit.
Scope: CPU microbenchmark harness/ledger runner, no production protocol changes.

I tried to break it by changing one unused original slice final, and the control
ClaimMismatch rejected it (NC-0209, required before measurement). The harness
always runs verify_public on warmup and measured proofs, retains every claim,
checks all SC phases, compares canonical values across strategies/samples and
compares prover/verifier continuation. Strategy choice never disables a binding.
The measured operation includes prover and complete public consumption, separately
reported. Reference and dense comparisons fix descriptor/k; skip comparisons state
that the protocol, SC loss and claim count change.

Memory accounting uses actual process peak RSS plus separate native input/proof
payloads. Scratch figures are conservative requested-payload bounds, not allocation
instrumentation. With a inputs, W=N/s, D=degree*(s-1), j=m-k:
- Dense bound covers two a*W hybrid/state buffers, three W eq/slice buffers,
  three a value vectors, three s weight vectors, both skip/tail interpolation
  buffers and three j coordinate vectors, even where lifetimes do not overlap.
- Reference bound covers eq(W), overlapping original slice/final buffers (2*a*s),
  value vectors (2*a), coordinates (4*j) and weights (2*s).
- Consumer bound covers eq(N), all claim points/values (a*s*(m+1)), coordinate,
  weight, interpolation and value buffers. Descriptor/A1 suffix capacity and all
  message framing are added; Vec/allocator headers and stack are excluded.
The reported process peak includes those excluded objects and the entire harness.

Workflow 03 checklist:
- Public items: no core API; example/runner implement A3 and RFC-0018 §1 evidence.
- Challenges/absorbs: unchanged production/reference schedules, final continuation checked.
- Claims/consumers: every measured proof is consumed by actual verify_public.
- Bindings/controls: no new binding or NC credit; full controls/accounting gates precede runs.
- Ledger: actual three-phase SC records compared independently by the runner.
- Certificates: no new integer witness identity; memory bounds are not soundness certificates.
- Padding/masks: unchanged plan obligations; synthetic public tables only, no privacy claim.
- Determinism: frozen plan/commit, fixed inputs, byte equality, every sample retained.
- Parity: both-field harness smoke checks; broader reference gates retained; no GPU change.
- Costs: c_sc/T_misc measurement path, not fitted constants; evidence requires validated ledgers.
- Verifier: core no_std unchanged; harness rejects unsupported shapes/strategies.
- Glossary: existing terms; microbenchmarks cannot certify inference or profiles.

Sign-off: approve the harness subject to actual ledger validation. E3-03 remains
in progress until the measured improvement and complete cost/memory evidence land.

# E3-03 zerocheck corpus review

Reviewer: codex-root, also the author. Same-author soundness-auditor and
sumcheck-prover-engineer passes; not independent audit. Scope: shared corpus,
CLI adapters and executable gate comparisons; no protocol code changes.

I tried to break it by generating a fresh proof over two false rows whose
residuals sum to zero, and the control RoundSumMismatch rejected it. The public
Rust verifier, not fixture expectations, makes the acceptance decision. Expected
acceptance only requests an additional prover-parity check. All 314 cases compare
against the independent Python verifier, including original claims, phased SC
records and continuation. Complete-skip descriptor changes may remain honest;
requiring rejection there would incorrectly strengthen A3's statement.

Workflow 03 checklist:
- Public items: no library API change; corpus adapters implement A3/A5 fixtures.
- Challenges/absorbs: production order unchanged; continuation uses Transcript.
- Claims/consumers: verify_public consumes every original slice; gate compares
  actual returned claims and descriptor-derived SC records.
- Bindings/controls: no new binding or NC credit; NC-0207..0209/0800/0802 retained.
- Ledger: same three SC losses; gates compare records and reject producer drift.
- Certificates: no new integer identity or bound certificate.
- Padding/masks: unchanged, plan obligations and no privacy claim.
- Determinism: seeded oracle, ordered JSON cases, proof parity for accepted cases.
- Parity: 314 shared decisions and receipts in both fields; GPU untouched.
- Costs: no c_sc/T_misc change or measurement; no benchmark claim.
- Verifier: core no_std code unchanged; example parser rejects noncanonical fields
  and out-of-range integers before passing typed values to production methods.
- Glossary: existing terms, reductions remain conditional outside public consumption.

Sign-off: approve with E3-03's larger seeded reference and cost/memory criteria
retained. This finite corpus is not a theorem, independent audit or profile certificate.

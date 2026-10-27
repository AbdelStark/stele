# E2-01 transcript integration audit

Reviewer: codex-root, also the author; PCS-engineer and soundness-auditor skill
passes, not an independent audit. This closes the integration task after E2-00
and E3-01; no protocol code or Accepted RFC changes.

Acceptance evidence:
- KATs: `crates/stele-hash/tests/fixtures/transcript.json` covers QM31 and OM31;
  `matches_reference_transcript_vectors` checks every state and challenge.
  The pinned Python transcript oracle also passes. Its framing/counting logic
  is independent; both implementations use official BLAKE3 implementations.
- Registry uniqueness: `rejects_duplicate_labels_across_every_kind` and NC-0801
  exercise the production validator. Construction validates the fixed registry.
- Distribution: `matches_reference_challenge_distribution_diagnostic` checks
  canonical limbs and fixed-input histograms in both fields. Forced-rejection,
  exhaustion and state-update tests pass. Histograms are not a uniformity proof;
  RFC-0012 A1 gives the conditional counting argument and abort rule.
- NC-0800/0802: registered real-prover/public-verifier controls pass in both
  fields. Each hook changes exactly one final scalar; an early challenge or an
  omitted preceding Final absorb is rejected with FinalEvaluationMismatch.
  NC-0801 changes one label and gets DuplicateLabel; configuration-only credit.

Review checklist:
- Public items: none added; existing transcript implements RFC-0012 A1, with
  the consuming schedule and message encodings in RFC-0006 A1.
- Challenges: public input, instance and current round precede each sumcheck
  challenge; state updates precede return. Final claims precede the next instance.
- Claims: the sumcheck final relation checks P; verify_public consumes every
  returned evaluation at the same derived point, including unused inputs.
  Future private PCS consumers remain an obligation, not evidence from this task.
- Bindings: none added; NC-0800/0802 cover the integration schedules above.
- Ledger: no lines change. Accounting validates five registered labels and
  196 actual Rust/Python corpus decisions and SC records. Q12 remains open;
  neither profile's aggregate Fiat-Shamir/hash budget is certified.
- Bound certificates and padding/masks: no integer relation, lookup, zerocheck
  or new instance is introduced by this completion record.
- Determinism: fixed byte vectors and chained protocol cases agree; no hash-map
  iteration, timing-dependent order or imported transcript state is introduced.
- Parity: CPU/reference evidence only here; no GPU code changed or parity claim.
- Costs: no term or constant moves; no benchmark is required for metadata.
- Verifier: unchanged no_std core, checked lengths and errors; no bypass added.
- Glossary: existing vocabulary retained.

I tried to break it by omitting the first instance's Final absorb before deriving
the next instance's challenge, and the control NC-0802 rejected it with
FinalEvaluationMismatch through the production public verifier.

Local validation: fmt, all-target/all-feature clippy, workspace tests, hash
all-feature tests, transcript oracle, digest, negative-controls and accounting
gates pass. Current catalog coverage remains 6/67 controls (one configuration
control), with proof controls in 2/17 broad categories; this is not complete
claim-graph coverage, zero knowledge, inference verification or independent audit.

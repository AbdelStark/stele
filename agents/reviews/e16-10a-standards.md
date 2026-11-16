# E16-10a standards review

Reviewer: Codex, independent lane B reviewer of lane V work, 2026-11-16.
Implementation reviewed: `f31aaeee7c8c07cf247e897d840e1d08eafdb527`.
Fixed base and verified merge base: `65f35281b7771c26b2a3209092345df7f45d1c04`.
Diff: `git diff 65f35281...f31aaeee`; commits `59100e66`, `2a32a72a`, `f31aaeee`.

## Decision

Standards approval. No documented-standard violations and no discretionary smell
findings. This approval does not substitute for the integrator's required gates
on the intended merge tree.

I tried to break it by replacing one canonical certificate-row limb with `p` and
adding one to the first matmul output claim, and the control NC-1303 rejected it
with `Engine(Pcs(NoncanonicalField))` and NC-1307 rejected it with
`Engine(Sumcheck(RoundSumMismatch))`, respectively. Both controls first accepted
the honest production proofs on L0, T=16 and L1, T=64, under profiles 3 and 5.

## Standards and scope checked

Read `AGENTS.md`, `agents/context/{invariants,glossary}.md`,
`agents/guardrails/{forbidden,review-checklist,soundness}.md`, workflows
01, 03, 08 and 12, and task E16-10a. Applied the code-review skill's Fowler smell
baseline as discretionary heuristics, subordinate to repository rules.

Inspected all eight changed files and the relevant existing callers, harness,
catalog execution, fixture parser, production prover, container codec, PCS parser,
matmul producer/consumer and native-gate registration. The only shared helper
change exposes `span_of` within the crate; existing behavior and fixture bytes
are preserved. E8-02f3c's completed status matches base PR #389's merge.

The new module reuses `check_proof_control`. Its cache stores genuine production
proofs or a propagated construction failure, never verification outcomes. Every
invocation verifies the honest proof again. The hook receives only a cloned
container, holds public inputs immutably, asserts a nonzero canonical-limb change,
then restores that limb and compares the entire container. Exact typed errors
are compared before formatting. The row offset is checked against the production
source parser; the matmul prefix is its production output claim.

The two direct tests are compiled through `#[cfg(test)]` library modules. The
native gate runs package tests with all features and executes catalog coverage.
The catalog also explicitly invokes both registered controls. Coverage adds two
controls and one distinct binding because width already has NC-1310; NC-1302,
NC-1306 and NC-1308 remain unregistered and `todo`.

## Review checklist

- [x] Public items: the documented control runner/module implements RFC-0026 §4,
  §9; the existing crate-local fixture accessor retains its documentation.
- [x] Challenges and absorb order: none added or changed; production paths reused.
- [x] Claims and consumers: no new claim; the changed output claim is consumed by
  the existing matmul sumcheck at its existing point.
- [x] Bindings: no new binding; NC-1303/1307 exercise existing composed checks.
- [x] Ledger: no soundness line changes; accounting gate remains the integrator's check.
- [x] Bound certificates: no new instances or changes to static validation.
- [x] Padding/masks: unchanged.
- [x] Determinism: fixed fixture/profile order; immutable cached proofs; no new randomness.
- [x] Parity: no backend change; GPU parity was not rerun by this reviewer.
- [x] Cost model: no performance claim or cost-model change; control coverage only.
- [x] Verifier: no verifier source or dependency change; harness assertions are not verifier panics.
- [x] Glossary: no forbidden synonyms introduced.
- [x] Tier: development only; no security, zero-knowledge or promotion claim.
- [x] Commit rule: no committed/virtual column change.
- [x] Plain checker: ran honest/near-miss parity test; passed.
- [x] Segments: no relation or carried-column change.
- [x] Proof bytes: production code and pins unchanged; full digest gate belongs to integration.
- [x] Ladder: targeted controls passed on both declared rungs/profiles; no benchmark comparison claimed.

## Actual checks and limitations

Read the supplied red/green logs: the registration test first failed because the
control was absent, then passed with all expected exact rejections. Independently
ran `catalog rejects_composed_message_tampers --exact --nocapture` and
`relation accepts_exactly_what_the_checker_accepts --exact --nocapture` from APFS
clones of existing test binaries in `/tmp/stele-e16-10a-standards-bins`; both passed.
The latter checks honest values and perturbations including +1 and -1. These
were prebuilt binaries, not an independent recompilation. Verified reviewed
control/crate sources still match the implementation SHA after execution.

Skipped duplicate full suites, formatting/lint checks, accounting, digest and GPU
gates while integration owns them. Remaining merge risk: their final results
must cover the intended merge tree; this review grants no broader control coverage.

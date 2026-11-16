# E8-02f0b: review of A15 erratum E1 and independent validation

Integration owner: codex-root, verifier lane. Original erratum author: claude-code.
Base: `bad479ab` (#381 merged). The earlier docs-only head `4486e2b0` is superseded.

## Findings and specification acceptance

The initial review found missing UTF-8 validation in #381. A15 §1 already requires
it; the regression failed before the fix. Merged #381 validates all eight named
lists and all column kinds, while accepting valid non-ASCII names.

Fresh reviewers then found three further differences between the reference and
independent validators:
- Unused tables with empty widths or rows passed independent validation.
- A weight with `log_len = 31` reached planning's `Unsupported`, whereas reference
  validation rejects every oversized column as `Invalid::Column`.
- Independent matmul enforcement made later columns see newly enforced operands
  immediately. The reference collects all eligible refs before enforcing any matmul
  output. The fixed-position cap makes these schedules differ: extra eligible refs
  can prevent enforcement.

E1 now specifies the eligibility snapshot, compose declaration order, permanent
column enforcement, the cap's scope, and validation-before-planning precedence.
It quotes the superseded A15/A6 sentences and leaves their original text intact.

Workflow 02 full-path spec approval, before implementation:
- `erratum_spec_review`: soundness-auditor and lane C owner; approved the static
  bounds, slice-cover argument, schedule and error precedence.
- `erratum_standards_review`: RFC-author; approved glossary, claim graph and exact
  replacements. Its test-name finding is fixed by the `matches_reference_` prefix.
- codex-root: verifier lane owner; approved the clarified validation contract.

The fresh author `erratum_replay_author` read the RFC and independent verifier only,
with no production implementation open, following ADR-128. The integration owner
wrote reference vectors and the entry-point regression; those are not claimed as
independent derivations.

## Evidence and checklist

The ten golden vectors pin reference validation and full BLAKE3 relation encodings;
the reference encoder equals the A15 test encoder on each. The new vectors cover
empty table widths/rows, snapshot acceptance and the column-domain cap. The entry
regression proves unused malformed tables are rejected before proof decoding;
a valid unused table reaches the deliberately absent proof header.

The empty-table entry regression and four independent validation regressions failed
before correction. The cover-cap case was already correctly rejected. The mutation
experiment changes only the reference cap from 16 to 17 in an isolated worktree.

I tried to break it by raising the cover cap to 17, and the control
`matches_reference_a15_erratum_validation_vectors` rejected it.

- Public items: no new API; corrected `Relation::validate` follows §3.6, A6 and A15 E1.
- Challenges: none changed; statement/source roots still precede checks and openings.
- Claims: none moved; opening sections retain claim-batch then PCS-opening order,
  and public claims retain their MLE consumer.
- Bindings: none added; existing forged-table/public controls remain applicable.
  Validation regressions test prerequisites, not a new claim-graph edge.
- Ledger: no round, probability term or theorem assumption changes. Existing static
  `B < p` bounds and A6's slice-cover argument remain the basis.
- Bounds: every column domain is capped at 30 before planning; table and cover caps
  are static. No bound depends on witness values.
- Padding/masks: unchanged; the selector text specifies the existing ref index and tail.
- Determinism: composes use declaration order; matmuls use one eligibility snapshot
  per pass. No hash-map or timing order is introduced.
- Parity: reference runtime unchanged; independent decisions are tested against the
  specified relation vectors. No GPU source changes or new GPU parity requirement.
- Cost model: no term or constant changed; no performance claim.
- Verifier: `no_std` and runtime dependencies unchanged; snapshot storage uses
  fallible reservation, and validated ids index fixed-length vectors.
- Glossary: existing relation, selector, opening and claim terminology retained.
- Tier: development only; no standard or treaty admission.
- Commit rule: no new column, source, virtual column or advice.
- Plain checker: unchanged; reference validation covers the ten honest/near-miss cases.
- Segments: no new read or carried column.
- Proof bytes: unchanged; no digest is re-recorded for an honest proof.
- Ladder: the native gate replays L0/L1 byte-5 dumps and forged windows; no new
  performance comparison or before/after ledger pair is claimed.

Spec and runtime verdict: accepted by `erratum_spec_review` (soundness-auditor,
lane C); standards cleared by `erratum_standards_review`. The runtime reviewer
independently ran all seven relation tests, the unused-empty-table entry regression
and the ten reference vectors, and confirmed snapshot allocation, index validity,
validation precedence and fixture parity. The fresh cap mutant failed at the named
assertion. The task's crate metadata now names `stele-verifier`.

Local fmt, full workspace Clippy, the full verifier suite, no-default-features check
and all 93 tooling tests passed. Full workspace/native gates and current-base CI
remain merge conditions. Merge only with a passing run covering current main and
the intended merge tree. The replay still requires a trusted relation and `cqis_id`;
ADR-131 plan/request binding remains.

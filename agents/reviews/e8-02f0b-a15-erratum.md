# E8-02f0b: independent review of A15 erratum E1

Reviewer: codex-root, soundness-auditor, verifier lane. Original author: claude-code.
Reviewed #384 at `736a63c1` against Accepted A15, production validation/planning and
the independent replay in #381. Integration base: `bad479ab` after #381 merged.

The six golden validation vectors pass, including their full BLAKE3 pins. In an
isolated worktree, raising only the fixed-position cover cap from 16 to 17 makes
`matches_a15_erratum_validation_vectors` fail: the covers-cap vector changes from
`Undisciplined(ColumnId(0))` to `Ok(())`. Production source retains the cap of 16.

I tried to break it by raising the cover cap to 17, and the control
`matches_a15_erratum_validation_vectors` rejected it.

The review also found missing UTF-8 validation in #381. A15 §1 already requires it;
the regression failed before the fix. Merged #381 now validates names in all eight
named lists and all column kinds, while accepting valid non-ASCII names. This was
a decoder bug, not new behavior authorized by this erratum.

Checklist:
- Public items: no new API; the appended replacements clarify A15 §§4–6 and A6.
- Challenges: unchanged. A15 §6.4 still fixes the statement and source roots before
  relation checks and openings; no absorb, label or draw changes.
- Claims: unchanged. Each opening section is its claim batch followed by its PCS
  opening; the opening consumes that batch's point. Public claims reach the MLE check.
- Bindings: none added. Existing forged-table/public windows remain the controls
  for their named checks; the vectors pin existing validation requirements.
- Ledger: no line or error term changes; the native gate checks the existing accounting.
- Bounds: no new bound instance. The cap is static and fails closed; table entries
  and arities retain their existing validation rules.
- Padding/masks: the selector text specifies the existing ref index and zero tail.
- Determinism: declaration order, codecs and tie-breaking are unchanged.
- Parity: no production code change. #381's exact-tree replay on Lucid H100 passed
  for L0/L1; no additional GPU change or parity requirement is introduced here.
- Cost model: no term or constant changes; no benchmark claim.
- Verifier: no code change; no new allocation, panic or length calculation.
- Glossary: existing relation, selector, opening and claim terminology is retained.
- Tier: development only; no standard or treaty admission.
- Commit rule: no column or source changes.
- Plain checker: unchanged. The golden vectors exercise its relation-validation
  prerequisite on the six specified cases, including the accepted matmul shape
  whose weight later fails range discipline.
- Segments: no new read or carried column.
- Proof bytes: unchanged; golden vectors additionally pin relation encodings.
- Ladder: this is a specification review, not a new performance measurement.

Verdict: accept E1 at the development tier. Record it in the index and ADR-132;
merge only after current-base CI passes. Model/request derivation remains separate
under ADR-131; acceptance still requires a trusted relation and `cqis_id`.

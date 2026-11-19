# Independent Soundness Auditor & Lane C Review — `E18-06a` (`stele-pcs` Owned `PreparedSource`)

- **Scope:** Workflow 12 interface prerequisite for Lane P task `E18-06` (`PreparedSource<'static, K>` owned-message constructors via `Cow<'a, [M31]>` in `crates/stele-pcs/src/preparation.rs`).
- **Reviewer:** Independent `soundness-auditor` and Lane C (PCS) reviewer (`ddbff108-230d-404e-a8ca-1b3c04a190f8`).
- **Verdict:** **APPROVE** (after resolving F1–F5).

## Findings & Resolution

1. **F1 [High — Resolved]:** Widened `dev_pattern` in `scripts/gates/check.py` to `\bfrom_code_id_development(?:_owned)?\b`, added `crates/stele-pcs/tests/preparation.rs` to `dev_allowed` (without widening `policy_two_only`), and added `from_code_id_development_owned` to `scripts/tests/test_quarantine.py`.
2. **F2 [High — Resolved]:** Updated `field_source_codec` closed surface (`prepared_surface`, `impl` list, and required test receipt) in `scripts/gates/check.py`.
3. **F3 & F4 [Medium/Low — Resolved]:** Computed `owned_message_bytes` from `checked_bytes::<M31>(values.capacity())?` before the pre-allocation overflow guard in `crates/stele-pcs/src/preparation.rs` and included it in `owned_message_bytes + bytes + refs + nodes`.
4. **F5 [Low — Resolved]:** Expanded `matches_reference_owned_prepared_source` in `crates/stele-pcs/tests/preparation.rs` to verify `message_reads()` parity, `RetainedRow` zero-read opening over `PreparedSource<'static, QM31>`, spare `Vec` capacity accounting, and `Error::MessageShape` on both owned constructors.

## Workflow 03 Approval Statement

Verified byte-identical sources, certificates, and openings between borrowed and owned preparation, preserved all 10 compile-fail boundaries and hiding/lifetime/mask invariants, and confirmed `standard_quarantine`, `field_source_codec`, `test_quarantine.py`, and `stele-pcs` tests pass.

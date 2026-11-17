# E16-40c — owning lane P spec/soundness review

Reviewed `1cfd0fed0f8b26b63c3e70d5857302bb52523796...01596788c847819ee3ef64f70444547d41310348`
(PR 398). **PASS for this interface's specification scope; no blocking finding.**
Merge remains conditional on current-base mandatory gates. The device consumer
must wait for this interface's merge (Workflow 12).

Workflow 03 checklist:

- [x] Public items: `LookupCase`, `LookupInputs`, `LookupTree` implement Accepted RFC-0008 A7 items 2/3 and implementation notes; off-by-default `bench` only.
- [x] Challenges: none added. Synthetic arguments never enter a transcript. Production keeps multiplicity-source roots, `LookupStatement`, `LookupUnits`, then β/α.
- [x] Claims: none added; reference returns precommitment material. Existing top identities and GKR/opening consumers remain unchanged.
- [x] Bindings: none added; no new NC required. Adapter malformed-input and zero-denominator controls pass.
- [ ] Ledger: no accounting/transcript changes; accounting-gate result pending, not independently rerun.
- [x] Bounds: unchanged production planning; characteristic-safe padded domain remains capped at `n ≤ 30`. No dynamic bound or multiplicity-validation claim introduced.
- [x] Padding/masks: production helpers preserve shifts, selectors, member repetition/order, zero outside members, table denominator-one padding and zero multiplicity beyond its original domain.
- [x] Determinism: unchanged ordering and arithmetic; canonical M31 values use production `element` conversion. Extension-QM31 compression passes.
- [x] Parity: no CUDA/SIMD change or parity claim; future consumer requires RFC-0014 §5.
- [x] Cost: no measured term moved. RFC-0014 A1 preparation/transfer/lifetime charges are documented; normalized witness buffers are neither free nor public metadata.
- [x] Verifier: untouched; inherited plan and assigned-length checks precede access. Supplied default/no_std logs pass.
- [x] Glossary: no new forbidden synonyms.
- [x] Tier: development qualification only; no security, acceleration or GO claim.
- [x] Commit rule: no new committed/virtual columns.
- [x] Plain checker: ran targeted lookup cases; four pass, including honest/unselected and near-miss rejection.
- [x] Segments: unchanged.
- [x] Proof bytes: production algorithms and serialization unchanged; digest execution remains pending.
- [ ] Ladder: L0/L1, workspace and native gates pending; PR 395 CI 943 is not evidence for this head.

Evidence: independently reran the five-test release adapter binary and isolated
`cargo test -p stele-ir --lib lookup`; inspected supplied red/green, Clippy,
default/no_std and docs logs. Diff whitespace and forbidden-pattern scans pass.

I tried to break it by substituting one lookup value and forcing a zero top
denominator, and the controls `rejects_lookup_tamper` (`Violation::Lookup`) and
`rejects_lookup_bench_zero_denominator` (`DenominatorZero`) rejected it.

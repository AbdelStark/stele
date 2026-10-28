# Q20 stacked statement review

Reviewer: codex-root, also the author; rfc-author, gkr-reduction-author and
soundness-auditor. Not an independent audit. Decision: retain A4 and companion
RFC-0012 A6 / RFC-0020 A2 as Draft; publish the candidate bytes and codec checks.

- Public items/RFC: research codec and Draft grammar only. No core crate imports
  them; no label, Cargo dependency or production API is added.
- Challenges/absorbs: candidate Stack precedes derived A1 Instance, ordinary rounds
  and all Final values. There is no proposed extra draw. Production registry and
  exact consumer/accounting updates remain acceptance/implementation gates.
- Claims/consumers: the consumed output/layout and every original id are bound.
  A4 explicitly frames nested A1 variables and keeps its raw receipt internal;
  only restored original points reach consumers. Source authentication is not
  inferred from descriptor bytes or matching ids; its fixed interface remains open.
- Bindings/controls: no NC credit. Actual wrong-layer/source/final-coordinate and
  continuation controls require real closed-statement consumers after acceptance.
- Ledger: proposed A1 m*delta/p^d only, delta=0 for empty P, otherwise max factors+1.
  Zero coefficients retain their conservative degree. Q12 and profile bounds remain.
- Certificates: no integer inference identity; checked shapes/counts are parsing
  rules, not field-faithfulness or CQIS certificates.
- Padding/masks: validity and selected-axis weights enter the Boolean table before
  its MLE. Shared-axis weighted evaluators need their own production evidence;
  the codec does not certify that algebra or source identity.
- Determinism: fixed byte order, explicit lengths/flags, full canonical limbs,
  no semantic term reordering or implicit tensor views. Both field widths preserve
  nonzero extension coefficients, but this is serialization evidence only.
- Parity: 48 descriptor round-trips, all truncated prefixes, malformed counts/tags
  and independent framing checks pass. No Rust/Python protocol or GPU parity claim.
- Cost model: every source/selector byte is charged in descriptor absorption;
  actual resolution, evaluation and original consumers remain additional costs.
  No measured constant, benchmark or extra weight pass changes.
- Verifier: unchanged. Research decoding checks remaining byte budgets before list
  creation; exact production resource/error admission still needs review.
- Glossary: no source-authentication token, new commitment or accepted profile.

I tried to break the candidate codec with noncanonical field limbs, unknown tags,
overlong counts and every truncated prefix; they reject as InvalidStacked.
This is research parsing evidence, not a production proof-witness control.

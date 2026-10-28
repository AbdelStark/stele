# GeLU candidate review (E5-02 / Q25)

Reviewer: codex-root, also author. Same-author cqis-numerics, rfc-author and
soundness-auditor passes, not independent audit. A2/E5-02 stay Draft/blocked.

Workflow 03 checklist:
- Public items: research definitions only under Q25/Draft A2; accepted RFC text,
  A1 and unrelated A3 remain byte-identical. No native registry admission.
- Challenges: none. Certified arithmetic does not establish lookup/FS error.
- Claims: none emitted/consumed. Eventual table/variant/index/range consumers
  remain required, and every future probabilistic reduction needs accounting.
- Bindings: altered interval/value/precision/strictness and wrong-variant
  metadata reject. These research checks do not count as native NC controls.
- Ledger: unchanged labels/losses. No new profile budget is asserted.
- Static bounds: output int16 rejection is checked over every generated entry,
  but is not proof-side range enforcement or an INV-5 bound certificate.
- Padding/masks: complete signed-int16 order, 65,536 rows, no padding.
- Determinism: rational series, root inequalities and explicit caps; no floats.
  Strict Gaussian tails prevent zero-limit substitution. Precision failure
  rejects. Series lengths and requested precisions have explicit caps.
- Parity: different pi identities, root algorithms and integral series agree on
  the full example domains. The large-tail inequality is explicitly shared.
  This is not native Rust/NumPy inference parity or CUDA parity.
- Cost: direct-table and membership costs retained; no measured constant,
  extra weight pass or new committed intermediate.
- Verifier: native no_std code unchanged. Research mutable dictionaries are not
  authenticated protocol objects. Complete registry bytes remain required.
- Glossary: existing terms. The tanh variant's rounding error is relative to
  that variant; it is not a claim of half-unit error from exact GeLU or fidelity.

I tried to break it by substituting the other variant, changing certificate
fields, using float constant-cache keys, overflowing a complete table and
rounding zero-tail limits; the control cases rejected these mutations and
retained the oracle's signed integers. The example variants differ in 108 rows.
Total normalization, canonical identities, scale alignment and native/model
evidence remain open obligations; this is approval of numerical research only.

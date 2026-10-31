# Complete row conversion capacity review in progress

Codex-root applies cqis-numerics and soundness-auditor. This is a same-author
review, not an independent audit. The [scope](../../research/cqis-bounds/ROW-CONVERSION-CAPACITY.md)
and accounting preceded tests and code. Tests first reproduced Capacity at
1025 entries. Three adapter guards now admit complete 16384-entry rows;
validation is running. This is not a completed sign-off.

- Public items: Draft RFC-0004 A3/A6/A8. Existing APIs and wire formats stay
  unchanged; only attained-magnitude and row-code capacity guards change.
- Challenges: every existing root/state absorb, label and draw order remains
  unchanged. Larger rows increase the existing dimension-dependent accounts.
- Claims: complete source/range/maximum/scale/rounding consumers remain
  mandatory. Dynamic one-hot attainment spans the entire row. Tests retain
  all 22 dynamic and 10 static parent originals, plus nested originals.
- Bindings: existing source, scale, rounding, zero, alias and compensated
  original controls rerun. New full-size proofs mutate the last actual source
  byte. Capacity rejects before malformed witness/proof processing.
- Ledger: the appended capacity account retains all 19 dynamic and nine
  static lookup identities, unsquared reductions, selection and range/A3
  terms. Exact receipts and repository accounting remain under validation.
- Bounds: all certificates remain static. N<=16384, column planes<=4 and
  two-byte carry values fit the existing 131072-byte range limit. No lookup
  has dimension above 18. Per-column integer bounds do not depend on N.
- Padding: old zero masks, signed-source padding, gap/indicator ranges and
  carry endpoints are unchanged. New geometry/witness tests include 8193 and
  16383 entries; the complete proof matrix includes ragged 65-entry rows.
- Determinism: no producer arithmetic, ordering or encoding changes. Frozen
  legacy corpus and proof hashes must match. No float or challenge retry.
- Parity: native CPU/SIMD/CUDA are unchanged. Independent integer rounding
  checks the research witnesses. Full-size reference proofs remain pending;
  no GPU parity result is claimed.
- Costs: the same linear views and complete nested reductions apply to larger
  rows, affecting c_a/c_sc/c_lu/T_misc. No benchmark, measured constant,
  additional weight pass or new committed tensor is claimed.
- Verifier: native no_std is unchanged. Expected shapes determine bounds;
  all complete child proofs remain required. Rejections at count 16385 must
  precede malformed payload handling. Python prototypes remain revealing.
- Glossary/history: scope and accounts are append-only. Accepted text and
  original task criteria remain unchanged. Head assembly, full inference
  provenance, native/private proofs, fidelity and independent audit remain.

The 40 geometry/witness cases and two full-size zero rows passed. Every
nested domain fits the existing limits at both fields; 1548288 independent
byte-column checks matched and 16385 entries rejected before malformed
payload processing. The geometry digest is frozen. Actual proof, legacy
regression, full-size and repository gate validation is still running or queued.

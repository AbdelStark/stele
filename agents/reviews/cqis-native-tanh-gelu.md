# Native tanh-GeLU review (E5-02)

Reviewer: codex-root, also author. Same-author cqis-numerics and soundness-auditor
passes; not independent audit. RFC-0021 §§2.2,3,4,6 / RFC-0004 A4.

Workflow 03 checklist:
- Public items: Table::activation now supports the distinct gelu_tanh_q descriptor.
  The Machin, root, normalizer and Gaussian helpers remain private. Exact GeLU
  remains unimplemented and cannot be substituted through this API.
- Challenges: none; existing ordinary identities and byte framing are unchanged.
- Claims/consumers: generated integer tables only. No inference, configured model,
  membership, original claim, passport, private opening or profile is admitted.
- Bindings: no new claim-graph edge or NC coverage. Entry/alias/overflow tests are
  primitive rejection checks; NC-0412/0413/0414 await their real consumers.
- Ledger: no challenge/label/loss change; the rounding error is the proved RFC
  half-output-unit bound, not a maximum inferred from tested samples.
- Bounds: exact arctangent denominators need <=8+512*(16+11) bits each; Machin
  products, comparisons and root scaling remain under the 2^18-bit cap. With
  F<=30 and normalizer precision <=264, tanh exponential denominators after
  halving are below 2^384; <=512*(384+9)+269 scratch bits suffice. Scaled output
  magnitude is <=2^29 before int16 checking. These are resource bounds, not
  field-faithfulness certificates for a future reduction.
- Padding: all 65,536 signed inputs are real rows in increasing order; there is
  no padded activation row. Actual lookup selector enforcement remains separate.
- Determinism: exact 8943/200000 coefficient, the stated Machin identity and
  alternating stopping rule, reversed subtraction/reciprocal endpoints, exact
  root inequalities and fixed 32/64/128/256 schedule. Four generation-owned
  lazy normalizers cache only exact constants; no global state or float math.
- Parity: full table bytes match independent exact Python; 10,000 varied valid
  inputs and 30 boundaries match the separate pi identity/positive exponential
  oracle. All four normalizer precisions and 10,000 NumPy gathers agree. Finite
  half-limit tails, exact zero, invalid domains and whole-table overflow are tested.
- Cost: exact generation/scratch remain T_misc. No benchmark, fitted constant,
  weight-pass change or additional committed intermediate is claimed.
- Verifier: no_std/no unsafe/no floats; every owned arithmetic buffer uses fallible
  reservation. No new Rust dependency, unchecked table constructor or external
  table-truth callback. Failed generation returns no partial object.
- Glossary: tanh-GeLU and exact GeLU retain distinct names and identities.

Tests preceded implementation. I tried to break it by closing the positive
half-limit tail, substituting exact GeLU, overflowing table outputs, changing an
entry or its field-congruent integer encoding, and selecting invalid precision
or domains, and the control checks in the native primitive tests rejected those
inputs. They earn no NC credit. Exact GeLU, function/manifest bytes, public MLEs,
lookup/private PCS/ZK and full inference remain required; E5-02 stays in progress.

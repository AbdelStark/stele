# Native public table MLE review (E5-02)

Reviewer: codex-root, also author. Same-author cqis-numerics and soundness-auditor
implementation review; not independent audit. RFC-0021 §4,§6 / RFC-0004 A4.
Completion evidence is the exact-head CI/PR gate result, including the full release
parity command below; focused tests alone do not complete this delivery.

Workflow 03 checklist:
- Public items: Table::evaluate, immutable Evaluation and the sealed TableField
  interface. Only canonical QM31/OM31 are supported; an external Field with the
  same modulus cannot implement the private seal.
- Challenges: none. The query is a mathematical input, not an authenticated
  transcript point; this primitive draws no randomness or FS challenge.
- Claims/consumers: column polynomials and a separate validity polynomial only.
  No membership, original-claim, configuration or proof acceptance follows.
- Bindings: no new claim-graph edge or NC credit. Existing table-definition
  mutation tests remain in place; real consumers must bind the point and selector.
- Ledger: no challenge/label/loss/profile line changes. Unused deterministic
  primitive arithmetic has no new SC/RLC/LU/PCS/MASK instance.
- Bounds: checked root shape has L<=65536, c<=2 and exact point dimension log2 L.
  Each recursive split preserves complete tuples and consumes the next MSB;
  maximum depth is 16. Canonical signed integer lifts use the sealed field's M31
  embedding. This is not a reduction field-faithfulness certificate.
- Padding: column interpolation includes all canonical padded entries. Validity
  separately evaluates the Boolean prefix [0,N), using its exact half recursion.
  Zero data is not treated as evidence of row validity; off-cube validity need
  not be Boolean. A future lookup must enforce its selector at the actual consumer.
- Determinism: fixed MSB order, left+r*(right-left), canonical lifts and no maps,
  data-dependent backend choice, heap allocation or mutation of borrowed inputs.
- Parity: ordinary tests cover every kind/maximum shape in QM31 and OM31, signed
  rows, malformed dimensions, non-Boolean validity and two-row high components.
  The mandatory release harness independently constructs Boolean equality weights
  and sums full tuples/validity at 10,000 full-extension points for each of 14
  configurations in each field: 280,000 total. It has no reduced-count option.
  This full command must pass before merge:
  `cargo run -p stele-cqis --example table_mle_parity --release --locked --offline`.
- Cost: O(Lc) column work, O(log L) selector work/stack, all in T_misc. No timing,
  benchmark, fitted constant, additional weight pass or commitment is claimed.
- Verifier: no_std/no unsafe/no floats, no new dependency. Evaluator scratch is
  bounded stack state. Unsupported fields fail compile-time checks, including a
  complete external Field implementation that passes its positive compile control.
- Glossary: public-table evaluation is distinct from proof/membership admission.

I tried to break it by reversing MSB significance, confusing padded zero data
with valid rows, supplying wrong point dimensions and an external field, and the
control checks in native primitive tests rejected those inputs. They earn no NC
credit. The full release parity gate is mandatory in CI. Remaining E5-02 parity
and actual lookup/private PCS/ZK/inference deliveries are not marked complete here.

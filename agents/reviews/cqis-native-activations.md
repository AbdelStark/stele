# Native sigmoid, SiLU and softcap review (E5-02)

Reviewer: codex-root, also author. Same-author cqis-numerics and soundness-auditor
passes; not independent audit. RFC-0021 §§2.2,3,4,6 / RFC-0004 A4.

Workflow 03 checklist:
- Public items: Table::activation generates all signed-int16 inputs for the three
  named functions; Error::Overflow rejects the whole result. Metadata alone still
  does not admit rows. GeLU remains a separate incomplete delivery.
- Challenges: none. Existing ordinary TableId hashing is unchanged.
- Claims/consumers: deterministic integer rows only. No configuration, membership,
  original-claim, passport or proof acceptance follows from this API.
- Bindings: no new claim-graph edge. Mutation tests are ordinary primitive checks;
  NC-0412/0413/0414 remain pending their real consumers and earn no new coverage.
- Ledger: no loss, label or profile change; soundness accounting remains unchanged.
- Bounds: softcap's exponential numerator is at most 2^46, its denominator below
  2^46, and halving leaves a denominator below 2^48. At most 512 Taylor steps
  need <=512*(48+9)+269 bits including rounding scales, below the 2^18 scratch
  cap. Scaled endpoint magnitudes are below 2^30, hence fit checked i32 rounding.
  These resource bounds are not field-faithfulness certificates for reductions.
- Padding: every activation has exactly 65,536 real rows, in signed input order.
  Other generators retain their padding rules; proof selectors remain unimplemented.
- Determinism: fixed precision schedule and exact adjacent Taylor sums. The exp
  refactor replaces machine-integer factors with exact natural factors without
  changing rational partials, stopping comparisons or outward squaring.
- Parity: three complete table byte digests, 10,000 varied valid entries per
  function and 90 additional boundary cases match independent exact Python.
  NumPy int64 gathers (10,000 per table) and 10,000 integer endpoint roundings
  match native values. Existing exp vectors and full table checks are retained.
- Cost: generation and scratch remain T_misc. No measurement, fitted constant,
  weight-pass change, committed intermediate or performance claim is introduced.
- Verifier: no_std, no unsafe or floats. All owned buffers reserve fallibly and
  failures drop the incomplete object. Inputs are borrowed or immutable; there is
  no supplied table-truth callback or unchecked constructor. No Rust dependency
  changes; the oracle uses existing pinned BLAKE3/NumPy versions.
- Glossary: primitive table generation is distinct from lookup admission/fidelity.

Tests preceded the API. I tried to break it by closing finite tails at half-integer
limits, changing a table entry or its field-congruent integer encoding, altering
identity/length, overflowing outputs, and selecting invalid entry domains, and the
control checks in native primitive tests rejected those inputs. They are not NCs.
GeLU, function/representation/manifest bytes, public MLEs and all actual
lookup/private PCS/ZK/inference deliveries remain required; E5-02 stays in progress.

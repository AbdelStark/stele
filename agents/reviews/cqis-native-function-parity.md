# Native function gather parity review (E5-02)

Reviewer: codex-root, also author. Same-author cqis-numerics and soundness-auditor
review; not independent audit. RFC-0021 §2.1-§2.3,§6 / RFC-0004 A4.

This closes two evidence gaps in the existing native generators: composite exp
functions across parameters and NumPy int64 gathers for fixed tables. It adds no
production API or arithmetic. Completion requires the exact-head PR gates.

Workflow 03 checklist:
- Public items: none. Harness-only fixtures and integration tests use the existing
  immutable Table API and complete canonical data encoding.
- Challenges: none. Python random sampling uses fixed test seeds, never transcript
  challenges or production randomness.
- Claims/consumers: none. A gathered function value is numerical test evidence;
  these tests do not authenticate configuration, prove membership or admit inference.
- Bindings/controls: no new claim-graph edge or catalog credit. Existing primitive
  mutation tests remain required; NC-0412/0413/0414 need their real consumers.
- Ledger: no new loss, label or profile line. The accounting gate remains required.
- Bounds: product components are in [0,2^E], so int64 multiplication is exact.
  Negation promotes the inclusive i32::MIN input before deriving its high/low
  indices. Rsqrt bisection thresholds are below 2^47 and use only NumPy int64.
  These are test arithmetic bounds, not reduction field-faithfulness certificates.
- Padding/masks: exp oracle data contains every descriptor-derived padded tuple,
  with increasing signed input coordinates for direct/correction. Fixed tables
  compare full canonical bytes and padding. No masks or selector enforcement added.
- Determinism: fixed seeds, ordered cases, explicit little-endian layouts, exact
  integer operations and pinned harness dependencies. No floats or timing choices.
- Parity: 32 product and 32 nearest/corrected parameter configurations; 10,000
  sampled inputs per function, including domain endpoints and split transitions.
  A positive-series reciprocal oracle supplies 192 complete component digests;
  native generation uses alternating Taylor bounds and outward dyadic squaring.
  NumPy independently performs indexing, gathering, product division and correction
  addition. A further 40,000 fixed gathers cover range_8/12/16 and rsqrt_q; every
  rsqrt entry also passes NumPy bisection of the final rounding cell. No GPU change.
- Cost: no production term or constant changed, and no benchmark claim or ledger.
- Verifier: unchanged no_std API and dependencies. NumPy and fixture allocations
  exist only in the harness; the core does not call a reference subprocess.
- Glossary: table parity is not full inference, lookup or model-fidelity admission.

The existing all-entry correction test and full-byte comparisons distinguish the
product exp function from nearest exp; a direct representation and its corrected
representation must agree exactly. I tried to break it by changing fixed-table
entries, padding and integer aliases, and the control
`rejects_changed_data_identity_shape_padding_and_integer_aliases` rejected it.
That existing primitive test remains in the required workspace run. New parity
checks include the inclusive wide endpoint, extreme scales, signed input order,
two-row high components and different splits, with exact equality throughout.

RMSNorm's native forward arithmetic and static certificates remain E5-03/E5-04,
as RFC-0021 §2.3 explicitly requires. Here the rsqrt table is completely generated
and checked; no native RMSNorm row evaluator is claimed. E5-02 also still requires
the separate full QM31/OM31 MLE gate and all predecessor gated merges.

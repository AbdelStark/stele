# Fraction primitive ledger review (E3-07a)

Reviewer: codex-root, also author. Same-author benchmark-runner and
soundness-auditor pass, not independent audit. RFC-0008 A3 / RFC-0018 §1.

Workflow 03 checklist:
- Public items: two measurement artifacts and generated report only; native code
  is unchanged from clean source commit 8798d1ac60e67d1a6580339f3951427efd82cc05.
- Challenges: original production Transcript and accepted tree/leaf order;
  full proof and continuation digests agree across all samples in each case.
- Claims: every sampled proof consumed both original pair arrays and, where
  selected products apply, original sigma and every original column. Beta=0
  retains all source obligations. This is conditional public arithmetic only.
- Bindings: existing controls and shared decision corpus ran before each field's
  measurement. No binding disabled; 20/78 catalog controls do not imply complete
  claim-graph coverage, and configuration coverage remains separate.
- Ledger: actual tree id, Gamma/Fold counts, local layer SC and leaf SC records
  checked against the fixed descriptor for all 120 measured operations. No new
  soundness loss, integer identity or bound certificate.
- Padding/masks: fixed Boolean synthetic selectors; no private lookup admission.
- Determinism/parity: both fields, scalar boundaries, ordinary/weighted trees,
  selected-product and zero-beta cases. No GPU change or CUDA parity claim.
- Cost: preparation, every internal copy/level, proving, encoding, decoding,
  actual original consumption, validation/result construction and cleanup are
  included. All three samples retained; no fitted constant or c_lu claim.
- Memory: complete native process peak, including transient copies and allocator
  retention. Named original/encoded capacities are narrower; no attributed prover,
  stack, allocator or total-host bound. Counterintuitive RSS observations retained.
- Verifier: unchanged no_std code; benchmark/ledger code does not introduce a
  production acceptance mode. Separate root-equation predicate is outside the
  measured conditional reduction operation; no full lookup identity is claimed.
- Glossary: established terms; report numbers derive only from the two ledgers.

I tried to break it by removing original claims or scoped records and understating
charged work; the benchmark admission controls rejected those mutations. Both
measurement runs validated their ledgers and preserved a clean source checkout.
Publication formatting preserves every JSON value; the report uses all samples.
E3-07a remains in progress until the required exact-head CI and gated merges finish.

# E4-02 circle encoder implementation review

Reviewer: codex-root, also the author; pcs-engineer/stele-code owner and
soundness-auditor passes. Not an independent audit. Scope: the A2 CPU encoder and
its reference/rejection tests; the large benchmark is a separate delivery gate.

I tried to break it by changing normalization, coefficient ordering, extension
inputs and selected-column order, and the control in each named direct-reference
test rejected it. These temporary mutants were restored before release/full-gate
validation. They are encoder tests, not production PCS NC credit.

- Public API: Circle::new checks log dimensions without allocating; lengths and
  code_id are derived from the checked state. encode and eval_row implement
  RFC-0010 A2, including duplicate column order and validated empty requests.
  A1's generic Code/PCS parameter registry is not implemented or admitted.
- Challenges: none added. Domain generator and all exponents are deterministic.
  Batch inversion uses nonzero base-field twiddles proved by A2, with no retry or
  challenge conditioning. The single final normalization includes all /2 factors.
- Claims/consumers: no proof or claimed evaluation is accepted. Future commitment,
  codeword-validity, proximity and original-input consumers remain mandatory.
- Bindings/controls: no new claim-graph edge. Invalid row/column/field/size requests
  reject before transform allocation; unit capacity overflow rejects. No NC status
  changes, verifier bypass, alternate field modulus or fallback map is introduced.
- Ledger: no new label, challenge, exceptional event or certified loss. The
  distance lower bound remains A2's bound, not profile or PCS certification.
- Certificates: field arithmetic only, no new CQIS integer identity. The shape
  checks precede shifts and allocations. Code identity uses the exact fixed tag
  and checked one-byte logs; the surrounding protocol must bind field encoding.
- Padding/masks: input rows have exact length. Only coefficients are zero-extended;
  output is non-systematic. No intermediate commitment, inference padding or mask.
- Determinism: reverse-paired butterflies restore quotient order; bit reversal
  converts the internal order to the canonical LSB-first basis. Twiddles remain
  M31 while values and linear combinations stay in their full element field.
- Parity: 112 direct-reference/linearity cases per M31/CM31/QM31/OM31 (448 total),
  all selected-column checks, constants, maximum dimension arithmetic and errors.
  Twelve shared Python vectors use independent integer/direct-basis evaluation;
  CI regenerates them, and Rust checks every value. The Rust extension oracle
  shares field arithmetic but no production domain/twiddle/transform code.
  Internal inverse tests cover logs 0..10. Debug and release tests pass.
- Costs: one output buffer reused for both transforms, O(N) base twiddles and
  batch-inversion scratch, with O(k log k+N log N) work. Every allocation uses
  try_reserve_exact. The input remains borrowed/resident; capacities, preparation
  and allocator/process peaks must still be measured. No throughput, memory peak
  or fitted constant is claimed here, and no weight pass is added.
- Verifier: this no_std encoder has no proof verifier. All boundary failures are
  typed; private loops use dimensions established by the checked Circle state.
  No unsafe code or floating-point arithmetic is used.
- Glossary: original claim/commitment/profile meanings retained.

Sign-off: approve this implementation for gated merge with E4-02 in progress.
Do not mark it done until the full 2^30-input-symbol benchmark runs at both rates
with all required rows, validation and cost/memory ledgers. No GPU parity result
or PCS parameter admission follows from these CPU tests.

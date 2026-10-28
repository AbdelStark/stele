# RFC-0010 A2 encoder contract review

Reviewer: codex-root, also the author; pcs-engineer/stele-code owner,
rfc-author and soundness-auditor passes. This is not an independent audit.
Scope: accept the deterministic encoder contract for gated merge. Production
implementation, independent Rust vectors and the full benchmark remain open.

I tried to break it by reversing the codeword order and omitting interpolation
normalization, and the control in the research direct-evaluation comparisons
rejected it. This describes algebraic checks only, not a production NC or PCS
acceptance test. The actual PCS controls remain uncredited.

- Public items: A2 defines a concrete Circle encoder, dimensions, code identity,
  codeword/column ordering and errors. A1's general Code/parameter registry is
  still Draft; no profile-admissible parameter object is created by A2.
- Challenges: none. Generator selection and order are fixed exact algebra, with
  no random setup, transcript draw or exceptional challenge conditioning.
- Claims/consumers: the map emits encoded values only. Original committed-input
  claims, codeword-validity tests, proximity and authentication remain with the
  actual PCS. A2 supplies no replacement acceptance predicate.
- Bindings/controls: independent expected encoding will catch basis/order/scaling
  mutations. No new PCS edge or NC credit; malformed-input tests are not soundness
  controls. The code-id bytes must be bound by future authenticated descriptors.
- Ledger: no implemented challenge or loss changes. The distance bound N-k is
  deterministic, applies to the chosen subspace, and is not a proximity theorem.
  The k=2,N=4 counterexample forbids importing an MDS N-k+1 bound. Q12 and all
  required PCS/provenance/setup accounting remain separate.
- Certificates: no new CQIS integer identity. The generator's two power identities
  prove its order, not statistical confidence. The root bound uses a nonzero
  degree-at-most-k polynomial with distinct finite parameters; it holds in M31
  extensions. The transform's injectivity has its own butterfly argument.
- Padding/masks: only coefficient zero-extension is specified; message rows must
  already have exact supported length. No implicit tensor padding, packing,
  systematic prefix, selector, mask or new cut is introduced.
- Determinism: fixed generator, odd-exponent domain order, LSB-first basis and
  exact normalization. Reverse index pairing is derived from the exponents.
  At all supported sizes required y/x divisors are nonzero; length-one is constant.
- Parity: 140 seeded complete M31 encodings agree with direct basis evaluation
  and linear combinations; 28 boundary round trips add zero/one/p-1 cases.
  No production, extension-backend or GPU parity is claimed from Python alone.
- Costs: one-time O(k log k+N log N) encoding; no per-proof weight pass added.
  No benchmark is inferred from arithmetic identities or small tests. The clarified
  2^30 criterion is total input symbols at both rates: two/four supported rows,
  each with 2^30 output symbols. Every row must run, not be extrapolated. There is
  no claim of a single oversized row. Preparation, validation and peak memory
  must appear in real ledgers.
- Verifier: unchanged; no no_std or parser change. Future field/row/column/size
  and capacity failures are explicit. Missing PCS evidence still rejects admission.
- Glossary: existing code, claim, commitment and profile boundaries retained.

Sign-off: accept A2's encoder-only contract with these limits and the linked
self-contained derivation. Keep E4-02 ready for implementation after gated merge,
not done. This does not accept A1 or any treaty/standard PCS parameter set.

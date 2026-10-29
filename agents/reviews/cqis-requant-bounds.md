# Q26 closed scalar Requant research review

Reviewer: codex-root. Same-author cqis-numerics and soundness-auditor passes;
not independent audit. E5-03 retains the complete contract/control criteria.

- RFC/public items: research-only closed A1 schema under Draft RFC-0004 A3;
  native Requant behavior and Accepted text are unchanged.
- Challenges/absorbs: none. The proposed integer equivalence is deterministic.
- Claims/consumers: no cryptographic claim emitted. Actual source/range/lookup/
  PCS consumers must enforce the modeled bindings, including shared wide digits.
- Bindings/controls: no catalog edge or NC credit. Local tests change all
  certificate fields, sign/source/value/digit relations and forbidden remainders.
  Coherent replacement columns still fail at cross-column equalities.
- Ledger: no challenge, loss or profile line changes. Standard accounting gate
  remains required on this exact head.
- Bounds: only three expected A1 parameters select the fixed schemas. Both
  column sides include carries; source and target ranges are independently
  enforced. Full int32 source aliases cannot be disambiguated by one M31 value.
  Product+p can remain in the global product range: its rejection must be the
  source/digit binding, not a claimed overflow. The initial test's expected
  reason was corrected accordingly; no acceptance condition was weakened.
- Padding/masks: no lookup/zerocheck padding changes. Column lengths are static;
  digit comparisons zero-extend only already validated result arrays.
- Determinism: fixed seed, exact integers, pinned NumPy, exact rational oracle,
  independent static column oracle and existing native Rust arithmetic example.
- Parity: 20,420 Rust/exact/NumPy decisions agree, including overflow. No GPU
  code changes or CPU/GPU proof parity claim; real certificate parity is open.
- Cost: c_a/c_lu would cover admitted limb/range work. No benchmark, fitted
  constant, commitment, cut or inference weight-pass change.
- Verifier: unchanged. The Python checker allocates and uses plaintext source
  integers; it is not a fallible no_std verifier or authenticated consumer.
- Glossary: existing bound certificate, range, column, sign and carry terms.

I tried to break it by using an int32 source with the same M31 residue and by
rebuilding all columns around a false product, and the control
`rejects_malformed_requant` rejected it with `SourceDigits` and `IntegerRelation`,
respectively. These are research rejections, not NC-0109 or a security audit of
the unfinished end-to-end prover.

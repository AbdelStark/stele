# RFC-0010 A4 native differential/gate review

Reviewer: codex-root, also the author; pcs-engineer/stele-code owner and
soundness-auditor review. Not an independent audit.

- Public items/RFC: no production API or algorithm change. A4 doctests add a
  shared external Field implementation with a positive control and sealed-trait
  rejection. The bounded example format is research-only, not protocol bytes.
- Challenges/absorbs: none added or reordered. Random inputs are deterministic
  test fixtures; setup expansion still uses the unchanged A4 BLAKE3 framing.
- Claims/consumers: full native words and query values are consumed by an exact
  byte comparison with the materialized Python map. No proof claim is accepted.
- Bindings/controls: no new proof binding or NC credit. Gate controls detect
  fixture drift, missing test/corpus execution, query reordering and field-seal
  removal. Existing native faults/capacity tests now run in the digest gate too.
- Ledger: no line changes. Existing accounting and control gates remain required;
  successful encoder checks cannot admit a PCS parameter or profile.
- Certificates: no integer relation or bound certificate added. Adapter limits
  cap research allocations before row/column decoding and native execution.
- Padding/masks: no padded row, fallback identity or masked protocol introduced.
  Corpus coordinates include duplicates, endpoints, empty and invalid queries.
- Determinism: fixed independent seeds, canonical little-endian limbs, exact bytes;
  no timing input or unordered reduction. J=3 seeds identify the same base map.
- Parity: 1000 seeded cases plus six linearity words per field, over M31/QM31/OM31,
  with complete output/query comparison. Nine digests regenerate exactly. Dense
  and base reference checks remain separate; CPU work supplies no GPU evidence.
- Cost model: no measured term or pass count changes. Test execution adds CI work;
  actual encoder operation/preparation/capacity/stack/process ledgers remain E4-08.
- Verifier: unchanged. Native no_std/Clippy/tests pass; the example uses bounded
  std I/O and canonical decoders, with errors on malformed adapter requests.
- Glossary: encoder results remain distinct from PCS parameters and admission.

I tried to break it by removing the private field seal, and the control
test_rejects_external_field_seal_removal rejected it because the complete external
CodeField implementation compiled unexpectedly. The positive Field control passed.

Reproduce: `scripts/gates/digest.sh`; mutation cases live in
`scripts/tests/test_gates.py`. Coverage and outstanding delivery requirements are
recorded in the [native corpus report](../../research/code-provenance/NATIVE.md).
E4-08 remains in progress; E4-01/A1, A3/A7, Q12 and the full MVP remain incomplete.

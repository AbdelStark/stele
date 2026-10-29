# Native closed static records review (E5-03a)

Reviewer: codex-root, also author. Same-author cqis-numerics and
soundness-auditor passes; not independent audit. Scope is RFC-0022 §§2-6.
Merge requires the accepted contract's parent and the exact-head CI gates.

Workflow 03 checklist:
- Public items: `bounds::Record::{requant,rmsnorm,as_bytes,validate_encoding}`
  and `bounds::Error` implement RFC-0022 §§2-4. Existing private checked
  Requant/Descriptor values are the separate expected-parameter authority.
  A different function rejects; no arbitrary modulus/schema or raw constructor.
- Challenges: none. Fixed seeds and the fixture checksum are test evidence.
- Claims/consumers: none emitted or admitted. Regeneration checks metadata;
  actual source, range, digit, carry, lookup, branch and output consumers remain
  required by §5. A caller still must authenticate its expected parameters.
- Bindings/controls: no new claim-graph edge, NC credit or Workflow 08 exception.
  NC-0109 remains an acceptance condition of full E5-03 under its real consumer.
- Ledger: no challenge, SC/RLC/LU/PCS/MASK/H/FS term or profile change.
  The ordinary accounting gate remains required; no new accounting line.
- Bounds: only shapes and checked CQIS parameters derive the six/eleven roles.
  The private u160 preserves all high words, rejects overflow and retains norm
  bounds beyond u128. Static caps, both zero carry boundaries and both strict
  p/2 side checks match the independent packed-polynomial oracle. Whole-value
  ranges are separate obligations; digit caps alone never establish them.
- Padding/masks: fixed zero extension of digit caps; no tensor selector or
  lookup masking is implemented or claimed by this primitive.
- Determinism: fixed scalar/role order and widths, exact integer arithmetic,
  canonical little-endian encoding, no maps or data-dependent runtime bounds.
- Parity: complete native bytes match 10000 configurations per schema plus
  seven boundary vectors. The unchanged reference corpus checksum is
  `6ebb4c66a125e60a031f6ba76aaf75e330dc21f96ac1f2509a7fa1f8352503e0`.
  Ten thousand independent 80-bit factor products and every pair of bit
  positions test full-width multiplication and rejected high bits. No GPU change.
- Cost: bounded static derivation/encoding belongs to T_misc; actual consuming
  reductions retain c_a/c_lu. No measured constant, weight pass or cut changes.
- Verifier: no_std and no unsafe code; fixed 8192-byte record, at most twenty
  columns, checked arithmetic and bounded indexing from private invariants.
  Full byte equality allocates nothing from supplied lengths. Failure returns
  no partial public record; private capacity failure preserves existing bytes.
- Glossary: record validation is not proof admission or authenticated CQIS identity.

I tried to break it by changing every representative record byte, truncating
every prefix, adding trailing bytes and field-congruent aliases, reordering roles
and substituting another valid expected configuration, and the control
`matches_reference_complete_records_and_rejects_every_changed_byte` rejected it.
These are primitive rejection tests, not catalog controls. Field endpoints,
capacity and arithmetic failures have separate native tests. The CI byte corpus
always invokes the native adapter; no option lowers the required case count.
E5-03a remains in progress until merge. Full E5-03, quantisation, inference,
lookup, private PCS/ZK, Fiat-Shamir, GPU parity and fidelity remain unfinished.

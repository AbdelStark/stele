# Component table identity review (E5-02 / Q25)

Reviewer: codex-root, also author. Same-author cqis-numerics, rfc-author and
soundness-auditor passes, not independent audit. A2 remains Draft.

Workflow 03 checklist:
- Public items: research candidate for RFC-0004 A2/RFC-0008 §4. Accepted text,
  A1 and unrelated A3 unchanged. No native registry or composition admitted.
- Challenges: none. Identity/data hashes are ordinary BLAKE3, not FS challenge
  derivation. No transcript label, random error term or profile loss waived.
- Claims: no native claims emitted. Complete data is checked against regenerated
  definitions. Passport, selector and original tuple consumers remain required.
- Bindings: one-field id/length/shape/entry/padding tampering, row reordering,
  alternate field-congruent integer bytes and unknown schemas reject. These are
  research checks, not NC-0404/0405/0701 consumer credit.
- Ledger: no new labels/error lines; no claim of a complete H/FS budget.
- Bounds: shape/allocation limits derive from validated definitions. Component
  coordinates fit below p/2, but larger operation relations need their own
  static certificates. Claimed row counts are never allocation authority.
- Padding: zero rows and exact padded length checked. Actual selector/membership
  exclusion remains a separate mandatory lookup/plan relation.
- Determinism: fixed field widths, exact signed integers, explicit names/versions,
  ordered rows, no JSON authority. Overflow rejects the whole table; a descriptor
  alone is not a successful generation/admission certificate.
- Parity: independent byte assembly and fixed digests. Numerical generators
  retain their own oracle checks. No native MLE/Rust/NumPy/CUDA parity claim.
- Cost: O(Lc) generation/validation/storage retained. No measured constant,
  commitment, weight pass or benchmark changed.
- Verifier: native no_std verifier unchanged. Decoder uses expected sizes and
  exact lengths before parsing rows; complete passport commitments remain open.
- Glossary: component identity, research data digest and passport commitment
  have explicitly different roles. Large exp products are compositions, not
  oversized registered tables. No new unsupported-name fallback.

I tried to break it by preserving an honest identity while changing an entry,
padding row, row order or field-congruent integer encoding, and the control
cases rejected each. The shape check rejects giant declared dimensions before
row parsing. This approves component research only, not complete A2 admission.

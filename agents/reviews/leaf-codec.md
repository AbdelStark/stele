# Selected-product codec review (E3-07a)

Reviewer: codex-root, also author. Same-author soundness-auditor and
GKR-reduction-author passes, not independent audit. RFC-0008 A3 / RFC-0020 A4.

Workflow 03 checklist:
- Public items: borrowed immutable LeafDescriptor, checked exact size and A1 codecs.
  Sources are nonempty, ordered distinct u64 ids >=2; Eq/selector ids stay reserved.
- Challenges/absorbs: none added. Leaf registration waits for the actual engine.
- Claims/consumers: decoding returns an unverified A1 object, no acceptance receipt.
- Bindings/controls: no new protocol binding or NC credit. NC-0409/0410 remain todo.
- Ledger/certificates: no random loss or integer identity. Dimensions come from
  the validated tree and original ids; the complete A1 count must fit u32.
- Padding/masks: every final is preserved, including zero-coefficient columns;
  Boolean selector and actual source consumers remain engine requirements.
- Determinism/parity: twelve actual Python proofs compare exact native decoded
  fields and bytes in QM31/OM31, including scalar cases and beta=0 unused columns.
- Cost: no source-domain materialization or descriptor copy. O(m+c) payload space;
  identity validation uses pairwise duplicate checks. No measured constant,
  c_lu, weight-pass or complete pipeline-memory claim; ledgers remain required.
- Verifier: no_std; exact length before allocation, canonical limbs, checked
  capacity. Maximum depth, all truncations/limb positions and wrong shapes tested.
- Glossary: existing descriptor, source, selector, field, claim and reduction terms.

I tried to break it by truncating every byte length, corrupting every limb position,
adding a trailing byte and repeating a source id; the both-field leaf codec tests
rejected these at ProofShape, NoncanonicalField and InvalidDescriptor. The gate
also rejects divergence from independently regenerated Python fixture records.
E3-07a remains in progress with the selected-product engine, real consumers,
transcript controls, expanded decision corpus and primitive ledgers still due.

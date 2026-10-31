# Signed attention output review in progress

Codex-root applies cqis-numerics, gkr-reduction-author and soundness-auditor.
This is a same-author review, not an independent audit. The
[scope](../../research/cqis-bounds/ATTENTION-SIGNED-OUTPUT.md) preceded tests
and implementation. Tests first rejected the missing module; corpus and
proof suites are running. This is not a completed sign-off.

- Public items: Draft RFC-0004 A3/A6 and RFC-0009 A2. Complete int16 source
  proofs reuse the actual q magnitude root. A Boolean input-sign range and
  one degree-two A3 bind the output sign, conditional on source provenance.
- Challenges: child transcripts remain unchanged. Full schema, roles,
  field/repetition bytes, all external roots and verified child states precede
  the parent. It draws a per ZeroWeight/Sumcheck label; no new label or A1.
- Claims: actual q, input sign and canonical output sign retain their emitted
  original-point consumers, even at q=0. All sixteen signed-source originals
  and every inherited range/lookup claim remain mandatory.
- Bindings: controls target all roots, fresh wrong signs, pinned q, metadata,
  zero-hidden and compensated originals. Boundary controls cover +32768,
  q=32769, Boolean caps, padding and high planes. Both actual canonical sign
  branches must compose through the same magnitude, numerator and division.
- Ledger: four independent lookup identities retain repeated identities and
  unsquared reductions. Full range/A3 is 55a+35, including parent3a. Full
  nonlookup draws are 23a+14 per label. Exact runtime receipts and the
  repository accounting gate remain under validation.
- Bounds: complete signed-source magnitude is <=32768 and both signs are
  Boolean. Each side of q*b=q*s is <=32768<p/2. Both verified magnitude
  byte planes supply q; no observed value chooses the bound.
- Padding: the sign range fixes padded flags to zero. Signed-source ranges
  retain both raw/magnitude planes and canonical output-sign padding. No
  output branch or original consumer is omitted when the magnitude is zero.
- Determinism: fixed child order, expected dimensions, disjoint namespaces
  and canonical byte order. No float, retry or witness-selected configuration.
  Independent NumPy outputs, byte roots and carries are under validation.
- Parity: native CPU/SIMD/CUDA are unchanged. Capacity cases cover ragged
  8193 and full 16384 channels. Both fields and repetition counts must match
  exact accounts, followed by the complete full-channel proof.
- Costs: a Boolean range and one O(N) sign relation add c_a/c_sc/c_lu/T_misc
  work to the complete int16 source consumer. No benchmark, fitted constant,
  new cut, larger capacity or additional weight pass is claimed.
- Verifier: native no_std is unchanged. Expected metadata fixes lengths;
  exact proof keys and canonical parent fields are checked. Actual byte views
  and complete proofs authorize acceptance, not plaintext sign arithmetic.
- Glossary/history: Draft/accounting additions are append-only. Original
  task criteria stay blocked. Full source/key/block/model ownership, global
  base/offset aggregation, configured conversion, native/private inference,
  fidelity and independent review remain required.

The observed-attack conclusion is pending actual controls. Full proof and
required repository gates must also complete.

The independent corpus passed all 10000 cases and two capacity cases. Its
observed digest and counts are now asserted by the checker. A metadata replay
was rejected earlier than the initial test expected, at RoundSumMismatch;
the diagnostic expectation was corrected without changing verification.
The original corpus result is retained, and the corrected proof suite runs
separately. Full proof and repository gates remain pending.

Primary and boundary controls passed. I tried to break it by attaching a
positive input sign to a valid signed-source proof of -32768, and the control
SignedOutput:RoundSumMismatch rejected it. The -32768 and negative-input-zero
cases accepted; all three zero-hidden originals and compensated signs
rejected at ClaimMismatch. Complete source compositions, matrix, full proof
and repository gates remain pending.

Both actual source-chain compositions and all 16 matrix proofs subsequently
passed. Valid replacement sources rejected, and every receipt, draw total
and original count matched. The observed matrix digest is frozen; the
corrected proof runner completed successfully. The full-width proof,
repository gates and independent audit remain required.

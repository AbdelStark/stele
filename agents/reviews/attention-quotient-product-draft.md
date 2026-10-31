# Attention quotient product review in progress

Codex-root applies cqis-numerics, gkr-reduction-author and soundness-auditor.
This same-author review is not an independent audit. The
[scope](../../research/cqis-bounds/ATTENTION-QUOTIENT-PRODUCT.md) preceded tests
and implementation. Tests first rejected the missing module; the independent
corpus and proof suites are running. This is not a completed sign-off.

- Public items: Draft RFC-0004 A3/A6 and RFC-0009 A2. Expected normalization
  metadata fixes q<=32768, D<=Dmax and Qp=q*D. q retains two external byte
  planes; the scalar denominator and product retain sixteen.
- Challenges: complete child transcripts remain unchanged. Full schema,
  roles, field/repetition bytes, all external/internal roots and verified
  child states precede the parent A3. It draws a+4 per ZeroWeight/Sumcheck
  label, with no new label or A1.
- Claims: seven actual originals consume q low/high bytes, current/previous
  denominator bytes, carry-in, product and carry-out at their emitted points.
  All inherited range, lookup and packing consumers remain mandatory.
- Bindings: controls target every root, fresh false child values, both carry
  bytes, all seven originals including zero factors, genuine ranged Qp-p,
  whole caps, padding, endpoints and high external planes. Actual positive
  denominators must compose and reject valid source replacements. q remains
  a bounded witness until strict division consumes the same roots.
- Ledger: 6+G independent lookup identities retain repeated identities and
  unsquared reductions. Exact range/A3 and draw formulas appear in the scope
  and ledger, including degree-two parent loss 3(a+4). Runtime receipts and
  the repository accounting gate remain under validation.
- Bounds: q, D and product bounds are static. Complete carries are <=510;
  both verified bytes reconstruct each carry. Independent column sides are
  <=130815<p/2. Final carry is zero and product capacity is below 2^128.
- Padding: G=2 children have N/2 caps with explicit zeros on unused entries.
  Product joins are plane-major; scalar D broadcasts to all channels while
  padded q is zero. Carry padding and final entries have zero caps; the
  initial carry is the expected zero. No unused word escapes its range.
- Determinism: fixed expected child order, namespaces and byte order. No
  float, retry or witness-selected configuration. Independent NumPy integer
  multiplication, byte roots and carries remain under validation.
- Parity: native CPU/SIMD/CUDA are unchanged. Capacity cases include ragged
  8193 and full 16384 channels. Full proofs cover maximum G=2 products and
  G=1 with nonzero high carry bytes, retaining exact receipts and consumers.
- Costs: complete ranges, seven byte views and degree-two A3 contribute to
  c_a/c_sc/c_lu/T_misc. Every child respects existing capacity. No benchmark,
  fitted constant, new cut or additional weight pass is claimed.
- Verifier: native no_std is unchanged. Expected metadata fixes lengths;
  strict keys and canonical field values are checked. Admission uses complete
  byte-column proofs, not plaintext whole-product multiplication.
- Glossary/history: Draft/accounting entries are append-only. Original task
  statuses and criteria remain blocked. Strict remainder, signed output,
  configured conversion, complete ownership, native/private inference,
  fidelity and independent review remain required.

The observed-attack conclusion is pending actual control results. All full
proofs and required repository gates must also complete.

The primary controls passed. I tried to break it by changing a carry high
byte through a separately valid complete range proof, and the control
Product:RoundSumMismatch rejected it. All seven original-final attacks also
rejected at Product:ClaimMismatch, including both factors hidden by zeros.
Other proof suites, the corpus, full proofs and repository gates remain open.

Boundary controls subsequently passed. Whole caps, padded entries, terminal
carries, full external byte planes and the genuine ranged Qp-p alias retain
their consumers. A forged initial carry with a compensating product byte
rejected at Product:ClaimMismatch. Source compositions, corpus, matrix, full
proofs and repository gates remain pending.

The independent corpus and both actual positive-denominator compositions
subsequently passed. All 10000 cases and four ragged/full capacity cases
retain complete byte roots and carries, including 144695 carries above 255.
The corpus digest is frozen in the scope. Matrix, full proofs and repository
gates remain pending.

The complete 16-proof field/repetition matrix subsequently passed. Exact
receipts, draws and all seven parent originals matched, and the digest is
frozen. Both full-width proofs, repository gates and independent review
remain pending; the original successful runner was not restarted.

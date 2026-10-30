# RMSNorm decomposition — same-author review

Codex-root applies cqis-numerics, gkr-reduction-author, rfc-author and
soundness-auditor. This is not independent audit. [Evidence](../../research/cqis-bounds/NORM-SUM.md).

- Public items: RFC-0021 §2.3 A=MD+R and RFC-0022 §2.3 normal_sum under
  Draft RFC-0004 A3. This isolated equality cannot establish strict R<D.
- Challenges: parent draws none. Complete expected norm bytes, five roots and
  the verified child state seed its final state. All inherited range, packing,
  product rho and row/two-plane A1 challenge/final framing remain unchanged.
- Claims: actual left source planes reconstruct both full MD/R roots; every
  right plane equals the exact unit view. Actual sum output reconstructs full
  external A. All original source and power claims use their actual emitted
  points and full consumers. No sum recomputation substitutes for the proof.
- Bindings: source substitutions, dropped unit factors, high external slots,
  field aliases and malformed shape controls passed. A genuine altered MD/R
  sum under the same A fails its pinned MD root. Actual paired A and MD proof
  roots compose successfully. All8 extra width-boundary proofs/controls passed.
- Ledger: A3 numerator9b+18g+42, three lookup dimensions b+3,g+3,g+3,
  separate product identity C-1 and A1 loss2+4b. Nonlookup draws18+4b+8g
  ZeroWeight and20+6b+8g Sumcheck. Exact assertions cover all proof cases;
  all24 main/width proofs passed. Accounting and required local gates passed;
  no production profile is certified.
- Bounds: complete expected norm parameters derive the closed role and widths.
  Actual whole bounds and integer product/carry acceptance establish the sum;
  each left operand's MDmax cap does not replace the subsequent strict bound.
- Padding: full8/16/32-slot MD,16-slot R and16/32-slot A roots survive both
  extension and excess-zero checks. Internal output slots and carry endpoints
  stay bound. A shorter external A cannot silently discard internal high bytes.
- Determinism: canonical complete norm bytes and fixed plane/side/invocation
  order; exact integer operations. Independent NumPy sums/convolutions passed
  10000 cases. No hash-map traversal, floating point or timing-dependent order.
- Parity: native CPU/SIMD/CUDA unchanged. Full revealing field/repetition and
  width matrices passed; no native/private inference credit.
- Costs: O(B) source/zero-extension views plus all inherited c_a/c_sc/c_lu/
  T_misc work. No measured constant, benchmark claim or additional weight pass.
- Verifier: native no_std unchanged. Expected metadata and bounded shapes
  precede source reconstruction; malformed field/length inputs reject. One
  test expected SourceShape instead of the actual OpeningShape; only that
  expectation was corrected. The verifier already rejected, and is unchanged.
- Glossary/history: append-only Draft/accounting evidence; original blocked
  acceptance criteria retained. No Accepted role, public-MLE kind, native NC/cut.

I tried to break it by composing a genuinely valid altered-MD sum with the
same A under the actual upstream MD root, and the control
Product:CommitmentMismatch rejected it.

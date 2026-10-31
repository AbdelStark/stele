# Strict attention division review in progress

Codex-root applies cqis-numerics, gkr-reduction-author and soundness-auditor.
This is a same-author review, not an independent audit. The
[scope](../../research/cqis-bounds/ATTENTION-DIVISION.md) preceded tests and
implementation. Tests first rejected the missing module. Corpus and complete
proof suites are running; this is not a completed sign-off.

- Public items: Draft RFC-0004 A3/A6 and RFC-0009 A2. Three complete children
  share one expected denominator root. Equality and strict remainder bind
  the rounded quotient magnitude; signed output remains separate.
- Challenges: complete child transcripts remain unchanged. Full schema,
  roles, field/repetition bytes, all roots and verified child states precede
  both parent A3s. They draw 2(a+4) per ZeroWeight/Sumcheck label. No new
  label or A1 is introduced; the doubled child's A1 remains accounted.
- Claims: equality consumes Qp, R, carry-in, W and carry-out; strict remainder
  consumes R, gap, carry-in, masked D2 and carry-out at the emitted points.
  Every inherited source/public claim retains its actual consumer.
- Bindings: controls target all roots, fresh false range values, all ten
  compensated finals and complete child substitutions. Boundary controls
  include ranged R=2D, R+p, zero D, a forged strict initial zero, padding,
  whole caps and terminal carries. Actual upstream source proofs must compose.
- Ledger: add 2G independent remainder/gap lookup identities and eight carry
  identities, retaining repeated identities and unsquared reductions. The
  scope's new range/A3 and draw formulas include parent4(a+4). All three
  inherited accounts remain unchanged, including the doubled child's K-1
  identity and 4b reduction. Runtime receipts and accounting gate are pending.
- Bounds: whole bounds are static and below 2^128. Complete equality and
  strict carries are <=2 and <=1; their independent sides are <=767 and
  <=511 respectively. Zero final carries exclude overflow. The strict
  relation implies positive D without a plaintext verifier comparison.
- Padding: fixed G=2 halves include explicit zero caps. All scalar and
  channel roots retain their full byte widths. Strict initial one and D2
  broadcast are masked to real channels; padded and final carries are zero.
- Determinism: fixed expected child order, namespaces and byte layout. No
  float, retry or witness-selected plan. Independent NumPy integer division,
  remainder endpoints, byte roots and carries remain under validation.
- Parity: native CPU/SIMD/CUDA are unchanged. Capacity checks cover 8193 and
  16384 channels. Both fields and repetition counts must match exact receipts;
  full proofs cover G=2 at Dmax=2^64 and G=1 with q=32768.
- Costs: two byte-column A3s and complete remainder/gap/carry ranges add
  c_a/c_sc/c_lu/T_misc work. Existing child proofs supply W/Qp/D2 ranges.
  No benchmark, fitted constant, new cut or extra weight pass is claimed.
- Verifier: native no_std is unchanged. Expected metadata fixes lengths;
  strict keys and canonical fields are checked. Complete proofs and actual
  byte views authorize acceptance; whole plaintext division does not.
- Glossary/history: Draft/accounting additions are append-only. Original
  statuses and criteria remain blocked. Actual source/model/key ownership,
  global attainment, signed/configured output, native/private inference,
  fidelity and independent review remain required.

The observed-attack conclusion remains pending actual controls. Full proofs
and every required repository gate must also complete.

Focused source-view controls passed. I tried to break it by replacing the
quotient product with a separately valid changed-D proof while q=0 preserved
the product, and QuotientProduct:Denominator:CommitmentMismatch rejected it.
The bias-source substitution, metadata replay, remainder high plane and
unmasked D2 broadcast also rejected. The original complete suite continues;
these focused results do not establish the remaining controls or full proofs.

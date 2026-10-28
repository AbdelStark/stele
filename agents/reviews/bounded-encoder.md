# Q23 bounded encoder execution review

Reviewer: codex-root, also the author; pcs-engineer, rfc-author, soundness-auditor.
Not an independent audit. Decision: continue Draft A1 with the bounded traversal;
no native implementation, PCS parameters or measured resource claim is approved.

- Public items/RFC: bounded.py proposes A1 execution for the exact seeded v2 map.
  The pure requirements calculation describes requested vector payloads, not RSS.
- Challenges/absorbs: no new transcript draw, label or frame. Setup blocks retain
  every canonical coordinate; changing traversal does not change their contents.
- Claims/consumers: complete codewords match the existing materialized map. Query
  values select those exact coordinates. No commitment/source/PCS consumer is added.
- Bindings/controls: malformed inputs fail before allocation. Forced outer/inner A
  and late B exhaustion rejects SamplingExhausted with input preserved. All-zero
  inputs still generate every graph row. Research tests earn no production NC ids.
- Ledger: no soundness line changes. Code, setup event and conditional proximity
  remain as previously specified; accounting must retain the same production state.
- Certificates: n/S/E/R and payload/counter bounds depend only on the fixed code,
  field, query length and target width. No dynamic integer-identity certificate.
- Padding/masks: exact lengths and canonical limbs; no padding, fallback or removal
  of zero coefficients. Query duplicates retain their original order.
- Determinism: row order is explicit, block identities unchanged and each block is
  used once. Sampler sorting remains the existing deterministic neighbor order.
- Parity: J=3/4/5 across M31/QM31/OM31 matches full materialized words, counts,
  linearity and queries. Dense/base evidence is inherited from that separate
  reference study. No native CPU/GPU digest, large-size execution or RSS measurement.
- Cost model: no graph/raw-byte storage on the candidate encoding path; sparse
  work stays d*E(J) plus base, and every call pays capped row generation. Requested
  vector, input and query overlap formulas are explicit. Hash/stack, actual capacity,
  allocator and process overhead need native evidence; no measured constant moved.
- Verifier: unchanged. The native proposal uses sealed approved fields, checked
  size conversion/fallible allocation and u64 work counters. A 32-bit address
  limit must not be applied to operation counts. Native no_std/error/API checks
  remain required before production delivery; Python is not an allocation proof.
- Glossary: code identity, distance, setup, query and profile authority remain
  distinct; code catalog proven flags are unchanged and false.

I tried to break it by exhausting the coefficient stream in the final B row, and
the control check_bounded rejected it with SamplingExhausted. No partial output
was returned and the original row was unchanged. This is a research execution
check, not a production binding control or evidence of full inference soundness.

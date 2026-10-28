# Q23 recursive encoder review

Reviewer: codex-root, also the author; pcs-engineer, rfc-author and soundness-auditor.
Not an independent audit. Decision: publish candidate map/base/bytes and research
checks; retain RFC-0010 A1 as Draft, E4-01 blocked.

- Public items/RFC: research-only recursive map under formal/recursive-code.md.
  No core import, accepted parameter registry or PCS/profile admission.
- Challenges/absorbs: no protocol transcript change. Seeded research fixtures are
  not setup randomness evidence; complete future setup binding remains required.
- Claims/consumers: encoding and column selection only. No polynomial opening,
  committed-source consumer, private input or inference acceptance is supplied.
- Bindings/controls: no NC credit. Malformed descriptors reject, but structurally
  valid zero edges deliberately encode a distance-one map and prove no certificate.
- Ledger: no production loss line changes. The existing ensemble bound and Q12
  remain conditional/unresolved for actual setup/grinding/reuse and PCS composition.
- Certificates: the accepted circle root bound closes the base-distance hypothesis;
  it does not certify outer matrices. No integer inference identity is introduced.
- Padding/masks: only exact supported lengths; no implicit padding, arbitrary base,
  duplicate-edge merging, zero-edge deletion or semantic normalization.
- Determinism: exact level/A/B/row/neighbor order, canonical M31 coefficients and
  fixed circle basis. The base is explicitly non-systematic, outer maps systematic.
- Parity: nine field/size cases compare FFT-based recursion with independent dense
  matrices; full-K linearity and ordered duplicate queries pass. No Rust/GPU parity
  or maximum-size recursive evidence. The underlying field arithmetic is shared.
- Cost model: exact sparse edge-operation formula plus separate base transforms,
  setup bytes, allocation and live copies. No measured constant or benchmark claim.
- Verifier: production unchanged. Research decoder checks complete derived byte
  count before graph allocation; production resource/errors/admission remain open.
- Glossary: a parsed map is not a certified code instance or `proven` profile entry.

I tried to break the inference from valid setup to good distance with all-zero
coefficients. The parser and encoder correctly accept that map, and its systematic
unit word has weight one. A future actual consumer must reject unsupported distance
provenance; this encoder study supplies no waiver.

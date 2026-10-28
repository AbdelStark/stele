# RFC-0010 A4 native encoder contract review

Reviewer: codex-root, also the author; pcs-engineer/stele-code owner, rfc-author
and soundness-auditor passes. Not an independent audit. Decision: accept the
encoder implementation contract for gated merge; E4-08 remains undelivered.
A1/A3/A7 and full E4-01/PCS/profile requirements remain open and unchanged.

- Public items/RFC: native-code.md fixes Encoder, EncoderInfo, sealed Code/CodeField,
  exact factory IDs, deterministic v2 map and native errors. Existing Circle APIs
  remain compatible. No ProximityParams or registry parser is authorized by A4.
- Challenges/absorbs: no new challenge or label. The exact fixed block namespace
  is setup expansion only; production FS still exclusively uses Transcript.
- Claims/consumers: codewords and coordinate selections only. Actual authenticated
  source/plan/passport/PCS consumers remain mandatory. Rust types are arithmetic
  choices, not evidence of the public field/identity binding.
- Bindings/controls: no proof-binding edge is added, so no NC id/credit is claimed.
  Identity/row/query rejection, exact vectors and sampler-exhaustion checks support
  the contract. Native compile-fail, parser, capacity and fault tests are delivery
  gates, not silently counted as completed by research checks.
- Ledger: none changes. The algorithm does not certify its distance or a Merkle
  commitment. A7's candidate all-seed event, A3's conditional tensor/query terms
  and Q12's unresolved composition/profile budget remain outside A4 acceptance.
- Certificates: static lengths/counts are derived from exact identities. Info
  snapshots cannot be supplied back as authority. No CQIS identity or certificate.
- Padding/masks: no implicit padding, identity equivalence normalization, alternate
  base/rate, zero-edge removal or value-based sampler skip. Output order is fixed.
- Determinism: preserve all v2 record coordinates and caps, despite changing the
  order of row regeneration. Exhaustion returns no partial output or fallback.
  The base-only seed is retained in identity despite not affecting its map.
- Parity: existing independent dense/base evidence, sampler KATs, thirty identity
  cases and nine bounded/materialized cases support exact semantics. Native
  thousand-case-per-field parity/digests and large runs remain delivery criteria.
- Cost model: explicit d*E sparse work, fixed base, per-call regeneration, copies
  and complete requested/actual memory categories. New field scaling must really
  use one multiplication per base limb. No benchmark result or fitted constant
  is inferred. Matmul weight passes and cut set are unchanged.
- Verifier: production unchanged. The new API rejects raw graph/metadata injection
  and seals both trusted traits. Native no_std, allocation failure behavior and
  exact error/compile-fail tests remain required. Direct pinned BLAKE3 adds no
  workspace dependency edge or alternate FS API.
- Glossary: encoder information, distance/setup evidence, registry authority and
  PCS/profile admission remain distinct. Both research proven flags stay false.

I tried to break it by supplying a canonical raw graph as a code identity, and
the control check_identity rejected it with InvalidCodeId. I also exhausted a
late B stream; check_bounded rejected SamplingExhausted without returning partial
output. These are research boundary checks, not production PCS controls.

Sign-off: accept A4's deterministic encoder API/map/resource contract. E4-08 is
ready only for implementation, with every native test and complete ledger still
required. E4-01 depends on E4-08 and retains its original acceptance criteria and
A1 blocker. This stages delivery without dropping any requirement of the full MVP.

# RFC-0010 A4 first native encoder implementation review

Reviewer: codex-root, also the author; pcs-engineer/stele-code owner and
soundness-auditor. Not an independent audit. E4-08 remains in progress; full
1000-case-per-field byte parity, comprehensive compile-fail coverage, digest-gate
integration and complete operation/memory ledgers remain delivery work.

- Public items/RFC: exact A4 Encoder/EncoderInfo/Code/CodeField surface; factory
  fields and both sealing traits are private. Existing Circle implementation is
  reused unchanged. Only exact Circle/v2 IDs and approved field types reach encode.
- Challenges/absorbs: no new transcript operation. The private 74-byte BLAKE3 frame
  is the specified deterministic setup input. Public calls always use that hash;
  private test callbacks exercise exhaustion, not a verifier bypass.
- Claims/consumers: complete codewords and coordinate selections only. Metadata
  snapshots are not input authority. No distance, source/PCS/profile acceptance.
- Bindings/controls: malformed requests, empty-query no-generation, outer/inner/late
  exhaustion and exact 256-word cap checks pass. These earn no PCS NC credit.
- Ledger: no new loss or challenge. A1/A3/A7/Q12 remain open. No proven flag changes.
- Certificates: checked mathematical counts and requested payloads are static in
  ID/type/query length. U64 work totals are independent of address-sized buffers.
- Padding/masks: exact rows; no padding, code equivalence normalization, zero-edge
  deletion, alternate seed or partial output. Query order/duplicates preserved.
- Determinism: fixed per-row frames and degrees; sorted distinct neighbors paired
  with coefficients in draw order. Recursion uses disjoint source/output/scratch
  slices and preserves the non-systematic Circle base.
- Parity: nine whole-word digests from the materialized Python map in all fields,
  native linearity/zero/query checks, existing Circle tests and initial compile-fail
  tests pass. This is not the required larger full-byte suite or GPU evidence.
- Cost model: fixed workspace plus base/query overlap, no retained graph; every
  call pays generation and sparse work. No measured constant or benchmark claim.
  Requested bytes are not actual capacities, hash stack, allocator overhead or RSS.
- Verifier: no_std/unsafe-free core, fallible reservations and checked capacity;
  private recursion shapes follow the validated identity. Public output is only
  returned after all sampling/arithmetic succeeds. Native resource evidence remains.
- Glossary: encoder information is distinct from PCS parameters and profile bounds.

I tried to break it by exhausting the final B coefficient stream, and the control
rejects_outer_inner_and_late_sampling_exhaustion rejected it with SamplingExhausted
and preserved the original input. This checks the encoder error path, not proof
soundness or completion of the full MVP.

# Encoder observation contract review

Task E4-08, RFC-0010 A5. Reviewer codex-root, also author; pcs-engineer/owner,
rfc-author and soundness-auditor passes. Same-author review, not independent audit.

- Public items: A5 specifies measured encode/query results and their units; A4's
  existing closed API/map/error contract remains normative.
- Challenges/absorbs and claims/consumers: none added. Measurements are returned
  only with a successful encoding and have no verifier consumer.
- Bindings/controls: no proof binding or NC credit. Native parity, report liveness,
  empty/error paths and omission mutations are implementation delivery gates.
- Ledger: no error term changes. Neither work counts nor observed capacities
  establish code distance, setup/proximity composition or PCS admission.
- Certificates: no integer-inference identity or bound certificate. Shape-derived
  allocation checks remain A4's; actual capacities are separately observed.
- Padding/masks: no new padding or value-based skipping. Zero edges still count.
- Determinism: one arithmetic path, fixed traversal, no timing/callback input.
  Reports are not hashed into proofs or used to select a different map.
- Parity: exact canonical values/queries must remain equal in all three fields.
  No GPU work, independent audit or complete inference proof follows.
- Cost: full timing includes reports, hashing, sampling, initialization, copies,
  base and sparse work. Logical operations and vector payloads have explicit
  exclusions; stack/hash frames, runtime and process peaks remain required.
- Verifier/no_std: no verifier API change; no_std and fallible allocations remain.
- Glossary: observed work is not a trusted parameter or resource certificate.

I tried to break it by treating an observation as a supplied encoder or profile
parameter; the contract rejects that construction by leaving all authoritative
factories unchanged and providing no consumer for reports. Native mutation tests
are still required; this specification review claims no executed new control.
Sign-off: accept A5's observation-only extension, retaining all A4 delivery gates.

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

## Native implementation evidence

One implementation now produces ordinary and measured encodings. Reservations
charge actual Vec capacities; explicit releases follow buffer lifetimes. The
outer output/scratch coexist with the temporary base word and its transform
allocations. Query selection survives the complete second encoding. Counter
updates are bounded by A4's admitted J/field sizes and cannot select map data.
Every success includes hash draws, completed rows, sparse limb operations,
initialization/copies, base transforms and recursion depth. Errors expose no
partial result/report; empty queries retain zero observed work/allocation.

The actual digest gate requires the complete-work test. All three fields match
independent capacity/operation recurrences, ordinary results and Circle results;
zero rows preserve full work. The independent full-byte corpus and sampler/seal
checks still pass. Workspace tests, all-target/all-feature Clippy, no_std, fmt,
bans, digest, controls, accounting, ledger/RFC/link/glossary/Rust policy gates pass.
GPU unchanged. Existing coverage stays 3/17 bindings and 14/72 controls with one
separate configuration control. This is encoder evidence, not a proof digest.

I tried to break it by reporting only the largest individual allocation and
omitting simultaneous buffers, and the control
`test_rejects_native_measurement_overlap_omission` rejected it in the real gate.
The compiler-frame parser also rejects dynamic SP updates, inconsistent/growing
cycles, unbalanced returns and unknown indirect branches. Conditional allocation
and unreachable code tests pass. Its exact native/hash frame inventory is not
a whole-process stack bound; caller/runtime frames and complete RSS remain
separate. Large clean-source benchmark delivery remains required for E4-08.

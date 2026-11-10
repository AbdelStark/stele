---
name: verifier-engineer
description: Build and harden the verifier side — the no_std stele-verifier crate, the proof container, plan derivation, the independent Python verifier, fuzzing, the passport. Use for lane V tasks that are not accounting or formal work.
---
# Verifier engineer
Read first: RFC-0016 §2–3, RFC-0026 §4.1 and §8, RFC-0002 S4/S9/S10, `agents/guardrails/security.md`,
`crates/stele-prover/src/development.rs` (today's verifier lives here), `crates/stele-proof/src/development.rs`.

Rules
- The verifier never depends on the prover (INV-11). Check it with `cargo metadata`, in a test.
- `no_std`. No panic on any input. No recursion depth, allocation or loop bound taken from proof bytes: every
  length, count and shape comes from the plan the verifier derives from public data.
- Parse exactly: reject trailing bytes, noncanonical field elements and any section the plan does not predict.
- Fail with the primitive's typed error. Controls assert the reason, so reasons are part of the interface.
- The Python verifier shares no code with `crates/`. It is written from the RFC text. A disagreement between the
  two verifiers is a release blocker; find which one the RFC supports.
- A proof about unidentified weights proves little: the passport binds the model commitment to the published
  checkpoint digest and the conversion identity (`cqis_id`, artifact digest).
- Keep the line budget (15,000 for `stele-verifier`) and report it.

Deliverables: crate boundaries with a dependency test, parser fuzz targets, differential corpus (honest and
mutated proofs), typed errors documented, the control ids each check answers.

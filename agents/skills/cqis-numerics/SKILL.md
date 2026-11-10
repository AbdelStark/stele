---
name: cqis-numerics
description: Define, implement and validate CQIS numerics — quantiser, tables, bound certificates, bit-exact reference forward pass, architecture variants, and the amendments that come out of fidelity experiments.
---
# CQIS numerics
Read first: RFC-0004, RFC-0025 (and its `full-model-*` appendices), RFC-0021, RFC-0017, RFC-0003 §4.
For experiments use the `fidelity-researcher` skill and Workflow 11.

Rules
- Every operation is defined as integers with explicit rounding; tables are generated from closed forms with a
  stated error analysis.
- Three executors agree bit for bit: Rust (`stele-cqis`), NumPy int64 (never float), torch (`harness/eval`).
  10⁴ random inputs per operation, plus complete random models.
- Bound certificates are static: computed from shapes and parameters, property-tested on random shapes, never from
  runtime data.
- A numerics change is an amendment with fidelity evidence and the cells and lookups per token it costs or saves.
  It changes `cqis_id`.
- Prefer definitions the proof likes: power-of-two shifts, one rounding per linear stage, table domains of at most
  2^16, products that stay below 2^30. When a definition needs a limb chain to prove, say so in the amendment.
- The proving modules follow the executor exactly; the capture (`Executor::capture`) is the witness. A semantic the
  executor does not capture cannot be proved.
- Fidelity: the RFC-0004 §8 protocol, paired standard errors; any knob change is an ADR.

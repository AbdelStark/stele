# E3-04 benchmark harness review

Reviewer: codex-root, also the author. Same-author soundness-auditor and
benchmark-runner passes, not independent audit. Production libraries unchanged.

I tried to break it by flipping one unused final byte in the benchmark's warmup
proof, and the control rejected it with ClaimMismatch. The test also rejects a
missing proof and false continuation; no catalog credit is added. The runner
writes no ledger unless every produced proof has been consumed successfully.

Workflow 03 checklist:
- Public items: example/runner only, RFC-0006 A5 and RFC-0018 §1 micro evidence.
- Challenges: unchanged A1 Instance, Round before Sumcheck, then all Final values;
  each worker initializes the same transcript and checks its continuation.
- Claims/consumers: four original tables reconstructed by the actual public
  consumer; every warmup and measured proof is consumed, not only the last one.
- Bindings: no disabled check or new binding. Separate prove/consume processes
  are an ordinary proof pipeline; the ledger runner requires both to succeed.
- Ledger: unchanged m*delta/p^d; SC metadata and original claim count checked.
  Micro root verifier/proof/control fields remain zero as required by the schema;
  actual operation records are in model_config and stage_times_ns.
- Certificates: deterministic bounded typed fixtures; no integer proof or range
  certificate claimed. External proof bytes require exact canonical width.
- Padding/masks: no new privacy, mask, selector or commitment semantics.
- Determinism: proof and continuation identical across strategy/k, fixed fixtures,
  all samples retained; reverse case order on alternate samples.
- Parity: both-field CPU tests and actual CLI smoke; no GPU change.
- Costs: c_sc/T_misc observations planned, no result yet. Prover time includes
  representation preparation, construction and transition. Consumer time includes
  K materialization and table deallocation. Synthetic fixture setup, transport,
  parsing, assertions and launch are excluded explicitly.
- Memory/verifier: unchanged no_std verifier. Native worker RSS captures setup,
  warmup, overlap and retained capacity; sequential pipeline peak is max of
  worker peaks, excluding Python controller. This is not isolated scratch memory.
- Glossary: micro observations cannot certify inference, a profile or fitted costs.

Sign-off: approve harness conditional on gates and clean-source measurement.
E3-04 remains in progress until actual ledgers, including complete consumer cost
and memory and all losses, are inspected. Prover-only savings are labelled as such.

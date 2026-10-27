# Post-proof control helper review (RFC-0006 A1)

Reviewer: codex-root, also the author; same-author negative-control-author pass.
The helper calls the honest prover once, requires honest acceptance before the
hook, clones the proof, rejects no-op mutation and requires the exact verifier
error. It neither calls a second prover nor provides a check-disabling option.
The shared ProverHook leaves the exactly-one-value assertion with each concrete
control, as required by Workflow 08. Existing witness/configuration paths remain.

I tried to break it by accepting the tampered proof, returning the wrong rejection,
rejecting the honest baseline and using a no-op hook; the harness self-checks
rejected each case. A call-order assertion verifies one prove and two verifies.
These fixture checks earn no protocol coverage; all planned sumcheck NCs remain
incomplete until connected to the production sumcheck implementations.

No challenge, claim consumer, field identity, padding, mask, cost-model term,
benchmark, core dependency or protocol API changes. E3-01 remains in progress.

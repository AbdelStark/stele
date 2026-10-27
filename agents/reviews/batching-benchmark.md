# Batching benchmark review (RFC-0006 A2 / RFC-0018 §1)

Reviewer: codex-root, also the author; benchmark-runner, sumcheck-prover-engineer
and soundness-auditor passes, not independent audit. E3-02 remains open until the
separate measured-ledger delivery is merged.

I tried to break it by returning an unverified sample, and the control
`rejects_unverified_sample` rejected it with ClaimMismatch. This is a harness test,
not additional NC catalog credit; all existing protocol controls run before timing.

Workflow 03 checklist:
- Public items: none in core; executable benchmark uses both A2 engines.
- Challenges: only production transcripts; initialization and BatchFinal are timed.
- Claims: every warmup/measured proof passes the public adapter; verification is untimed.
- Bindings: unchanged; no skip/check-disabling option or new claim edge.
- Ledger: expected SC/RLC and field degrees checked; padded constants use degree one.
- Certificates: only existing field identities; no new integer relation or profile claim.
- Padding/masks: equal/unequal sizes, sparse/overlapping/arbitrary claims; no ZK claim.
- Determinism: fixed synthetic inputs; proof bytes checked within/across samples.
- Parity: both fields smoke-tested in CI; native CPU measurements, no GPU changes.
- Costs: actual timing/RSS source recorded; no fit or performance improvement claimed.
- Verifier: core no_std APIs untouched; failure aborts the benchmark without a ledger.
- Glossary: existing terms; RSS is process memory, logical payload is separately labelled.

The frozen runner checks clean source state before/after, retains every sample,
uses a new output path, and validates the resulting micro ledger. Both-field runs
completed from the recorded source commit; measurement artifacts are delivered separately.

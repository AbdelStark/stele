# Shared sumcheck corpus review (RFC-0006 A1, E3-01)

Reviewer: codex-root, also the author; same-author sumcheck-prover-engineer and
negative-control-author passes, not an independent audit.

The corpus serializes the canonical logical instance, public tables and subproof;
it never supplies a verifier point. Python decodes exact-width canonical limbs,
replays each chain on one transcript, consumes every public obligation and reports
the first exact rejection. Expected outcomes are explicit, not copied from verifier
output. Successful receipts retain points, tensor/value obligations and SC rows.

I tried to break it by changing one final value using an early/stale challenge or
omitting the preceding Final absorb; the reference controls rejected each with
FinalEvaluationMismatch. Constant-P false claims reject at the public consumer.
These are research controls only. Actual Rust parity and production NC registration
remain required by E3-01. No core code, challenge label, budget, benchmark constant,
scaffold guard, catalog status or task acceptance criterion changes.

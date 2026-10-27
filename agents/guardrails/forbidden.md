# Forbidden — a PR containing any of these is closed without review
1. Any flag, feature or environment variable that disables a check in prover or verifier (`--unsound-*`, `skip_*`, `allow_invalid`).
2. Conjectural bounds in the `treaty` profile; unlabelled conjectural bounds anywhere.
3. Challenges from anything but `Transcript`; prover-side randomness in the transcript path (ZK masks are drawn from an RNG *and then committed* — that is allowed).
4. Floating point in prover/verifier crates.
5. Vendoring or forking another proof system into `crates/`.
6. Editing Accepted RFC text in place; deleting ADRs; force-pushing `main`.
7. Benchmark numbers without a ledger; comparisons that mix statements without saying so.
8. Committing any tensor not named a cut in an Accepted RFC.
9. A second weight pass in any phase.
10. Human timelines, "soon", "later", "TODO" without a task id.
11. Tolerances ("approximately equal") in parity or digest gates.
12. Logging weights/activations; disabling ZK in treaty profile.

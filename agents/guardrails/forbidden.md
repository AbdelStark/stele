# Forbidden — a PR containing any of these is closed without review
1. Any flag, feature or environment variable that disables a check in prover or verifier (`--unsound-*`, `skip_*`, `allow_invalid`).
2. Conjectural bounds in the `treaty` profile; unlabelled conjectural bounds anywhere.
3. Challenges from anything but `Transcript`; prover-side randomness in the transcript path (ZK masks are drawn from an RNG *and then committed* — that is allowed).
4. Floating point in prover/verifier crates.
5. Vendoring or forking another proof system into `crates/`.
6. Editing Accepted RFC text in place; deleting ADRs; force-pushing `main`.
7. Benchmark numbers without a ledger; comparisons that mix statements without saying so.
8. Committing any tensor not named a cut in an Accepted RFC. (The development tier's cuts are the columns RFC-0026 names.)
9. A second weight pass in any phase of a `standard` or `treaty` plan. (The development tier may read twice and reports the count.)
10. Human timelines, "soon", "later", "TODO" without a task id.
11. Tolerances ("approximately equal") in parity or digest gates.
12. Logging weights/activations; disabling ZK in treaty profile.
13. Claiming a security level, zero knowledge or a profile for a development-tier proof; promoting a capability inside the change that introduces it.
14. Marking advice as a virtual column (RFC-0028 §1.2), or giving a virtual column a definition that is not an integer polynomial in other columns.
15. Merging a change that leaves rung L0 failing on `main`; patching forward instead of reverting.
16. A performance or capability statement without a ledger on a named rung; a before/after pair from different rungs, hosts or thread counts.
17. Stacked changes in a lane, or a second open change in a lane.
18. New work on a stopped line (RFC-0027 §7) without an ADR that reopens it.

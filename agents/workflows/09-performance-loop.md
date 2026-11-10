# Workflow 09 — Performance loop (profile, change, record)
Use for every task whose acceptance is a time, memory or size number.

1. **Baseline.** Record the rung with stage times and counters before touching code (Workflow 04).
2. **Profile.** Name the stage and the loop. Stage timers first; a sampling profile if the stage is opaque. Write the
   finding in the PR: stage, share of prove time, what it does per element.
3. **Hypothesis.** State the cost-model term (`c_w`, `c_a`, `c_x`, `c_c`, `c_lu`, `c_sc`, `T_misc`), the expected
   gain and why. No change without one.
4. **Order of attack.** Fewer elements (protocol) before cheaper elements (representation) before more hardware
   (threads, SIMD, GPU). A kernel for a loop the protocol can remove is wasted work.
5. **Change** one thing. Proof bytes must not change unless an amendment says so (digest gate). If they must change,
   that is a protocol change: Workflow 02 first.
6. **Parity.** A new backend path equals the scalar reference byte for byte on seeded inputs, edge values included.
7. **Record** the after ledger on the same rung, host class and thread count. Regenerate the scoreboard.
8. **Keep or revert.** A change that does not move its stage by the amount its hypothesis needed is reverted, and
   the finding is written down.

Habits that pay here: typed small integers until the first sumcheck fold; base-field arithmetic for as many rounds
as the values stay small; one pass over a table per round; one thread pool for the process; no allocation inside a
round; counters for every read of a weight.

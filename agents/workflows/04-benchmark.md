# Workflow 04 — Benchmark on the ladder
1. Pick the rung (RFC-0027 §3). L0 and L1 run anywhere. L2 and above run on a named host class; use the scripted
   remote host (task E17-04) and record the class in the ledger.
2. Run the documented commands (`docs/development-e2e.md`), all bindings on. Record device, commit, toolchain and
   thread count; add a one-line note of what changed.
3. Write the ledger with `bench/dev_e2e.py` (development tier) or `stele-cli bench` (`standard`, `treaty`); it must
   validate. From task E17-01 on, a record carries stage times and the cell, lookup and byte counters.
4. A comparison is a pair of ledgers from the same rung, host class and thread count, one before and one after.
   One run each is a smoke result; state the run count. Never mix rungs or hosts in one claim.
5. Regenerate `bench/scoreboard.md` (`python3 bench/scoreboard.py --write`; `stele-bench scoreboard` once task
   E17-02 lands). A stale scoreboard fails the tooling tests. Numbers in docs come only from ledgers.
6. State the cost-model term moved and the measured constant before and after. Run `stele-bench fit` when the task
   says so; never hand-edit a fitted constant.
7. Comparisons to external systems cite their statement, arithmetic, hardware and source (RFC-0018 §1.3).
   A different statement is said to be different in the same sentence as the number.

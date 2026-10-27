# Workflow 04 — Benchmark
1. Use `stele-cli bench --workload W<n> --profile <p> --ledger bench/ledger/<run>.json`; all bindings on (the CLI refuses otherwise).
2. Record device, driver, commit, toolchain automatically; add a one-line human note (what changed).
3. Run `stele-bench fit` and `stele-bench roofline`; attach the plots to the PR.
4. State the cost-model term moved and the measured constant before/after. Numbers in docs come only from ledgers.
5. Comparisons to external systems must cite their statement and arithmetic (RFC-0018 §1.3).

# Workflow 11 — Numerics and fidelity experiment
Use for any change to what CQIS computes, and for every R-NUMERICS question.

1. **Pre-register.** Before any score is seen, commit: the hypothesis; the candidates; the model and revision; the
   protocol (`harness/eval/fidelity.py`: WikiText-2 windows, the task benchmarks, paired standard errors); the
   subset used for screening; the decision rule and the kill criterion.
2. **Two measurements per candidate, always together:**
   - fidelity: perplexity delta, task deltas with paired SE, top-1 agreement with the float model;
   - proof cost: committed cells and lookup positions per token from the accounting tool (task E22-01).
   A candidate that wins one and loses the other is reported as that, not as a win.
3. **Screen in simulation, decide on the exact executor.** Float fake-quantisation may rank candidates. Only the
   exact integer executor (`harness/eval/cqis_torch.py`, parity-checked against the native executor) produces a
   number that enters a report or an amendment.
4. **Exactness evidence first.** Executor parity on the changed semantics (Rust, NumPy, torch) before any fidelity
   number is quoted. Zero rejected items, or the rejections are reported.
5. **Report** in `harness/eval/REPORT.md`: tables, evidence file digests, cost of the runs, what was excluded and why.
   State defects found by the sweep itself.
6. **Decide.** Amend through Workflow 02 with the report as evidence, or drop with an ADR. A numerics amendment
   changes `cqis_id`; say so.
Floats appear only in the harness, only to evaluate accuracy (INV-12).

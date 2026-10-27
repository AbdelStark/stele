# Harness (Python, uv)
- `cqis/` — quantiser driver, table generation, bit-exact NumPy int64 reference forward pass (no floats except in `eval/`).
- `eval/` — fidelity suite (RFC-0004 §8): perplexity, GPQA-D, MMLU-Pro, IFEval with paired standard errors.
- `verifier/` — independent Python verifier of `stele-proof-v1` (RFC-0002 S10), kept in lockstep with `stele-verifier`.
- `witness/` — capture of residual cuts, scales, indices, multiplicities from the reference forward pass.
Run `uv sync && uv run python -m harness.selftest`.

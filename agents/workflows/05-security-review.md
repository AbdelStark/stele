# Workflow 05 — Security review (per release and per transcript/PCS change)
1. Regenerate the soundness ledger for W1/W4 in both profiles; diff against the previous release; explain every delta.
2. Run the full negative-control corpus with coverage report (bindings without controls = release blocker).
3. Fuzz `stele-proof` parser and `stele-verifier` for 24 CPU-hours; zero panics.
4. Differential: 10⁴ random small-model proofs, Rust and Python verifiers agree; 10⁴ mutated proofs, both reject.
5. Check the forbidden list (`agents/guardrails/forbidden.md`) by grep: no `unsound`, no `skip_check`, no float types in prover/verifier.
6. Write `docs/security/review-<release>.md` with findings, each linked to an issue or an RFC amendment.

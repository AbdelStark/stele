# Guardrail — security engineering
- Dependencies: hash-pinned; no network at build; `cargo deny` clean; new dependency ⇒ ADR.
- No `unsafe` outside `stele-simd`/`stele-gpu`; each block has `// SAFETY:` naming the invariant and a test.
- Verifier: no panics, no recursion depth tied to proof data, all lengths from the plan, constant memory bound from the plan.
- Secrets: weights and activations never written to logs, ledgers or proofs in the clear; ZK on in treaty; debug dumps gated by `STELE_DEBUG_DUMP=1` and refused in release builds.
- Reproducible builds of `stele-verifier`; SBOM; signed release artefacts.
- Do not add telemetry.

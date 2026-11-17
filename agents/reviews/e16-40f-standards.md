# E16-40f Standards review — lane B

Reviewed `3c441a50d1becae9b9e5ea2d21a03b6c7677c84c...458186d944660befae928dca8c6736d57a150889` (claim `a8b2c6f3`, implementation `458186d9`).

**Findings: none.** No actionable documented-standard breach or heuristic smell found in the changed hunks. This is an implementation review, not completion of the hardware or merge gates.

- `src/source_material.rs`: the existing `for_each_chunk_weighted` seam satisfies the one-pool rule (`agents/guardrails/code.md`, Workflow 09). Whole-column mutable views are disjoint; the helper preserves global column indices. Prior shape/length checks and the new complete salt-range bound cover worker arithmetic. Canonical validation and fallible reservations precede workers. The descriptor counter uses actual vector capacity and element size, and the vector is dropped before returning; returned-material ownership accounting is unchanged. No second pool, unsafe code or altered error path was introduced.
- `tests/source_material.rs`: child processes isolate Rayon initialization; exact test selection prevents recursive full-suite execution. Exit status and three required root records prevent empty-run success. Each child also compares every payload and path with production `PreparedSource`, rather than relying on roots alone.
- Example, documentation and graph hunks: existing fields and root-only behavior remain intact. Added reporting distinguishes transient host storage from returned material and complete device peak (RFC-0014 A1). The performance hypothesis remains explicitly unmeasured (Workflow 09); no unsupported speedup or promotion claim appears.

Review checklist: the new public accessor is host-allocation instrumentation under RFC-0014 A1; challenges, claims, bindings, soundness ledger, static bounds, padding/masks, verifier independence, commit rule and segments are unchanged. Glossary/tier scope is respected. Determinism uses indexed independent writes. No relation/plain-checker or proof format changed; full-proof parity and L0/L1 were not rerun. No cost-model improvement or ladder result is established; H100 parity and matched before/after evidence remain pending.

Validation: Rust 1.90.0 targeted source-material integration tests and malformed/noncanonical unit test passed. I tried to break it by changing one payload word, and the `RootMismatch` control rejected it; incomplete and noncanonical material was also rejected.

Skipped tooling-enforced checks, workspace/native gates and GPU campaigns as requested. Risk: merge acceptance still requires the pending hardware evidence and mandatory gates.

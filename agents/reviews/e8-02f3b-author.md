# E8-02f3b independent-author provenance

Task E8-02f3b, RFC-0026 A16, ADR-128/131. Author: `registry_wrapper_author`.
This is an implementation record, not an independent review or profile admission.

The coordinating agent had read production code and therefore delegated only
`crates/stele-verifier/` to a fresh-context author. That author read Accepted A16,
A15/E1, existing independent verifier code and repository rules. It did not read
production code, production declarations, the control preflight or `vectors.py`.
Root separately implemented the production controls and gate wiring.

Before reference comparison, the author recorded an immutable five-file snapshot
and provenance in the coordinator's external
`/Users/abdel/dev/stele-validation/e8-02f3b-independent-initial/` directory. Six
spec-derived tests and the no-default-features library check passed. Initial
`src/registered.rs` SHA-256:
`60ec83edca25e6c2345b2a359a7186228d8b6a1b78b2f090ffc70b3c652cfc9d`.

Only after this milestone did the author compare `vectors.json` and public byte
exports. All seven codec, nineteen request-negative and three precedence cases
matched. Both pinned one/eight-layer full proofs passed. Twelve declaration-only
variants and the blocked embedding vector matched request/template computation;
those declaration variants do not claim full-proof acceptance. No runtime
correction was needed after comparison; later changes added tests, test lint
corrections and test receipts. The final runtime differs from the snapshot only
by its `cfg(test)` module declaration.

Targeted validation: verifier crate tests, all-target Clippy with warnings denied,
formatting and no-default-features library check passed. Tests with explicit
`STELE_DEV_REPLAY_DIR` emitted both named full-proof receipts and twelve named
declaration receipts. Required native validation checks those exact receipts,
so an environment-dependent test that returns without exports earns no credit.
Whole-workspace validation and independent review remain separate task gates.

The public `registered::verify` API preserves the original relation for A15 replay.
Acceptance states **trusted plan registry; development: no security level**.
Publisher correctness and entry distribution remain trusted; caller expectation
of tokens, checked range and next token remains the caller's responsibility.
There is no independent model/plan derivation, byte-4 replay or profile promotion.

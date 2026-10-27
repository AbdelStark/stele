# Decision log (ADRs, append-only; template in agents/templates/adr.md)

| ADR | Decision | Status | RFC |
|---|---|---|---|
| ADR-001 | Sumcheck/GKR core; no trace, no zkVM, no fork of Stwo | Accepted | 0001 D1 |
| ADR-002 | M31 base field, QM31 challenges; OM31 for treaty sumchecks pending R-OCTIC | Accepted | 0003, 0012 D10 |
| ADR-003 | Residual-stream-only cuts | Accepted | 0007 §3 |
| ADR-004 | Interleaved-code PCS with fused opening; circle RS for weights, RAA for cuts | Accepted | 0010 |
| ADR-005 | CQIS: int8 matmul inputs, int16 wide path, exact int32 accumulation, round-half-away | Accepted | 0004 |
| ADR-006 | LogUp-GKR for every nonlinearity; double challenge in treaty | Accepted | 0008 |
| ADR-007 | Blake3 transcript/Merkle; Poseidon2 only in wrapper | Accepted | 0012 |
| ADR-008 | Stwo as optional outer wrapper | Accepted | 0016 |
| ADR-009 | Codename Stele; rename is a one-line change in `Cargo.toml` workspace metadata and `scripts/rename.sh` | Accepted | — |
| ADR-010 | Output-side softmax normalisation; attained-max selection sumcheck | Accepted | 0009 |
| ADR-011 | Witness recompute from cuts instead of witness storage | Accepted | 0014 §4 |
| ADR-012 | Treaty profile uses proven PCS bounds only | Accepted | 0010 §6 |

## ADR-013 — Locked JSON parser for benchmark ledgers

Context: RFC-0018 §1, task E0-05 requires validation of untrusted JSON records.
Decision: use exact-version `serde` and `serde_json` dependencies in `stele-bench`,
with Cargo.lock checksums, retained parser depth limits, a byte limit, integer-only
visitation, and duplicate-key rejection at every depth. No derive feature is enabled.
A handwritten JSON parser was rejected because correct escaping, Unicode, numeric
syntax, and nesting checks are substantive parsing work. These dependencies do not
enter the prover or verifier dependency paths. Fetch locked sources before offline
builds. No protocol, soundness-ledger line, or cost-model term changes. Status: Accepted.

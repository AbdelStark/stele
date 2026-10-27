# Negative-control catalogue (INV-4). Every row is a test that must be *rejected* with the stated error.

| NC-id | Binding | RFC § | Tamper | Expected error | Status |
|---|---|---|---|---|---|
| NC-0001 | output token ↔ logits | 0004 §7 | flip one generated token | `DecodeMismatch` | todo |
| NC-0002 | residual cut ↔ layer | 0007 §3 | +1 on one `R_ℓ` element after capture | `ClaimMismatch(R_stack)` | todo |
| NC-0003 | weight block ↔ layer index | 0007 §2 | swap `W_Q` blocks of two layers | `FusedOpeningMismatch` | todo |
| NC-0004 | passport binding | 0011 | prove with another passport | `PassportRootMismatch` | todo |
| NC-0005 | prompt binding | 0001 §3 | change one prompt id in `io_digest` | `EmbeddingClaimMismatch` | todo |
| NC-0100–0109 | CQIS gadgets | 0004 §10 | see RFC | typed per gadget | todo |
| NC-0200–0204 | sumcheck engine | 0006 §8 | see RFC | `RoundCheckFailed` etc. | todo |
| NC-0300–0305 | matmul phases | 0007 §8 | see RFC | | todo |
| NC-0400–0405 | lookups | 0008 §7 | see RFC | `LogUpImbalance` etc. | todo |
| NC-0500–0506 | attention | 0009 §7 | see RFC | | todo |
| NC-0600–0605 | PCS | 0010 §10 | see RFC | | todo |
| NC-0700–0703 | passport | 0011 §6 | see RFC | | todo |
| NC-0800 | transcript/ledger | 0012 §6, A1 | draw challenge before required message in the real protocol | | todo |
| NC-0801 | transcript/ledger | 0012 A1 | configuration: replace one registered label with another | `DuplicateLabel` | done |
| NC-0802–0805 | transcript/ledger | 0012 §6 | see RFC | | todo |
| NC-0900–0901 | ZK | 0013 §6 | see RFC | | todo |
| NC-1000–1002 | GPU | 0014 §7 | see RFC | | todo |
| NC-1100–1101 | distributed | 0015 §7 | see RFC | | todo |
| NC-1200–1203 | verifier/wrapper | 0016 §7 | see RFC | | todo |
Coverage report: `scripts/gates/negative-controls.sh --coverage` lists claim-graph edges, PCS checks and ledger lines without a control.

The registry-collision entry checks the actual registry validator (configuration control, RFC-0012 A1). It does not establish a proof-statement binding. Early-challenge and missing-final-claim controls require real protocol consumers; primitive sensitivity tests earn no credit.

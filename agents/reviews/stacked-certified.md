# Certified stacked runtime review

This delivery implements the certified-source part of Accepted RFC-0006 A4,
RFC-0012 A6 and RFC-0020 A2. E3-06 stays `in_progress` until complete resource
ledgers satisfy the [runtime contract](../../formal/stacked-runtime.md).

Separate GKR, soundness-auditor and CI agents review the code and evidence.
The author owns all tracked changes and executions. These are coordinated
internal reviews, not an independent cryptographic audit. The PR records the
final reviewer results, validation receipts and tested revision; source review
alone does not authorize merge.

| Workflow 03 item | Finding and required evidence |
|---|---|
| RFC coverage | The existing Accepted contract supplies mode-1 source bytes, actual A1/A7/A9 composition, errors, capacities and controls. No Accepted RFC changes. |
| Source authority | Every expected handle comes from full certificate verification. The producer's immutable material must match its complete context. Full-real layouts only; every original remains in the roster. |
| Transcript | StackSources binds complete contexts and certificate IDs before Stack and actual A1. No new label, random challenge or source commitment. |
| Producer point | Dense reserves and captures actual fold arguments, restores them in place and releases its tables before opening preparation. The closed producer uses actual A1; raw strategy methods grant no authentication. |
| Claims | GKR independently consumes A7 and exports restored original obligations. Reductions calls actual A9 verify_point on every original at that point, including unused inputs. Each source retains its own row/column split. |
| Records | Only full closure constructs StackedSourceRecord. Its actual SC and opening records borrow the verified certificates; proof, statement and transcript buffers grant no authority. Construction/lifetime doctests are mandatory. |
| Controls | NC-0211 changes one unused original final, preserving all opening bytes; actual A1/A7 passes and PCS rejects ValueMismatch after exactly Opening/OpeningRow, before queries. NC-0213 replaces one genuinely verified expected handle for unchanged proof bytes and reaches RootMismatch. |
| Accounting | One cumulative transcript snapshot plus disjoint local Merkle work, including earlier successful openings and the failing path. Certificate registration/lifetime losses remain separate and retained. No new algebraic term. |
| Limits | Complete mode-1/Stack/A1/opening frames and proofs share descriptor/proof budgets. GKR prepared/partial/axis policies retain their stated scope; A9 retains checked allocations. Exact/one-below budgets and malformed later wires must reject before replay. |
| Parity | The 116 public decisions retain their digest. An additional 48 independent certified cases compare actual native-produced certificates/proofs/openings, restored claims, records, usage and continuation in both fields. No GPU change. |
| Cost | Direct M31-to-Dense preparation avoids a second lifted witness. Captured point capacity is counted. Complete source/setup/opening/overlap/process evidence remains due; no fitted constant or weight-pass claim. |
| Boundaries | Conditional field relations only. Integer/CQIS ownership, plan derivation, Q12, private coefficients, profile admission and zero knowledge remain separate obligations. |

The author ran both certified controls against the real consumers and both-field
round-trip, malformed-input and exact-budget tests. Review corrected an invalid
test assumption that Eq needed axis-vector storage; the boundary now uses a
onehot coefficient. It also strengthened NC-0211's transcript-work assertion.
The mandatory native gate repeats these checks and the independent wire comparison
on the frozen delivery source. Final approval requires those receipts and hosted CI.

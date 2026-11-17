# E16-40d Standards review — lane B

Reviewed PR #399, fixed base `6abc98cb836a504064811d6f34ba0fe175213116`
to head `9aecca0b8936dc978cb6944c3beecd9be37641cb` (both commits).
Scope: all eight changed files and their existing parser/CPU/CUDA consumers.
Read AGENTS, invariants, glossary, guardrails, Workflows 03/06/09/12,
cuda-kernel-author and governing RFC sections. No CONTRIBUTING or
CODING_STANDARDS files were found.

**Documented-standard breaches:** none found in this source diff.
**Judgment smells:** no actionable baseline smell; reuse and separation fit the
existing research harness. Standards approval covers implementation, not merge readiness.

E16-40d requires “preserve mask ordering”; `src/inventory.rs:130–142`
retains coordinate zero, each mask/predecessor and the last coordinate, then
sorts/deduplicates. This preserves simultaneous events without claiming original
geometry. `examples/inventory.rs:124–153` compares every table after construction
and every fold; preparation occurs inside campaign timing. Production code,
kernels, proof bytes and interfaces are untouched. MASKED-INVENTORY explicitly
excludes actual-size, lazy-limb, compact-final and full-proof evidence.

I tried to break it by deleting/duplicating records, disabling bindings and
corrupting indices/counts, and the control `rejects_incomplete_or_malformed_inventory`
and exporter rejection tests rejected it. Independently passed four Rust
inventory tests, three Python exporter tests and 27 `stele-ir` relation tests.

Workflow 03 checklist:

1. Public items: research Inventory/Case, RFC-0014 §5; no protocol API.
2. Challenges: synthetic fixed challenges; transcript unchanged.
3. Claims/consumers: unchanged; no proof emitted.
4. Bindings: none added; parser controls above.
5. Soundness ledger: unchanged; accounting gate pending.
6. Bounds: bounded harness geometry; no new faithfulness certificate.
7. Padding/masks: synthetic mask coordinates preserved; production unchanged.
8. Determinism: seeded cases, ordered vectors; HashSet membership only.
9. Parity: H100 execution pending; no full-proof/per-kernel parity credit.
10. Cost: c_sc coverage/cold-compilation risk; no measured gain claimed.
11. Verifier: untouched.
12. Glossary: no forbidden synonym introduced.
13. Tier: development research; no promotion/security claim.
14. Commit rule: unchanged.
15. Plain checker: honest and near-miss tests passed above.
16. Segments: unchanged.
17. Proof bytes: no encoding change; digest gate pending.
18. Ladder: none run here; no before/after comparison.

Remaining merge conditions: required current-base/merge-tree gates, owning-lane
review, and required hardware parity evidence. Task acceptance additionally
needs the bounded CPU/H100 campaigns, receipts and validated ledger (or explicit
failed-campaign disposition); ADR-127 remains NO-GO.

Skipped full workspace/native suites, H100 and tooling-enforced checks here.
Synthetic reduced parity cannot establish production integration readiness.

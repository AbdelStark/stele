# E16-40a independent specification / owning-lane P review

Reviewed base `07a7710044b8dc7b2f39433694cad7dba58ba062` through head
`3a1e077e0d6c35a18c9332fab326483c31baa066` (PR #395). Reviewer:
`codex-stage-inventory-spec-review`, acting as owning-lane P reviewer with the
`soundness-auditor` skill. **FIX-THEN-REVIEW; owning-lane approval withheld.**

## Finding

**P2 — Validate complete per-instance measurement sequences.**
`research/gpu-gating/stage_inventory.py:55–79` accepts child stages in any order
and checks only the total number of GKR shapes. Starting from its checked-in
fixture, independently swapping the first `gkr_factors` and `gkr_rounds` records
is accepted. Independently replacing both `shape gkr_first ` and
`shape gkr_leaf ` with `shape gkr_interior ` is also accepted: the returned
inventory has no first or leaf shape. The task requires the “actual production
relation and first/interior/leaf GKR shape inventory”; the documentation promises
“one complete development-ZK proof log” and checks of “phase order”. Aggregate
counts cannot establish either property. Require each child cycle in order,
exactly one shape between factors/setup, and complete GKR tree sequences whose
count agrees with the top-tree phase; add rejection tests for these mutations.

Preserve the legitimate single-step case: `plan_lookup` permits `n == k0`, so
the step is both first and leaf and this profiler labels it `gkr_leaf`.
The [preserved independent probe](/Users/abdel/dev/stele-validation/e16-40a-spec-one-step/README.md)
uses the existing lookup fixture with `extra=1`, proved and verified this case,
and asserted exactly one GKR step. Thus a tree's
labels are either `[leaf]` or `[first, interior*, leaf]`.

No protocol defect found. The additions read only public factor indices,
vanishing-coordinate indices, field degree and plan shape; no field coefficient,
witness, mask, seed or challenge value is printed. Existing coarse laps,
transcript operations, claim consumers, prepared-source ownership and explicit
tree drops are preserved. Children are disjoint within their parents;
unattributed time remains CPU work. RFC-0014 A1 says host measurements do not
“approve a GPU implementation”; this change makes no such claim.

H100 baseline/validated ledger and current-base L0/L1/mandatory CI remain
integration acceptance work, not credited here. RFC-0018 requires “a ledger for
each number”; the zero-time fixture is explicitly synthetic.

## Checklist and Workflow 03 evidence

1. **Public items:** no public Rust API added; opt-in measurement implements
   RFC-0014 §6 / E16-40a, constrained by §§1,4 and A1; development accounting
   follows RFC-0026 §7 and RFC-0018 A1/A2.
2. **Challenges:** none added/moved. Existing source roots precede lookup
   statement/units and β/α; top/shared roots precede relation draws and GKR
   r/λ. Masked round/final absorbs precede challenges, then t*, batch γ and PCS
   challenges in their existing consumers. Instrumentation never receives `t`.
3. **Claims:** none added/moved; occurrence and GKR finals use their returned
   point, route to existing source batches, and mask/block claims to the shared
   batch/opening. Sources are fixed before these points.
4. **Bindings:** none new. Ran existing table-final and shared-block controls:
   `rejects_changed_table` → `ClaimMismatch`;
   `rejects_unbound_block_finals` → `RoundSumMismatch`.
5. **Soundness ledger:** no accounting lines changed. Gate attempted but not
   completed: default Python lacks `tomllib`; 3.12 parent still invokes 3.9
   children, which fail `zip(strict=True)`. Integrator must obtain passing evidence.
6. **Bounds:** no new instances/certificates; existing plan-derived bounds remain.
7. **Padding/masks:** no selectors, masks or padded-row handling changed.
8. **Determinism:** no hash-map iteration/reduction-order change; independent
   subprocess instrumentation-off/on proof-field digest comparison passed.
9. **Parity:** CPU smoke above; SIMD/CUDA not run, no backend change or parity credit.
10. **Cost:** measurement separates existing c_sc/c_lu/c_c/T_misc work; no fitted
    constant, speedup or scoreboard claim, no new benchmark ledger reviewed.
11. **Verifier:** untouched; `cargo check -p stele-reductions
    --no-default-features` passed; no verifier panic or length source added.
12. **Glossary:** no forbidden synonyms introduced in changed code/docs.
13. **Tier:** development only; no promotion, security level or GO claim.
14. **Commit rule:** no committed/virtual column change.
15. **Plain checker:** `cargo test -p stele-ir relation:: --features std` passed
    all 28 honest/near-miss/static-bound cases.
16. **Segments:** no new cross-segment reads; source/claim lifetimes unchanged.
17. **Proof bytes:** all typed proof fields, including serialized sources,
    certificates and openings, agree off/on in the real-prover subprocess test;
    no serializer changed. Full container digest gate remains pending.
18. **Ladder:** no L0/L1 or benchmark pair run by this reviewer; focused tests are
    not ladder or H100 evidence. Four parser tests and ten `zk_lookup` tests passed;
    the additional malformed-log probes above expose the finding.

I tried to break it by changing one public lookup table entry, and the control
`rejects_changed_table` rejected it with `ClaimMismatch`.

Workflow 09: measurement scope only, no performance hypothesis accepted without
the pending baseline. Workflow 12: same-lane V stack on #394; inspected diff uses
no preceding unmerged column-routing interface, changes none of the named
cross-lane interfaces, and receives this owning-P review. Bottom-up integration
and rerunning gates on the intended current-main merge tree remain required.

Skipped full workspace/native/parity and H100 runs as assigned. The remaining
risk is acceptance of structurally invalid measurement logs until corrected.

## Focused re-review — correction accepted

Reviewed correction `3a1e077e0d6c35a18c9332fab326483c31baa066` →
`a9fd51f891ade65c5d95fa8ee6dd03b1da1eb130`, retaining whole-change base
`07a7710044b8dc7b2f39433694cad7dba58ba062`.
**APPROVED for owning-lane P implementation/soundness review at this head.**
The P2 finding above is resolved; the original record is preserved.

The parser now consumes each instance's children in order, requires exactly one
shape at its factors/setup boundary, matches measured counts to the plan's
leading declaration, and accepts exactly `[leaf]` or
`[first, interior*, leaf]` per lookup. Completed trees must match the declared
lookup count. The new producer declaration uses only the already validated
plan's public field/instance/source-batch counts, before witness conversion.
No transcript operation, claim source, lifetime, proof field or verifier check
changed. The documentation correctly separates structural log validation from
the ordinary verifier's polynomial-degree checks and proof acceptance.

Independent reruns passed all seven parser tests and the subprocess
`matches_reference_stage_instrumentation` test for both one-step and four-step
lookups, including proof-field equality with instrumentation off/on. Ten
additional probes rejected duplicate/missing/misplaced shapes, repeated first
steps, unterminated/all-leaf trees, a mismatched field, missing/repeated plan
declarations and zero variables. Fresh producer logs for both shapes also parsed
successfully after their proofs verified; raw outputs and parsed inventories are preserved at
`/Users/abdel/dev/stele-validation/e16-40a-spec-rereview/README.md`.
`git diff --check` passed. These runs are correctness evidence, not benchmarks.

I tried to break it by reordering GKR factor/round measurements and removing
the first/leaf topology, and the controls
`test_rejects_reordered_children_and_missing_batch` and
`test_rejects_false_gkr_topology_or_degree` rejected them.

The eighteen checklist answers above remain applicable; item 18's parser
finding is now resolved. No full gates were rerun in this focused pass. The
H100 baseline/validated ledger, current-base L0/L1, mandatory gates and bottom-up
stack integration remain pending acceptance work; this review grants no GPU GO,
speedup, parity or ledger credit.

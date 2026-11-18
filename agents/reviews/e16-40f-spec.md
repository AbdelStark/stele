# E16-40f — owning lane E specification and source-parity review

Reviewed fixed base `3c441a50d1becae9b9e5ea2d21a03b6c7677c84c` to head
`458186d944660befae928dca8c6736d57a150889` in
`/tmp/stele-codex-e16-40f`, using the three-dot diff. Reviewed commits
`a8b2c6f3` (claim) and `458186d9` (assembly). No repository or branch edits.
Applied AGENTS.md, code/review-checklist/soundness/GPU-parity guardrails,
Workflows 03/04/09/12, benchmark-runner and cuda-kernel-author guidance,
RFC-0014 §§1/4/5/A1, RFC-0010 A9/A15 and RFC-0013 A2/A8.

**PASS for the implementation's specification scope. No incorrect
implementation, missing code requirement or scope creep found.** Task acceptance
and merge approval remain incomplete until the evidence below passes.

E16-40f requires “assemble disjoint whole salted column payloads; preserve
canonical-word validation, allocation and offset failure handling, all source
bytes and all kernels.” `Material::new` satisfies this: source admission and
exact encoded/node sizes precede the canonical scan; checked total payload and
salt sizes precede workers; both new vectors reserve fallibly. The existing work
pool supplies each global start index for disjoint mutable whole-column slices.
For `index < leaves`, the preflight products bound `index * 32`,
`(index + 1) * rows`, and every copy. The immutable `MaskStream::fill_at` reads
exactly `[32*index, 32*(index+1))`; canonical words retain u32le row order.
No worker reads overlapping salt positions or writes another column. Borrowed
payload descriptors remain live while work runs and are dropped before return.

The new getter/output key records actual descriptor vector capacity times the
slice-reference size. It measures temporary host storage, not returned vector
ownership, process peak, or a complete device budget. Host RSS must include it.
The serial canonical scan, zero-fill and descriptor construction remain inside
assembly time. Existing output fields, root-only behavior, kernels, core APIs,
dependencies, transcript, proof bytes and profile scope are unchanged. The diff
does not consume the unmerged lookup, batch or inventory interfaces.

The new subprocess test compares every payload and authentication path against
production `PreparedSource`, checks out-of-range responses, exercises 0/1/p-1,
and executes the one-word `RootMismatch` control for each shape in each fresh
1/3/16-thread process. `ell6/m12` is included; comparing roots across processes
is additional evidence, not a substitute for complete payload/path checks.

Pending acceptance requirements are explicit, not code findings:

- E16-40f: “run explicit required-CUDA complete-source parity and actual
  production source-shape checks before measurement”; no actual H100 execution
  was reviewed here.
- E16-40f: “compare the unchanged baseline and candidate in three alternating
  cold-process pairs on one H100 allocation” at `ell11/m16`, including pinned
  threads, all transfers, assembly, whole wall/RSS and transient descriptors.
  Keep/revert must enforce “host assembly is at least twice as fast and complete
  GPU-command wall time is lower in every matched pair.” No local result grants
  this performance claim or whole-prover/ADR-127 GO credit.
- AGENTS.md/Workflow 12 require passing mandatory gates covering current main
  and the intended merge tree. CI 397 is the coordinator-designated full-suite
  route; this review neither duplicates it nor attests to its status or tree.

I tried to break it by changing one encoded payload word, and the control in
`matches_reference_complete_source_material` and its thread variant rejected it
with ordinary `merkle::Error::RootMismatch`. Incomplete encoding, incomplete
nodes and noncanonical M31 material were also rejected.

## Workflow 03 checklist

1. **Public items:** `assembly_descriptor_bytes()` is host-storage reporting
   under RFC-0014 §4/A1; assembly preserves RFC-0010 A9/A15 and RFC-0013 A2.
2. **Challenges:** none added or reordered; no transcript path changes.
3. **Claims:** none emitted or moved. The material remains an untrusted producer;
   ordinary Merkle verification authenticates responses.
4. **Bindings/controls:** no new binding. Existing one-word payload control
   rejects with `RootMismatch` in every complete-source comparison.
5. **Ledger/accounting:** no soundness ledger lines change by inspection.
   Soundness-accounting/native gates are not independently rerun here.
6. **Bounds:** no new relation or certificate instance. Source admission and
   checked size/offset arithmetic are static for each admitted source shape.
7. **Padding/masks:** no selector or padding changes. Whole real leaves preserve
   the source-salt context/id and canonical consecutive salt positions.
8. **Determinism:** no hash-map iteration or timing-dependent reduction.
   Independent disjoint writes; complete parity passed at 1/3/16 threads.
9. **Parity:** complete CPU source payload/path parity passed. H100 and
   prover-level CPU/SIMD/CUDA digests are not established by this review.
10. **Cost model:** targets source `c_c`/host assembly `T_misc`; no measured
    constant or gain is asserted. Matched hardware ledgers remain required.
11. **Verifier:** untouched; no new dependency, panic, length source or no_std
    change. `Material` grants no verifier authority.
12. **Glossary:** no forbidden synonym identified.
13. **Tier:** bounded research/development scope; no security level, privacy,
    profile promotion, complete device-budget or GO claim.
14. **Commit rule:** no new committed or virtual column.
15. **Plain checker:** independently ran all 27 relation tests, including honest
    relations and identity/matmul/lookup near misses; all pass.
16. **Segments:** no relation or carried-column access changes.
17. **Proof bytes:** production protocol/serialization unchanged by inspection;
    complete source bytes match the reference. Digest gate remains separate.
18. **Ladder:** no ladder gain claimed. Current-tree L0/L1 and mandatory gates,
    plus matched H100 source measurements, remain acceptance conditions.

## Exact independent commands and results

All commands ran from `/tmp/stele-codex-e16-40f` at the stated head.

```sh
env CARGO_TARGET_DIR=/tmp/stele-review-40f-spec-target CARGO_INCREMENTAL=0 cargo +1.90.0 test --manifest-path research/gpu-gating/masked/Cargo.toml --locked --test source_material -- --nocapture
```

Exit 0: 2 passed, 0 failed, 0 ignored. The thread test launches fresh 1/3/16
thread processes; each completes all three shapes and full comparisons.

```sh
env CARGO_TARGET_DIR=/tmp/stele-review-40f-spec-target CARGO_INCREMENTAL=0 cargo +1.90.0 test --manifest-path research/gpu-gating/masked/Cargo.toml --locked --lib source::material::tests::rejects_incomplete_or_noncanonical_material -- --exact --nocapture
```

Exit 0: 1 passed, 0 failed, 2 filtered out. An earlier command used the mistaken
exact filter `source_material::tests::rejects_incomplete_or_noncanonical_material`;
it ran zero tests and provides no evidence. The corrected command above does.

```sh
env CARGO_TARGET_DIR=/tmp/stele-review-40f-spec-target CARGO_INCREMENTAL=0 cargo +1.90.0 test -p stele-ir --locked --lib relation::tests::
```

Exit 0: 27 passed, 0 failed, 1 filtered out.

```sh
git diff --check 3c441a50d1becae9b9e5ea2d21a03b6c7677c84c...458186d944660befae928dca8c6736d57a150889
git status --short
```

Both exited 0 with no output. Read-only scope also inspected both
`Material::new` callers, the public export, example output, production
`PreparedSource` assembly, `MaskStream::fill_at`, and the existing pool helper.

Skipped duplicate workspace/native/fmt/Clippy campaigns and all GPU execution as
assigned. Remaining risk is unmeasured H100 benefit and pending current-tree
mandatory gates; this report does not authorize keeping a failed hypothesis.

Coordinator's validation note: CI966 is currently validating PR397, not this
candidate. PR401 requires its own current-main/intended-merge-tree mandatory
validation after its predecessors merge; that work has not started.

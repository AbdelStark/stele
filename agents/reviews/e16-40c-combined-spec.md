# Combined production reference — owning lane P spec/soundness review

**PASS for specification/interface scope; no blocking implementation finding.**
This approval does not replace the current-base mandatory gates or intended-merge-tree validation.
Reviewed as the independent owning lane P reviewer with `soundness-auditor`, Workflow 03, its checklist, Workflow 10, and Workflow 12. Tier: development. Repository and branches were not edited by this reviewer; this record is outside the repository at the coordinator's request.

## Fixed source and metadata provenance

- Worktree: `/tmp/stele-codex-e16-40c` (physical path `/private/tmp/stele-codex-e16-40c`).
- Base: `4954247f0d67c73f2bc0badc205491bdee93f8bf`.
- Initially supplied head and test source: `eec847e65d76a1fde2c7a266e5d42027612032b1`.
- Final reviewed head: `6df54c87c47162b158270980f50ace6b3d1c7d25`.
- Pre-consolidation head: `29852a4509f1a0a315c196b62ce7de40bc96b2ff`.
- Lookup implementation commit: `48d1e2bd37dacc6b73828181b6b0e1dd6c895e14`; batch implementation commit: `509298af34c2a44877b48d40a3e0237d99591126`.
- Lookup adapter blob: `08144baaa1e1e4fa29441c94753727f4d175f2e6`; batch adapter blob: `bc7360778d7946f05e79f155d66a8e6c4f168176`.
- Lookup test blob: `a74b0fa00645fc8a1ede407f4bc8012ceef2cda3`; batch test blob: `054a560aa4e89dba25a7833e6c725ac4f7b8ce8d`.

The full base-to-head diff is two bench-only adapters, their feature-gated module/export wiring, focused tests, measurement-scope notes, task metadata and review records. The two consolidation commits change only `agents/tasks/graph.yaml`. An independent `git diff --exit-code 29852a45...` comparison using the exact endpoints below confirms no source, test or method-document change. Focused test evidence therefore transfers to the final metadata-only head; binaries were not rerun without a source change.

## Requirements and findings

No missing implementation requirement, unrequested behavior or incorrect implementation was found.

E16-40c requires an “off-by-default bench-only adapter to the actual production lookup tree and committed-top construction.” `LookupCase` uses the ordinary complete statement plan, validates assigned column lengths and the selected lookup, and calls the existing tuple, table, selector, power, tree and top builders. Its top abort agrees with RFC-0008 A7 item 3: “A zero `q` entry at the top aborts the producer (`DenominatorZero`).” Exact leaves, numerator/denominator ordering, top values, selectors, shifts, member padding and extension compression are exercised. Canonical M31 input conversion uses the production embedding.

The carried batch requirement calls for the “actual production batch instance, weight-table and Y=0 face builders.” `BatchInputs::new` calls those functions. It rejects a non-hiding source before construction and validates counts and every position before the instance's zipped sum. Repeated positions accumulate, extension coefficients are retained, the mask-row half has zero weight, and the face retains source row/column order. RFC-0013 A5 item 5 specifies “over the source's row bit `w` and its data bits (`Y = 0` face)” and `W = Σ γ_a w_a`; the exact weighted-sum, Dense-round and final-value checks implement that oracle. A false claimed sum is intentionally not validated by the table adapter; ordinary sumcheck rejects it.

**Partial requirement evidence, not a demonstrated implementation failure:** E16-40c requires “keep default, bench, no_std, L0/L1 and mandatory gates green.” Focused tests and default/no_std builds pass in this review. Current-base formatting, Clippy, workspace, native/accounting/digest and L0/L1 checks, and the intended merge-tree run remain the coordinator's merge prerequisites. I did not execute or grant credit for them.

### Task consolidation and Workflow 12

The earlier two-active-task metadata conflicted with `agents/guardrails/code.md`: “one task per PR.” Final head `6df54c87` resolves that review concern: E16-40c carries both RFC sets and the entire substantive lookup/batch acceptance union. Its shared review/default/bench/no_std/L0/L1/mandatory-gate criterion covers the former batch gate line. E16-40e is explicitly blocked with acceptance carried by E16-40c, retains all original criteria/history, and is not marked done. The batch prerequisite E16-35 remains transitive through E16-40c → E16-36 → E16-35; both prerequisite tasks are done. RFC-0027 §6 says, “A superseded task is closed when its successor is done and every acceptance line that still applies is covered by the successor or moved to a named task.” The metadata preserves that closure obligation.

Consolidation **preserves Workflow 12 interface-first separation**. Workflow 12 requires an interface to be “reviewed by the lane that owns it, merged before any work that needs it.” This is one lane-V reference-interface task reviewed by owning lane P; neither device consumer is included. Both consumers explicitly wait for this interface's merge. The sole full merge-tree suite can validate the consolidated change; removing a duplicate future suite does not remove any acceptance or gate obligation.

## Workflow 03 checklist

- [x] **Public items / RFCs:** `LookupCase`, `LookupInputs`, `LookupTree` implement the production reference for RFC-0008 A7 items 2/3 and implementation notes. `BatchInputs` exposes RFC-0013 A5 item 5's instance and tables. All exports and adapter modules require the existing off-by-default `bench` feature. RFC-0014 §§1/4/5/A1 and RFC-0026 §7 constrain qualification and cost claims.
- [x] **Challenges / absorb order:** no challenge is added or drawn by either adapter. Synthetic beta/alpha/gammas are benchmark data. Unchanged production lookup order is committed early sources including multiplicities, `LookupStatement`, `LookupUnits`, then `LookupBeta` and `LookupAlpha`; the top source follows. Production batch coefficients still come from `Transcript::challenge(BatchCoefficient)` after relation instances. No caller routes benchmark inputs into the production transcript path.
- [x] **Claims / consumers / points:** no protocol claim is added or moved. Lookup output is precommitment tree/top material; unchanged top identity/sum and GKR/opening consumers remain. Batch `Instance.claimed_sum` is the ordinary weighted claimed sum, consumed by `Dense` in tests. Unchanged `verify_batch` evaluates its own weight at the sumcheck point and verifies the source value at that same point with Y=0 inserted at ell+1. These tables alone do not discharge the masking or authenticated-opening obligations.
- [x] **Bindings / controls:** no new binding, so no new NC id is required. `matches_reference_batch_tables_rounds_and_finals` changes one claim value and requires `RoundSumMismatch`. `rejects_batch_bench_invalid_weights_and_source` rejects count mismatch, the first mask-row position even with zero weight, `usize::MAX`, and a non-hiding source with `Statement`. Lookup malformed shapes/selection and zero-denominator tests reject as stated; one multiplicity near miss changes the tree numerator away from zero. These are focused adapter controls, not newly credited catalog controls.
- [ ] **Ledger / accounting gate:** no challenge, degree, query or soundness-accounting line changes by complete diff inspection. `soundness-accounting.sh` and ledger regeneration were not run by this reviewer; mandatory native validation remains required.
- [x] **Bound certificates:** no integer identity, bound certificate or profile parameter is introduced. Lookup validation uses the production plan and domain caps before assigned-column access. Batch dimensions come from the validated prepared source; its production instance remains degree two. No runtime witness-derived bound is introduced.
- [x] **Padding / masks:** unchanged helpers retain the public concatenated selector, shifts, member repetition/order, table denominator-one padding and zero multiplicity outside the original domain. Batch weights are zero on all w=1 positions, while the Y=0 face includes mask rows. Tests check every returned face value and row/column boundaries. No lookup or zerocheck selector changes.
- [x] **Determinism:** fixed slice traversal and production field arithmetic; repeated batch positions accumulate in claim order. No hash-map traversal, new thread scheduling or timing-dependent reduction order. Existing production parallel helpers are reused.
- [x] **Parity scope:** no GPU/SIMD algorithm or GPU source change. CPU reference-table/round comparisons pass; no CPU/CUDA or full-proof parity credit is established. RFC-0014 §5 remains mandatory for the future device consumers.
- [x] **Cost model:** no measured term, constant, weight-pass count, scoreboard cell, acceleration or GO decision is claimed. The named risk retired is a rewritten reference diverging from production. Measurement notes charge host preparation, table building, copies/transfers, retained material and host/device overlap; source preparation, rounds and authenticated openings remain distinct. No benchmark ledger is added or needed for a timing claim because none is made.
- [x] **Verifier:** untouched; `#![no_std]` and `#![forbid(unsafe_code)]` remain. No dependency, proof-selected length, verifier panic or bypass is introduced. Default and no_std+bench checks pass.
- [x] **Glossary / forbidden patterns:** no forbidden synonym or new unsafe code, float type, bypass, direct challenge generation, timing instrumentation or witness logging found in the added Rust source/tests.
- [x] **Tier:** development research reference only. No standard/treaty promotion, security level, zero-knowledge guarantee, complete device-memory bound, source acceleration or ADR-127 GO credit.
- [x] **Commit rule:** no committed or virtual column is added/reclassified. Adapter tables are explicitly witness data for benchmark callers, not public proof metadata.
- [x] **Plain checker:** independently ran all 27 `stele-ir` `relation::tests::` cases. Honest relations pass; identity, lookup, selected lookup, matmul and other near misses return their specified violations.
- [x] **Segments:** no relation or carried-column/earlier-segment access changes.
- [x] **Proof bytes:** production algorithms, transcript and serialization are unchanged by fixed-diff inspection. No amendment or pinned-digest update is needed for these adapters. Mandatory digest execution is still required and is not replaced by inspection.
- [ ] **Ladder:** no rung or before/after ledger comparison was run by this reviewer. L0/L1 and current-base/intended-merge-tree gate evidence are still required. No tables earn ladder capability, security or performance credit.

## Independent commands and results

All commands ran in `/tmp/stele-codex-e16-40c`. Toolchain versions were `cargo 1.90.0 (840b83a10 2025-07-30)` and `rustc 1.90.0 (1159e78c4 2025-09-14)`. The following Cargo checks were serialized and used the dedicated target directory; no workspace/native or hardware campaign was started.

```sh
env CARGO_TARGET_DIR=/tmp/stele-review-combined-spec-target CARGO_INCREMENTAL=0 cargo +1.90.0 test -p stele-reductions --features bench,std --test lookup_bench --test batch_bench --locked --offline
```

Exit 0: `lookup_bench` 5 passed; `batch_bench` 3 passed; none failed/ignored. Includes honest exact references, extension coefficients/compression, repeated positions, malformed inputs, DenominatorZero and the one-claim RoundSumMismatch.

```sh
env CARGO_TARGET_DIR=/tmp/stele-review-combined-spec-target CARGO_INCREMENTAL=0 cargo +1.90.0 test -p stele-ir --lib relation::tests:: --locked --offline
```

Exit 0: 27 passed, none failed/ignored; 1 unrelated test filtered out.

```sh
env CARGO_TARGET_DIR=/tmp/stele-review-combined-spec-target CARGO_INCREMENTAL=0 cargo +1.90.0 check -p stele-reductions --no-default-features --features bench --locked --offline
env CARGO_TARGET_DIR=/tmp/stele-review-combined-spec-target CARGO_INCREMENTAL=0 cargo +1.90.0 check -p stele-reductions --locked --offline
```

Both exit 0. These are build checks, not full default-feature test-suite claims.

```sh
git diff 4954247f0d67c73f2bc0badc205491bdee93f8bf...6df54c87c47162b158270980f50ace6b3d1c7d25
git diff --check 4954247f0d67c73f2bc0badc205491bdee93f8bf...6df54c87c47162b158270980f50ace6b3d1c7d25
git diff --exit-code eec847e65d76a1fde2c7a266e5d42027612032b1 6df54c87c47162b158270980f50ace6b3d1c7d25 -- crates research
git diff --exit-code 29852a4509f1a0a315c196b62ce7de40bc96b2ff 6df54c87c47162b158270980f50ace6b3d1c7d25 -- crates research
git diff eec847e65d76a1fde2c7a266e5d42027612032b1 6df54c87c47162b158270980f50ace6b3d1c7d25 -- agents/tasks/graph.yaml
```

The full diff and metadata diff were inspected. Whitespace check exits 0; both `--exit-code` comparisons exit 0 with empty output. `git merge-base 4954247f0d67c73f2bc0badc205491bdee93f8bf eec847e65d76a1fde2c7a266e5d42027612032b1` returned the pinned base. `git status --porcelain` was empty at the final reviewed head. Call-site search for `LookupCase|LookupInputs|LookupTree|BatchInputs` across Rust files in `crates research` found only adapters, their feature-gated reexports and tests; no device or production consumer.

I tried to break it by increasing one claimed batch value by one while preserving weights and source entries, and the control `matches_reference_batch_tables_rounds_and_finals` rejected it with `RoundSumMismatch`. I also forced a zero lookup top denominator and changed one plain-checker lookup value; `rejects_lookup_bench_zero_denominator` and `rejects_lookup_tamper` rejected them with `DenominatorZero` and `Violation::Lookup`, respectively.

Skipped cumulative workspace/native/L0/L1, formatting/Clippy, graph-test execution and GPU campaigns as assigned; coordinator evidence remains necessary before merge. Residual risk: exact reference tables alone establish neither bound masking, authenticated source openings nor integrated GPU proof parity.

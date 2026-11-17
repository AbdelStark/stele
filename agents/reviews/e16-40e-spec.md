# E16-40e — owning lane P specification and soundness review

Reviewed PR 400 with `soundness-auditor` and Workflow 03 against fixed diff
`8a3ac05133ebefff220d640b49367ff2fb68ba59...947efb52936bdf23e3ae970e949efd915e47d8d3`.
The reviewed commits are `b2ff4e27` (claim) and `947efb52` (adapter).

**PASS for the interface's specification scope; no blocking finding, missing
implementation requirement or scope creep found.** This is development research
support, not a GPU, authenticated-opening, complete-batch or proof-parity result.

E16-40e requires an “off-by-default bench-only adapter calling the actual
production batch instance, weight-table and Y=0 face builders.” `BatchInputs::new`
does exactly that, and the existing `bench = []` feature and crate-level
`no_std` remain unchanged. The source check precedes construction; the shared
weight builder checks equal counts and every position before the instance's
zipped sum. Zero coefficients or weights cannot hide an invalid position.
Repeated positions accumulate; the source face preserves row-major order and
mask rows, dropping the upper column half of each row.

RFC-0013 A5 item 5 specifies “over the source's row bit `w` and its data bits
(`Y = 0` face)” and `W = Σ γ_a w_a`. The inspected builders and exact table,
round and final comparisons match that contract. The adapter intentionally
accepts an inconsistent claimed value; its ordinary sumcheck rejects it.
Supplied coefficients are benchmark data, not proof challenges.

The task's “keep default, bench, no_std and mandatory L0/L1 gates green in stack
order” is only partially evidenced by this review: focused tests and both
builds pass; current-base L0/L1, workspace/native, formatting and Clippy gates
remain the coordinator's merge prerequisites. No new hardware campaign is
required by this adapter task. RFC-0014 A1's complete source, transfer and
device-allocation accounting remains an obligation of its subsequent consumer.

## Workflow 03 checklist and soundness record

- [x] Public items: `BatchInputs`, its three fields and `new` expose the existing RFC-0013 A5 item-5 instance and tables for RFC-0014 §1/§5 qualification. No production caller or wire item is added.
- [x] Challenges: none added or drawn by the adapter. Existing production `coefficients` still draws `BatchCoefficient` from `Transcript` after preceding relation instances; production absorb/order code is unchanged. Benchmark `gammas` cannot enter that path through this adapter.
- [x] Claims: the exposed `Instance.claimed_sum` is `Σ γ_a c_a`, consumed by ordinary `Dense` sumcheck in the tests. No protocol claim is emitted or moved. Existing `verify_batch` still checks the weight final with `expected_weight` at the returned point and discharges the source final through `verify_point` after inserting `Y=0` at `ell+1`; bound-mask obligations remain on the existing masked path.
- [x] Bindings: none added. `matches_reference_batch_tables_rounds_and_finals` changes one claim value and requires `RoundSumMismatch`. `rejects_batch_bench_invalid_weights_and_source` requires `Error::Statement` for count mismatch, the first mask-row position with zero weight, `usize::MAX`, and a non-hiding source. Existing NC-0911/NC-0915 cover source-opening/weight-final bindings; they were inspected, not rerun here.
- [ ] Ledger: no soundness line, challenge, degree or query changes by fixed-diff inspection. No ledger regeneration or `soundness-accounting.sh` run in this focused review; the mandatory native gate remains required.
- [x] Bound certificate: no new integer identity or certificate. The prepared-source constructor already validates geometry and lengths; the adapter's new trust-boundary checks reject non-hiding sources and invalid claim inputs. Degree remains two through the unchanged two-factor instance.
- [x] Padding/masks: the complete `w=1` half of weights is zero; the `Y=0` face retains mask rows. Exact comparison covers columns 511/512, the last data position 4095 and every face entry. No lookup or zerocheck selector changes.
- [x] Determinism: fixed slice traversal and field addition, with no map iteration, concurrency or timing-dependent order. Duplicate positions accumulate in claim order; extension coefficients are exercised.
- [x] Parity: no CPU/SIMD/CUDA algorithm or GPU code changes. Exact CPU builder/round/final comparisons pass. Hardware/full-proof parity is not established or claimed by this interface; no GPU parity gate is triggered by this diff.
- [x] Cost model: no measured term, speedup, pass count or scoreboard cell is claimed. The retired risk is a rewritten batch-preparation reference; documentation separates preparation, table construction, transfers, rounds and authenticated openings under RFC-0014 A1 and RFC-0026 §7.
- [x] Verifier: no verifier changes, dependencies, panic paths or proof-selected lengths. Default and `--no-default-features --features bench` builds pass; `#![no_std]` is unchanged.
- [x] Glossary: no forbidden synonym introduced. Forbidden-pattern scan of the added Rust files found no unsafe code, floats, bypass flags or direct challenge generation.
- [x] Tier: development research only. No security level, promotion, zero-knowledge guarantee or ADR-127 GO credit claimed.
- [x] Commit rule: no committed or virtual column added or reclassified; tables are explicitly benchmark witness data, not proof metadata.
- [x] Plain checker: all 27 `stele-ir` `relation::tests::` cases pass, including honest relations and one-value identity, lookup and matmul near misses. The batch-specific exact weighted-sum oracle and its claimed-value near miss also pass.
- [x] Segments: no relation, carried-column or segment-access changes.
- [x] Proof bytes: no production algorithm, transcript or serialization changes by inspection; no amendment or digest re-recording needed. This review does not substitute for the mandatory digest gate.
- [ ] Ladder: no rung or before/after performance comparison was executed by this reviewer. Current-base L0/L1 and intended-merge-tree gate evidence remain required before merge.

## Independently executed checks

All Cargo commands used `CARGO_TARGET_DIR=/tmp/stele-e16-40e-spec-target` and
`CARGO_INCREMENTAL=0`:

- `cargo test -p stele-reductions --features bench --test batch_bench --locked --offline`: 3 passed.
- `cargo test -p stele-ir --lib relation::tests:: --locked --offline`: 27 passed.
- `cargo check -p stele-reductions --no-default-features --features bench --locked --offline`: passed.
- `cargo check -p stele-reductions --locked --offline`: passed.
- `git diff --check 8a3ac05133ebefff220d640b49367ff2fb68ba59...947efb52936bdf23e3ae970e949efd915e47d8d3`: passed.

I tried to break it by increasing one claimed value by one while preserving all
weights and source entries, and the control
`matches_reference_batch_tables_rounds_and_finals` rejected it with
`RoundSumMismatch`. Invalid shapes, out-of-face positions and a non-hiding source
were rejected by `rejects_batch_bench_invalid_weights_and_source` with
`Error::Statement`.

Skipped cumulative workspace/native/L0/L1 suites and hardware execution as assigned.
Remaining risk: table equality alone does not establish masking, authenticated openings or integrated GPU proof parity.

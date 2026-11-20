# E20-01 / E20-02 soundness review: engine fast paths and the RFC-0026 A8 instance split

**Scope.** Commits `a06fea90` (E20-01), `adfb0e77` and `e987c911` (E20-02) on
`task/E20-02-lookup-fast-path`, read against their base `03a7b6b0`: `stele-ir` (`Values`),
`stele-sumcheck`, `stele-lookup`, the relation engine in `stele-reductions`, and the status line
of RFC-0026 A8. Specs read: RFC-0006 A1/A5, RFC-0008 A3/A5/A6, RFC-0026 §2.1, §4, A3, A8, A10,
A28, ADR-096, tasks E20-01 and E20-02. Line numbers below are at `e987c911`.

**Reviewer.** Independent `soundness-auditor` pass under Workflow 03; the reviewer wrote none of
the code. An internal agent review, not an external audit. Tier: development (RFC-0027 §2),
lane E. No security level is claimed or assessed.

## Verdict

**APPROVE.** No BLOCKING finding: no accepted false statement, no unbound value, no weakened
verifier check, and no proof byte that differs from the reference.

- Claim 1 (E20-01, bytes equal the all-extension reference): confirmed.
- Claim 2 (E20-02, unsplit bytes unchanged; the A8 control is rejected with `RootMismatch`):
  confirmed, with F1 and F2.
- Claim 3 (pinned L0/L1 digests unchanged): confirmed by running the digest gate.

F1 and F2 are MEDIUM. They complete the acceptance of A8, need no change to protocol code, and
should land in the same PR. Four LOW findings follow.

## Findings

**F1 (MEDIUM): A8 is marked Accepted without its Workflow 02 §5 records.**
- `docs/rfcs/RFC-0026-development-end-to-end.md:956` flips the status; `:983-984` names a
  control with no id.
- `docs/rfcs/RFC-0000-index-and-process.md:54` still lists "A7, A8 Draft".
- `agents/context/decision-log.md` has no ADR for the acceptance. ADR-096 (`:2084-2089`) says
  task E20-02 carries it and that control ids enter the catalogue at acceptance.
- `tests/negative-controls/catalog.md` has no row.
- The control is a unit test (`relation_tests.rs:3473-3516`) behind a `#[cfg(test)]` field
  (`relation.rs:614-618`), so the controls harness and its coverage report cannot see it.
- It replaces two multiplicity entries; unlike A10, the text states no INV-4 exception.

Requested:
- An ADR accepting A8 that cites this record, and the index line.
- An NC id, a catalog row and the catalog snapshot test.
- Either move the seam under the `controls` feature and run the control from
  `tests/negative-controls`, or state an A10-style relation-engine exception in A8.
- State in the ADR that A8 is implemented for the plain development engine, not dev-zk. A9's
  "Draft A8" sentence (`:989-991`) is Accepted text and must not be edited in place.

**F2 (MEDIUM): the segmented engine's split is untested, and the control does not reach the
verifier real proofs use.**
- `relation.rs:3354`, `:3579` and `:4629` have no caller in the range.
- The segmented multiplicity closure (`:4044-4048`) has no seam.
- `stele-prover/src/development.rs:751-776` and `:917` send every relation with virtual columns
  to the segmented engine. Since E18-05 that is every model.
- The segmented split arrived in `e987c911`, whose subject names only the tree-depth check.

I found no defect. Reviewer tests through `verify_segmented_with_instance_bound`, all passing:
- One-segment relation, `B = 2`, three source sets: accepted; sections equal the v1 proof's; an
  out-of-range value in the second block gives `RootMismatch`.
- The three-segment fixture (weights, carried columns, a matmul) at `B ∈ {1,2,3,4,30}`:
  accepted; bytes equal the default proof exactly when the plan is unsplit.
- A split `Linear` virtual member under a range at `B ∈ {1,2,3,30}`: accepted; an out-of-range
  sum gives `RootMismatch`.
- A selected lookup into a table smaller than the column's range at `B ∈ {1,2,3}`: every
  selected out-of-table entry is rejected, every unselected in-range value is accepted.
- The A8 control, using a four-line test-only copy of the v1 seam: the receiving instance
  keeping its old multiplicities, the sending instance keeping them, and both instances swapping
  vectors (jointly complete) each give `RootMismatch`.

Requested: add these tests, wire the seam (or its `controls`-feature form from F1) into
`prove_segmented_with_plan`, and name the relation-engine change in the commit message.

**F3 (LOW): `member_selected` in the segmented prover ignores `block_index`.**
`relation.rs:3945-3955`; the v1 copy (`:2313-2324`) was updated. Metric only
(`weight_elements_read`); wrong for a split member with a selector over a weight column.
Requested: the v1 expression.

**F4 (LOW): the commits' parity tests skip shapes the new code branches on.**
- `stele-sumcheck/src/parallel.rs:344`: the `fold_base` challenge is
  `QM31::from_i64(13) + QM31::from_i64(5)`, a base-field element.
- `parallel.rs:357-358` and `:383`: batch points and zerocheck coefficients are base-field
  embeddings; skip is 0 or 2 only; QM31 only.
- `stele-lookup/tests/tree.rs:119-121`: `b ∈ {m, m−1}` puts a weight on the root layer only, so
  `BaseLeafSummand` and the first-layer tables never see `left, right ≠ 1` for `m ≥ 2`.
- `tree.rs:244` and `:282`: the non-Boolean selector case uses base-field `α`, `β`.
- `relation_tests.rs:3305-3321`: `MatmulSummand` is compared with a `Dense` whose eq table the
  test builds by the same masking. `table_mixed` and `eq_shared` are never compared with the
  tables they replace.

Requested: add the reviewer's cases listed under question 1; all pass.

**F5 (LOW): `B` is a free argument, not a profile parameter.**
- Five public functions take it (`relation.rs:2117`, `:2130`, `:3085`, `:3579`, `:4629`).
- No proof byte selects it and every production caller uses 30, so nothing is unsound, but
  "plan-fixed" is a convention.
- `build_a8_checks` materialises `2^(m−B)` members (`:843`) before the instance cap is
  consulted (`:876`), and the v1 plan passes no cap (`:997`).

Requested: derive `B` from the source set or profile byte, or keep the `_with_instance_bound`
entry points `pub(crate)` until a second profile fixes a bound; bound the instance count before
expanding.

**F6 (LOW): hand-written summands restate the instance instead of checking it.**
- `MatmulSummand::round` ignores its `instance` argument (`relation.rs:2696`) and hard-codes
  `eq·lhs·rhs` in twelve near-identical arms (`:2696-2895`).
- `BaseLeafSummand` takes three coefficients from `i.terms` (`stele-lookup/src/tree.rs:715-717`)
  and hard-codes the factor layout.
- `Dense::round_into` contains `unreachable!()` (`dense.rs:245`).
- `VirtualBuf::from_i64` picks its storage from a scanned maximum (`relation.rs:1050-1058`).
  That is exact and no strategy eligibility depends on it, but RFC-0006 A5, which the commit
  cites, forbids inferring eligibility that way.

Today a mismatch can only make the honest prover fail its own round-sum or final check.
Requested: override `Summand::validate_instance` in both summands to compare the instance with
the hard-coded polynomial; return `PublicShape` instead of `unreachable!()`; add a comment on
`VirtualBuf` saying why the scan is not an eligibility test.

## What was checked

### 1. Byte identity

Every new prover path was compared with the reference on the same inputs, in QM31 and OM31 where
the code is generic. All comparisons were equal, including the transcript's next challenge.

| Path | Reviewer cases |
|---|---|
| `fold_base` | sizes `2^1..2^13`, transcript-drawn extension challenges (78) |
| `Dense::new_mixed` | 608 random instances: 0 to 12 variables, 0 to 5 inputs, 0 to 4 factors with repeats, constant terms, zero and extension coefficients, all-base, all-extension and mixed |
| `Zerocheck::prove_base_with_point` | 260: 0 to 9 variables, every skip 0 to 4 including `m = skip`, degrees 0, 1, 3, 4, an unused input, a zero coefficient |
| `Batch::prove_base_with_point` | 84: 0 to 13 variables, 1 to 5 claims, Boolean prefixes of every length, duplicate points |
| `BaseLeaves`, `build_base_levels`, `prove_built_base` | 8,580: `m` 0 to 9, every `b` 0 to `m` (weights on every layer), selectors in `{0,1}` and outside it, all-0 and all-1 selectors, `c` 1 to 3, `table_size` in {0, 1, 2, 16, 255, 256, 257, 300, 65536, 70000}, values inside, on the edge of and outside the table, and negative |
| `SelectedProduct::new_base` / `prove_base` | 180: `m` 0 to 9, `c` 1 to 3, all four base/extension pairings; same verdict from the base-selector verifier; `Selector` and `SelectorMismatch` errors equal to `new`'s |
| `table_mixed`, `eq_shared`, `MatmulSummand` | 600 random operand shapes (permuted, broadcast, fixed bits, non-shared free bits, 0 to 8 sumcheck variables) against a verbatim port of the base commit's `table` and `eq_table` |
| a prebuilt tree from other leaves | never yields a proof `verify_public` accepts (`m` 1 to 4) |

Relation engine, base commit against reviewed commit, same test code in both trees, FNV-1a over
every section:
- 354 proofs from 28 tests are identical: 66 from the 27 existing relation tests (controls,
  weights, segments, all three virtual kinds) and 288 from a generated set.
- The generated set is six relations of 4 to 32 rows. Each has ranges over 1 to 16 bit signed
  and unsigned widths, limb compositions up to signed 30, a three-factor identity, a masked
  identity, a selected two-column lookup through reversed `Ref`s, and four matmuls (shared bits,
  a broadcast operand, no summed bits, fixed-bit row blocks).
- Each relation was proved for eight witnesses (honest; an unsigned-8 entry set to `2^30`, `−1`,
  `256`, `65536`, `p+5`, `−2^40`, `p−1`), three source sets, and both containers. The verifier's
  outcome was equal in both trees for all 288.
- `p+5` is the field element 5 and is accepted by both trees.
- 521 proofs are identical at 1, 4 and 7 rayon threads.
- The digest gate on a tree byte-identical to `e987c911` reproduced the four pinned L0 and L1
  digests. Those proofs go through the segmented engine with virtual columns.

### 2. The A8 split

- **Who fixes the split.** `build_a8_checks` (`relation.rs:810-899`) takes the validated
  relation, the source set and `B`; `B` is `DEFAULT_INSTANCE_BOUND = 30` on every production
  path (`:902`, `:2113`, `:3081`, `:3351`, `:4625`). No proof byte reaches it. Prover and
  verifier call the same function.
- **Independence.** Each instance is a `Check` with its own id, multiplicity source id, tree,
  leaf and tuple ids. Every instance's multiplicity root is absorbed in step 3 before any
  identity draw. `start` (`relation_lookup.rs:244-273`) absorbs the instance statement and
  multiplicity identity, then draws `β, α` (`:260`). Nothing is shared between instances.
- **Block claims.** `route` (`:348-360`) sends a block's value to its column at
  `(bits(block) ‖ z_low)` through `restrict`; `sigma_base` and `originals_base` read
  `ref.index((block << m) | local)`.
- **Coverage.** On 12 random relations at `B = 1..6`, every (column, selector, position) lies in
  exactly one instance and every instance has at most `2^B` positions. Honest proofs verify; one
  out-of-table value gives `RootMismatch` at every bound.
- **Block binding.** With block 1 of the commitment holding 9 in an unsigned-2 column and block
  1's leaves, multiplicities and member values all taken from block 0's data, the opening
  rejects (`Pcs(ValueMismatch)`).
- **The control is not vacuous.** With the root equation (`relation_lookup.rs:544`) skipped for
  instance 1, `rejects_a8_member_value_moved_across_instance_boundary_without_multiplicity`
  fails because the verifier returns `Ok` on the forged proof, and the out-of-range witness
  above verifies.
- **Another bound.** Sizes are powers of two in descending order and at most `2^B`, so every
  instance of a target but the last is full and a target has `⌈T/2^B⌉` instances. Two bounds
  that split a target differently therefore give different counts, and the multiplicity
  sections miscount (`relation.rs:1425-1433`). Observed: `ProofShape` in 328 of 328 v1 pairs and
  in every segmented case.
- **At `B = 30`.** No member can be cut (`m ≤ 30`). A target of at most `2^30` positions gives
  the same single check, ids and name as before. Only a target the base rejected now splits.
- **Segment id window.** The segmented guard moved from the target count to the instance count
  (`relation.rs:876`). The largest multiplicity source id is `seg·2^16 + 65535`, still inside
  the segment's window.

### 3. The verifier

- `verify` and `verify_segmented` are the former bodies with the plan call and the `mle`
  argument type changed, and nothing else (function-level diff).
- `mle` (`relation.rs:1338-1348`) indexes instead of zipping. `Relation::validate` fixes a
  public column's length (`stele-ir/src/relation.rs:1071`) and every claim point has `log_len`
  coordinates, so no index leaves the column.
- `lookup::verify` (`relation_lookup.rs:528-619`) changes only `sigma_base`,
  `SelectedProduct::new_base` and the block bits in `route`. The root, table-denominator,
  member-sum and piece-sum checks and the openings are unchanged (`:544`, `:545`, `:557`,
  `:569`).
- `new_base` (`stele-lookup/src/selected.rs:121-150`) repeats `new`'s shape, Boolean-selector
  and incoming-claim checks; `finish` (`:215-243`) evaluates the selector with `mle_base`.
- Tree and sumcheck verifiers are untouched.
- No error-return site was removed in any changed file. No `unwrap`, `expect` or `panic!` was
  added outside tests; the one `unreachable!()` is on a prover path (F6).

### 4. Malicious-prover seams

- `skew`, `count_override` and `split` are `#[cfg(test)]`; `shift` is
  `#[cfg(any(test, feature = "controls"))]` (`relation.rs:611-626`). Every use is gated the same
  way or sits inside a `controls`-only function.
- The default and `--features controls` builds both compile.
- `cargo tree -e features` shows no `controls` feature for `stele-cli`, `stele-prover`,
  `stele-verifier` or the default workspace.

### 5. Field faithfulness

- `ColumnStorage::pack` uses `try_from` per native type and keeps `Vec<i64>` when any value does
  not fit (`stele-ir/src/relation.rs:361-395`). Unsigned native types are used only for unsigned
  widths. `at` widens with `i64::from`.
- The two `as` casts in `VirtualBuf::from_i64` follow a magnitude test.
- Every embedding is `M31::from_i64` (`rem_euclid`) followed by `mul_m31`, which equals
  `K::from_i64`.
- No code outside tests branches on the storage class.

## Review checklist

- [x] RFC section of each new public item: `ColumnSlice`, `Values::get` are RFC-0026 §2.1.
  `DenseTable`, `Dense::new_mixed`, `fold_base` and the two `prove_base_with_point` are prover
  strategies under RFC-0006 A1, admitted by A5's sentence on other input formats (A5's own text
  covers 16-bit tables and a prefix grid). `BaseLeaves`, `Built*Tree`, `prove_built*`,
  `new_base`, `prove_base` are RFC-0008 A3. `*_with_instance_bound` are RFC-0026 A8.
- [x] Challenges: no new label or draw. A split plan repeats RFC-0026 §4 steps 3 and 5 per
  instance, in instance order.
- [x] Claims: block member claims are consumed by the step-7 batch of their source or by the
  virtual-column reduction, at the point both sides derive in `route`.
- [ ] Control id for the new binding: none (F1). The binding is the A5 root equation, once per
  instance; the unit test catches its removal. It does not run through `verify_segmented` (F2).
- [x] Ledger: unchanged for unsplit plans. A split plan adds one LU, two RLC and three SC lines
  per instance, named `<table>/inst<i>`. `soundness-accounting.sh` was not run.
- [x] Bound certificate: none new; counts stay at most `2^30 < p` (`relation.rs:770-775`).
- [x] Padding: `σ = 0` and originals `0` on each instance's padding.
- [x] Determinism: no hash map, clock or RNG added; thread counts 1, 4, 7 agree.
- [x] Parity: no SIMD or CUDA code in the range; the CPU reference bytes are unchanged. The
  parity gate was not run.
- [ ] Cost model: no ledger in the range; the tasks' ledger criteria are open (INV-14).
- [x] Verifier: the default (`no_std`) build compiles; section counts and lengths come from the
  plan; no new panic site on proof bytes.
- [x] Glossary: the lint passes.
- [x] Tier: development; no level claimed. `B` is not tied to a profile (F5).
- [x] Commit rule: no column changes kind.
- [x] Plain checker: the 38 `stele-ir` tests pass with and without `std`.
- [x] Segments: instances are built per segment from that segment's members.
- [x] Proof bytes: unchanged for unsplit plans. Split plans are new bytes under A8 and have no
  pinned digest; none is needed at `B = 30`.
- [x] Ladder: L0 and L1 through the digest gate; no ledger pair to compare.

Workflow 03 development-tier questions: (1) ran, same decisions; (2) no column made virtual;
(3) the block claims above, discharged by sources whose roots precede every lookup draw; (4) no;
(5) no ledger pair in the range.

## Ran, read, not checked

**Ran** (release, at most four build jobs):
- `stele-sumcheck` (with `std`), `stele-lookup` and `stele-ir` suites.
- `stele-reductions --lib --features std,controls`: 192 passed, 1 ignored.
- The same relation tests and the reviewer's tests in the test profile (overflow checks, debug
  assertions).
- The reviewer tests above, the base-against-reviewed digest comparison, the three thread
  counts, and the mutation.
- `scripts/gates/check.py digest`, `rfc-status`, `docs-links`; the glossary and rust-policy
  lints; `cargo fmt --check` and `cargo clippy -D warnings` on the four crates' library targets;
  `cargo check` with default and `controls` features; `cargo tree`.

The digest instrumentation and reviewer tests were test-only additions to scratch copies. The
gates ran on a tree byte-identical to `e987c911`.

**Read only:** the RFC texts, `stele-prover`'s routing, the dev-zk plan's existence, the catalog
and the decision log.

**Not checked:**
- `cargo test --workspace` and `scripts/gates/native.sh` (the negative-controls suite and
  coverage, soundness accounting); the parity gate.
- `stele-prover`, `stele-cli` and `stele-verifier` suites beyond the digest producer; dev-zk end
  to end; the Python verifier on a split proof (none exists; at `B = 30` its inputs are
  unchanged).
- A check above `2^30` positions, the only split a development proof can meet: the split was
  exercised at `B ≤ 6` only.
- A relation-engine comparison with columns of one or two entries (0 and 1 variables are covered
  per primitive only).
- 32-bit targets.
- Performance, memory and the tasks' ledger criteria.

Two acceptance sentences, for the task owner, read stricter than the code:
- E20-01's "no dense extension-field table before the first sumcheck fold" holds for witness
  tables. The claim-batch coefficient table (`claim_batch.rs:228`), the zerocheck eq table
  (`zerocheck.rs:332`) and an operand with a non-shared free bit (`relation.rs:1643-1666`) are
  still extension tables before round 0.
- E20-02's "lookup instances run in parallel" describes the two trees of one instance and the
  operand tables of one matmul. Instances are proved one after another (`relation.rs:2501`,
  `:4199`).

## Workflow 03 sentence

I tried to break it by giving every base-field prover path the inputs most likely to split it
from the extension reference (0 and 1 variables, selectors outside `{0,1}`, values outside the
small-domain table, weights on the leaf layer, operands with fixed, broadcast and non-shared
bits, out-of-width and negative witness values), and no byte differed in any comparison. I then
tried moving a member value across an A8 instance boundary without its multiplicity, swapping
two instances' multiplicities, serving one block's claims from another block's data, selecting
an out-of-table value inside a split block, and verifying under another bound, through both
`verify` and `verify_segmented`. The control
`rejects_a8_member_value_moved_across_instance_boundary_without_multiplicity` (the receiving
instance's A5 root equation, `RootMismatch`), the source opening (`ValueMismatch`) and the
section count (`ProofShape`) rejected it.

## Resolution

By the author, in the commit that adds this record. The findings' line numbers are at
`e987c911`, before the stack was rebased; the reviewed patches are unchanged.

| Finding | Status | Change |
|---|---|---|
| F1 | Resolved | ADR-155 accepts A8 and states its scope (plain plans, not dev-zk). The RFC-0000 index lists A8 as Accepted. A8 names control NC-1341, where it runs and why (the A10 exception). The catalogue has the row, the registry the entry, the snapshot test the count. The multiplicity seam is under the `controls` feature. |
| F2 | Resolved | The seam is wired into `prove_segmented_with_plan`. NC-1341 runs from `tests/negative-controls` through the segmented verifier. The reviewer's tests are in `relation_tests.rs` (list below). |
| F3 | Resolved | The segmented prover's `member_selected` reads the selector at `(block index ‖ local)`. |
| F4 | Resolved | `crates/stele-sumcheck/tests/base_parity.rs`, `crates/stele-lookup/tests/base_parity.rs`, and `matches_reference_matmul_tables_of_the_all_extension_engine`. |
| F5 | Resolved in part | The `_with_instance_bound` entry points are `pub(crate)`; two are test-only. Under `controls`, `prove_segmented_forged_multiplicities` and `verify_segmented_under_bound` take a bound for NC-1341. Not changed: `B` is not derived from the profile byte (every profile uses 30), and `build_a8_checks` expands before the instance cap. With `B = 30` and `m ≤ 30` no member is cut, so nothing expands; task `E20-09` fixes the second bound. |
| F6 | Resolved in part | `MatmulSummand` and `BaseLeafSummand` override `validate_instance` and compare the instance with the polynomial they hard-code. `Dense::round_into` returns `PublicShape` in place of `unreachable!()`. `VirtualBuf::from_i64` says why its scan is not an eligibility test. Not changed: the twelve arms of `MatmulSummand::round`. |

Tests added from the review, under the repository's names:

- `accepts_a8_segmented_split_and_rejects_out_of_range_block_values`
- `accepts_a8_three_segments_under_small_instance_bounds`
- `rejects_a8_out_of_range_sum_of_a_split_virtual_member`
- `rejects_a8_selected_out_of_table_values_in_split_blocks`
- `rejects_a8_member_value_moved_across_instance_boundary_in_the_segmented_engine`
- `rejects_a8_block_claims_served_from_another_block`
- `matches_reference_a8_split_plans_cover_every_position_once`, which now asserts that a
  proof under another split is rejected with `ProofShape`
- `matches_reference_matmul_tables_of_the_all_extension_engine`

The reviewer's differential test against the base commit is not added: it needs a digest
hook in both trees.

The two acceptance sentences the review read as stricter than the code are reworded in
`agents/tasks/graph.yaml`:

- E20-01 now says "no dense extension-field witness table". The eq and coefficient tables
  and an operand with a non-shared free bit are tracked by the new task `E20-24`.
- E20-02 now says that the two trees of an instance and the operand tables of a matmul
  are built concurrently and that instances stay in transcript order.
- The proof-byte record at `B = 30` and `B = 23` moved to `E20-09`: the development
  profile fixes `B = 30`.

## Ledgers

Recorded after the review, each a singleton run on the reference class (Xeon Platinum
8480CL, 24 allocated CPUs, which are 12 physical cores; `bench/ledger/<name>.json`).
The proof bytes are the same in every run of a rung. `c_lu` here is the lookup stage's
wall time per lookup position.

| Rung | Ledger | Threads | Prove s | Lookups s | `c_lu` ns | Peak RSS GB | Verify s |
|---|---|---|---|---|---|---|---|
| L1 | `e18-05-dev-synthetic-8layer-24t` (before) | 24 | 14.30 | 5.63 | 449 | 1.55 | 1.47 |
| L1 | `e20-01-dev-synthetic-8layer-24t` | 24 | 16.78 | 7.24 | 577 | 1.46 | 2.03 |
| L1 | `e20-02-dev-synthetic-8layer-24t` | 24 | 13.54 | 4.76 | 380 | 1.22 | 1.67 |
| L1 | `e20-02-dev-synthetic-8layer-4t` | 4 | 18.08 | 7.56 | 603 | 1.10 | 1.30 |
| L1 | `e20-02-dev-synthetic-8layer-1t` | 1 | 30.31 | 14.69 | 1,172 | 0.93 | 1.47 |
| L2a | `e18-05-dev-stories42m-24t` (before) | 24 | 135.58 | 60.18 | 296 | 27.69 | 12.36 |
| L2a | `e20-01-dev-stories42m-24t` | 24 | 129.15 | 58.42 | 287 | 26.39 | 12.10 |
| L2a | `e20-02-dev-stories42m-24t` | 24 | 107.43 | 37.36 | 184 | 13.64 | 9.88 |
| L2a | `e20-02-dev-stories42m-4t` | 4 | 342.95 | 119.13 | 585 | 13.44 | 15.57 |
| L2a | `e20-02-dev-stories42m-1t` | 1 | 676.67 | 243.77 | 1,198 | 13.39 | 19.65 |

What they show:

- **E20-01 alone is slower on L1** (14.30 s to 16.78 s) and 5% faster on L2a. Its gain
  is memory on L2a (27.7 GB to 26.4 GB); the time comes with E20-02.
- **E20-02 halves the L2a peak RSS** (26.4 GB to 13.6 GB) and takes the lookup stage
  from 58.4 s to 37.4 s.
- **Parallel efficiency is low.** `T_1 / (n · T_n)` of the whole prove on L2a is 49% at 4
  threads and 26% at 24 (52% per physical core); of the lookup stage 51% and 27%. On L1
  it is 42% and 9%. Serial stages outside the engine (witness, model commitment) are
  part of it; they are not this task's.

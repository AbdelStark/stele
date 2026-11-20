# Soundness Audit Review — byte-identical prover speedups (tasks E18-10, E19-09, E20-23, E22-10, E22-11)

- **Tasks:** `E18-10` (lane P), `E19-09` (lane C), `E20-23` (lane E), `E22-10` and `E22-11` (lane N)
- **Audited commits:** the 16 commits `f1d68a6c..d2bca7e4` of `task/E22-10-capture-single-pass`. Line numbers are those of `d2bca7e4`.
- **Branch state:** the branch was rewritten during the review and is now at `62b06745`. See "After the audited head".
- **Reviewer:** independent `soundness-auditor` agent; did not write the change
- **Claim under review:** every commit leaves every proof byte, every public byte and every verifier decision unchanged, on every thread count and host
- **Governing specs (as cited by the commits):** RFC-0003 §§1, 6; RFC-0004 A15; RFC-0006 A1, A2; RFC-0008 A3, A5; RFC-0025 §§2.4, 2.5; RFC-0026 §§3.2, 5; RFC-0028 §2.1; RFC-0029 §§1.2, 1.3. INV-3, INV-5, INV-8
- **Tier:** development
- **Verdict:** **CHANGES REQUESTED**

## Summary

I found no proof byte, public byte or verifier decision that differs on an honest input.

- The six pinned L0 and L1 proofs reproduce at 1, 7 and 16 threads.
- The seven pinned L0 windows reproduce at each of the 16 commits.
- The `stele` binaries before and after the change write the same public and proof files on 35 flag combinations, and print the same verdict on 270 tampered files.
- Every new kernel equals its reference on every shape I tried.

The verdict is CHANGES REQUESTED for one defect and three gaps:

- **F1 (BLOCKING).** The guard in the new contraction kernel that chooses between int32, int64 and the checked wide loop multiplies without a check. For two operands whose magnitudes multiply past 2^128 it panics in the test profile and returns zeros in a release build. The code it replaced returned `Error::Capacity`, and the plain checker's answer to that near-miss changes with it. Only a witness far outside its declared widths reaches it, so no honest proof and no verifier decision is affected.
- **F2 (MEDIUM).** Five new code paths have no reference test that reaches them. Mutants of them pass the owning crate's tests, and three of the five also pass the pinned proofs.
- **F3 (MEDIUM).** `peak_codeword_bytes` is now computed from the thread count instead of observed, and undercounts when a row transform itself runs on the pool.
- **F4 (MEDIUM).** The five tasks are marked `done`, but the ledgers and the L2a comparison their acceptance lines name are not in the range.

Four LOW findings follow them.

## Scope

1. `stele-lookup/src/tree.rs`, `selected.rs`: `Layer`, `LayerSummand`, `BaseLeafSummand`, `SelectedSummand`
2. `stele-sumcheck/src/parallel.rs`, `claim_batch.rs`: four pieces per thread, `eq_table_scaled`
3. `stele-ir/src/relation/contract.rs`, `index.rs`, `check.rs`; `stele-reductions/src/relation.rs`, `relation_recursive.rs`
4. `stele-code/src/lib.rs`, `stele-pcs/src/recursive.rs`
5. `stele-field`: `Field: Send + Sync`, `#[inline]`, `M31::mul_m31`, `M31::from_i64`
6. `stele-cqis`: `execution/data.rs`, `model/rotary.rs`, the `std` feature and its wiring
7. `stele-prover/src/development.rs`; `stele-reductions/src/development/projection.rs`, `relation_lookup.rs`
8. `agents/tasks/graph.yaml`, `scripts/gates/check.py`

## Evidence labels

- **[ran]**: executed on `git archive` exports of `f1d68a6c` ("before") and `d2bca7e4` ("after") outside the repository. Host: aarch64 macOS, 16 CPUs, rustc 1.90.0. Release is fat LTO with no overflow checks; the test profile is optimised with overflow checks and debug assertions on.
- **[read]**: established by reading only.

Instruments, in the scratch copy only:

- **Parity and reference tests**: one test file per crate comparing a new kernel with its reference.
- **Differentials**: one test file that prints digests, run on both exports, with and without the pool, at several thread counts.
- **Mutants**: one changed line each. A mutant *survives* a test set when every test still passes.
- **Instrumented runs**: a worker count and a fault position read from the environment in `rotary.rs`, and a counter of live block tasks in `recompute_queried_columns`. Each was restored from git afterwards.

## What holds

### 1. The factored sumcheck strategies equal the dense one [read; ran]

A layer instance is `eq·(left·p0·q1 + right·p1·q0 + γ·q0·q1)` over tables indexed leading coordinate first.

- **State.** After `j` folds at challenges `c`, the dense `eq` table entry for leading bit `b` and suffix index `x'` is `eq(r[..j], c) · eq(r_j, b) · eq(r[j+1..], x')`. `Layer` keeps the three factors apart: `scale`, the line `eq_line(r_j, X) = (1 − r_j)(1 − X) + r_j·X`, and `suffix`.
- **Round.** The dense round polynomial is `g(X) = Σ_x' E(X, x')·T(X, x')`, each table interpolated between its halves. With `E` factored, `g(X) = scale · eq_line(r_j, X) · Σ_x' suffix[x']·T(X, x')`.
- **Three sums.** `T` is bilinear in `(p0, q0)` and `(p1, q1)`. Along the line it is `t(0) + X·(t(1) − t(0) − ℓ) + X²·ℓ`, where `ℓ` is `T` on the differences of the halves. The suffix-weighted sums of `t(0)`, `t(1)` and `ℓ` give `g(0..3)` (`tree.rs:211-225`). Nothing in this uses `left = right = 1`; the unit branch (`tree.rs:264-268`) is the same expression.
- **Binding.** `eq(r[j+1..], ·)` summed over its leading coordinate is `eq(r[j+2..], ·)`, because `(1 − r) + r = 1` (`tree.rs:227-236`). `scale` picks up `eq_line(r_j, c_j)`.
- **Zero and one variable.** With no variable no round runs, and the finals are the four single entries and `scale = 1`. With one, `suffix = [1]` and stays `[1]`.
- **Handoff** (`tree.rs:552-626`). The first round forms the same three sums with selectors in M31. The fold writes `a + c·(b − a)` into four half-length tables, sets `scale = eq_line(r_0, c)` and halves the suffix, which is `Layer`'s state for `r[1..]`.
- **Selected product** (`selected.rs:58-170`). `T = σ·V` with `V = Σ_j β^j x_j`, both linear along the line, so `ℓ = (σ_b − σ_a)(V_b − V_a)`.
- **Bytes.** The arithmetic is exact on canonical limbs (`m31.rs:5`), so equal elements are equal bytes.
- **Failure mode.** A wrong strategy cannot emit other bytes silently. `round_payload` checks `g(0) + g(1)` against the running claim, `finish_payload` checks the finals, and `advance` and `finish` check the `eq` final. It aborts the prover.

What the existing tests reach:

- `tests/tree.rs:119-121` covers `m ∈ {0, 1, 2, 5}` with `b ∈ {m, m − 1}`, so a round only ever sees unit weights.
- `tests/tree.rs:268-326` covers selectors outside {0, 1} at `m = 2`.
- `tests/selected.rs:103-109` covers `m ∈ {0, 1, 4}` at `c = 2` only.
- `prove_built` is never compared with `prove` directly. See F2.

My comparison [ran], against `prove` (dense) in QM31 and OM31 at 1, 2, 7 and 16 threads:

- Trees: `m = 0..7` with every `b ∈ 0..=m`, and `m ∈ {11, 13}` with `b ∈ {0, m − 2, m}`. Unit coordinates were random, Boolean or mixed; selectors Boolean, arbitrary or mixed; denominators included zeros. Compared: `prove_built`, `prove_base_leaves` General at `c = 1, 2, 3`, and SmallDomain at table sizes 16, 300 and 70,000.
- Selected products: `m = 0..7, 11, 13`, `c = 1, 2, 3`, `β` zero, one and random.
- 2,592 proofs, reductions and next challenges equal per thread count.

### 2. Integer arithmetic [read; ran]

- **`contract.rs`, int32 path.** Every partial sum is at most `bound(a)·bound(b)·n_sum ≤ i32::MAX`. `narrow()` is exact whenever the other bound is non-zero, and when a scanned bound is zero every product is zero. Worst inputs, run with overflow checks on:
  - `i8·i8`: `(−128)²` over 2^16 terms is 2^30 and stays int32; 2^17 terms go to int64.
  - `u8·u8`: `255²·2^15 = 2,130,739,200` stays int32.
  - `i16·i16`: one term of 2^30 stays int32; two terms go to int64.
  - `u16·i8`: up to 2^8 terms stay int32.
  - Scanned types on both sides of 2^31 and 2^63.
  - Random shapes of 1,024 outputs, which split on the pool.
  - All equal an i128 reference. The exception is F1.
- **`data.rs:162-177`.** Codes are in `[−127, 127]` (`row.rs`, `Error::Range`) and weights in `[−128, 127]`. A group size is a power of two below, and dividing, a row of at most 16,384 (`bounds/arithmetic/flow.rs:53`), so it is at most 8,192. The group sum is at most 133,169,152, below 2^27, and no wrap is possible. The same rule makes `chunks(g)` yield one chunk per scale. A mutant reading the weights as unsigned is killed by the `stele-cqis` suite and by the pinned grouped window.
- **`M31::from_i64` (`m31.rs:80-88`).** Inside `(−p, p)` the value, plus `p` when negative, lies in `[0, p)`; `±p` and beyond take `rem_euclid`. Checked in both profiles on 2^17-wide windows around 0, ±p, ±2p, ±2^32 and ±2^62, at both ends of `i64`, and on 6·10^6 random values. `mul_m31` equals the trait default on M31, CM31, QM31 and OM31 over 200,000 random and edge values.

### 3. Determinism [ran; grep]

The added lines contain no float, hash map, clock, environment read, `unsafe` or shared mutable state. Every parallel write has one writer per slot, and every reduction is an exact field or integer sum added in piece order.

| Check | Thread counts | Result |
|---|---|---|
| Six pinned proofs (`dumps_development_digests`) | after: 1, 7, 16; before: 3 | all equal `tests/digests/development.json` |
| `scripts/gates/digest.sh` | 16 | pass |
| `stele-cli --test stages` (release) | 1 against 2 | pass |
| `accepts_one_layer` (11 tests), `accepts_recursive_profile_6` (release) | 16, 1, 7 | pass |
| Each of the 16 commits: build, then 7 pinned L0 windows (test profile) | 16 | every commit builds without warnings and passes |
| 36 whole codewords, `CircleCoeff` and `Circle`, N from 2 to 2^19 | before and after; no pool; pool at 1, 2, 7, 16 | 10 of 10 runs identical |
| 8 certified sources, 2 to 1,024 rows, N_0 up to 2^16: certificate, opening, next challenge | same 10 runs | 10 of 10 identical; every opening verifies |
| Rotation digest | 1, 2, 3, 7, 16, 40 workers (emulated) | identical |

Two outputs depend on the machine and neither is a proof byte: `peak_codeword_bytes` (F3) and the number of rotation workers.

### 4. The verifier [read; ran]

`crates/stele-verifier` has no changed file. It depends on `stele-field` and `stele-hash` only, so it sees the `from_i64` fast path, the `mul_m31` override, `#[inline]` and the `Send + Sync` bound.

The development-tier verifier runs more changed code than the review request lists:

- **The circle transform.** `CircleCoeff::encode` now goes through `encode_into_with` and `forward_butterflies`. It is called by `verify_fresh_at_point_inner` (`recursive.rs:1697`), `verify_certified_registration` (`3196`), `verify_certified_opening` (`3419`) and `verify_joined_tail` (`5316`). `Circle::encode` reaches `forward_butterflies` too.
- **The pool's piece count** (`parallel.rs:47-54`), under `eq_table` and `sum_ranges`, for example in `SelectedProduct::finish` (`selected.rs:347-359`).
- **`Rotation::data_digest`**, through `Registry::new` in `decode(public)` (`development.rs:147`), which `verify` calls (`development.rs:1006`). Its output enters `cqis_id` in the first transcript frame, so it is a public byte as well.

Unchanged: `Relation::validate`, `Batch::coefficient`, `stele_sumcheck::verify`, `Descriptor::verify`, `SelectedProduct::verify`.

Decisions [ran]:

- Each tree's `verify-dev` accepts the other tree's proof on 9 windows: bytes 3, 5 and 6, segmented, grouped, wide GQA, T = 1 and 8, and a window without `next`.
- On 270 one-byte tampers of those proofs and public files, both binaries print the same last line and accept none. A sample of the reasons, both binaries agreeing: `Container(Header)`, `Engine(Sumcheck(FinalEvaluationMismatch))`, `Engine(Recursive(Merkle(RootMismatch)))`, `StatementMismatch`.
- `cargo test -p stele-negative-controls --all-features`: 148 passed, 4 ignored.
- `check.py native`: pass, including the independent verifier corpus decisions.

### 5. Row transforms and column recomputation [read; ran]

- **Butterflies.** For blocks wider than 4,096 the split pairs `low[j]` with `high[j]` and reverses afterwards. The loop reverses first and pairs `j` with `width − 1 − j`. Both leave `low[j] + t_j·high[j]` at `j` and `low[j] − t_j·high[j]` at `width − 1 − j`.
- **Direct placement.** Slot `j` receives `row[rev(j)]` when `rev(j) < 2^m` and zero otherwise, which is the padded row after the swap pass.
- **`log == 0`** (`lib.rs:251`) is unreachable: `CircleCoeff::new` requires `b ≥ 1`. It would agree with the old early return. The smallest reachable case, `m = 0, b = 1`, is equal.
- **Twiddles** depend on `m + b` only. `encode_into_with` compares the level count with `m + b`. A set of another size returns `Error::RowShape`; a set from another `(m, b)` of the same sum is the same set and gives the same codeword.
- **`encode_into_with`** equals `encode` and an independent basis-factor evaluation of every column, for `m = 0..9` and `b = 1..4`, in M31 and QM31, into a buffer still holding another shape's codeword.
- **`recompute_queried_columns`.** Each block of 128 rows owns its 4-byte slots of every queried column, and the layout is the old one. Rows are powers of two, so only a source of fewer than 128 rows has a short block.

### 6. `Rotation::data_digest` [read; ran]

- A coefficient depends on `(rotation, position, pair)` only; the generator's caches memoise pure values. Blocks are hashed in position order and only the filled prefix of a buffer is hashed.
- `Rotation::decode` admits widths 2 to 16,384 and lengths 1 to 2^20, so a row is never empty.
- Against the replaced algorithm rebuilt from the public `Rotation::coefficient`: 39 digests at lengths 1 to 2,065 crossing every block and round boundary, families 0 and 2. All equal without `std`, with it, and at 1, 2, 3, 7, 16 and 40 workers.
- A worker error at the first block, a middle block, the second round or the last position is returned as that error. Panics are F6.

### 7. `next` from the generation loop [read; ran]

The loop's logits are used only when generation ran, `--next` is absent and the window ends at T, that is `--checked` ends at the supplied length or at T. Otherwise the old `executor.full` path runs.

- **Value.** `step` and the full pass call the same `project` and `finish_block`. The full pass also scores later keys, but `attend` takes the maximum over `[..=position]`, gives later keys weight 0, and a block of zero weights rounds to 0 (`attention.rs:126-165`). At the last position the key sets are equal anyway.
- **Failure.** If the full pass would fail where the steps did not, `executor.capture` runs it on the same tokens right after (`development.rs:723`, `1426`, `zk.rs:926`), so the outcome is still `Error::Witness`. If the two values ever differed, the plain check, which runs unless a test hook is installed, refuses with `Check(…)`. The verifier is unchanged, so a wrong statement cannot be proved.
- **Flags.** 35 combinations of `--tokens`, `--length`, `--checked`, `--next`, profiles 3, 5, 6, segmented, grouped and wide GQA gave the same exit code, verdict lines with counters, `public.bin` and `proof.bin` from the binary before (3 threads) and after (5 and 1 threads). 21 wrote a proof and 14 were refused identically.
- **Loop against full pass.** In the binary after the change, a generated window (`--tokens 1 --length 16`) and the same 16 tokens supplied produce identical public and proof bytes, for bytes 3 and 6.

## Findings

### F1 — BLOCKING (E18-10 acceptance line 1; Workflow 03 question 1): the kernel's guard can wrap

`crates/stele-ir/src/relation/contract.rs:80`:

```rust
let magnitude = u128::from(bound(a)) * u128::from(bound(b)) * n_sum as u128;
```

The bounds are at most 2^63 each, so the product can pass 2^128. The replaced code used `checked_mul` and fell to the checked i128 loop (`Error::Capacity`).

Failing input [ran]: `free = 0`, `summed = 2`, both refs `Ref::identity(_, 2)`, both operands `ColumnSlice::I64(&[i64::MIN; 4])`. The definition's value is 2^128. `[±2^62; 16]` at `summed = 4` behaves the same.

| | `contract` | `check` on a validated relation with that witness |
|---|---|---|
| Before | not present; the engine returns `Error::Capacity` | `Err(Range { "a range", 0 })`, or `"c range"` when the virtual column's range is declared first |
| After, test profile | panic at `contract.rs:80:21`, "attempt to multiply with overflow" | panic |
| After, release | `Some([0])` | `Err(Range { "a range", 0 })` in both orders: the virtual column was materialised as 0 |

- **Reach.** The condition is `log2 bound(a) + log2 bound(b) + summed ≥ 128`. Columns within their declared widths stay below 2^90, so no honest proof is affected. A weight operand (int8) cannot reach it either.
- **Who can reach it.** Two witness operands held in the `I64` fallback storage, which `relation.rs` keeps for tests and controls that assign out-of-range values. `check` resolves virtual columns before it evaluates ranges (`check.rs:357-375`).
- **Effect.** The plain checker no longer decides this near-miss the same way, and `contract` breaks its own contract ("`None` when a sum may leave `i64`"). The verifier is not involved.
- **Fix.** Use `checked_mul` twice and return `None` on overflow. Add `[i64::MIN; 4]` at `summed = 2` to `rejects_sums_past_i64_and_indices_past_the_column`, whose largest case (`i64::MAX`, `summed = 1`) sits just below the wrap.

### F2 — MEDIUM: five new paths without a reference test

| Mutant | Line | Owning crate's suite | Pinned L0/L1 proofs and grouped window | My reference |
|---|---|---|---|---|
| M1: `Layer::round`, non-unit weights, `right` → `left` | `tree.rs:270` | survives | survives | killed |
| M3: `BaseLeafSummand` first round, `right` → `left` | `tree.rs:527` | survives | survives | killed |
| M4: `SelectedSummand`, one column, lead term | `selected.rs:81` | survives | killed | killed |
| M-rot: rotation blocks hashed in reverse within a round | `rotary.rs:263` | survives (`stele-cqis`, 166 tests) | survives | killed |
| M-hist: later histogram pieces skip a position | `relation_lookup.rs:180` | survives (`stele-reductions`, 284 tests) | survives | killed once pieces are 256 positions |

Mutants the existing tests do reject: the unit-weight layer term, the multi-column base round, the folded rounds, `halve_suffix`, the grouped dot, and a histogram counting into row 0.

- **(a) Non-unit weights in a round (M1, M3).** No test reaches them, and no production caller either: `relation_lookup.rs:305-307` builds both trees with no unit coordinates. The code is live through `prove_built` and `prove_base_leaves`.
- **(b) One column (M4).** Its own branch (`selected.rs:71-81`), tested only end to end. Three columns are untested in the crate.
- **(c) `prove_built`.** No direct comparison with `prove`; `tests/tree.rs:237` only rejects a wrong depth.
- **(d) Rotation past one block (M-rot).** `rotary-data.json` has lengths 33 and 1, and the longest rotation in `synthetic-e2e.bin` is 64 rows. The digest is a public byte (item 4).
- **(e) Histogram past one piece (M-hist).** No lookup block in the suite or in L0/L1 exceeds 65,536 positions. With `HISTOGRAM_PIECE` set to 256 in the scratch copy all six pinned proofs still match, so the code is right. It is untested at the shipped size.

Requested tests:

- The tree parity over every `b ∈ 0..=m` through `prove_built` and `prove_base_leaves`.
- The selected parity at `c = 1` and `c = 3`.
- A per-row rotation reference at lengths 63, 64, 65, 129 and across one round.
- A `counts` test on a block longer than a piece, against the generic path.

The E20-23 acceptance line "its messages equal the dense strategy's on the existing parity tests" is true and weaker than it reads.

### F3 — MEDIUM: `peak_codeword_bytes` is computed, depends on the thread count and can undercount

`crates/stele-pcs/src/recursive.rs:2766-2787` reports `(resident + 1)·N_0·4 + payloads`, with `resident = rayon::current_num_threads().min(block_count)`.

- **Thread-dependent.** For the E19-05 shape it is 89,088 B at one thread or without the pool, and 105,472 B at two or more.
- **Not an upper bound.** When `N_0 ≥ 2^16` the row transform itself runs on the pool, and a worker waiting on it starts another block. Counted with a live-task counter [ran]:

| N_0 | Rows | Blocks | Pool threads | Row buffers live at once | Reported |
|---|---|---|---|---|---|
| 2^12 | 256 | 2 | 1 | 1 | 1 |
| 2^12 | 256 | 2 | 2, 4, 16 | 2 | 2 |
| 2^16 | 512 | 4 | 4, 16 | 4 | 4 |
| 2^16 | 1,024 | 8 | 4 | **5** | **4** |
| 2^16 | 1,024 | 8 | 16 | 8 | 8 |

- **The memory invariant itself holds.** There is one buffer per block of 128 rows, so row scratch is at most 1/128 of the codeword.
- **What the E19-05 test still means.** `tests/recursive.rs:1083` checks the formula's arithmetic on a shape with two blocks and `N_0 = 4,096`. There the bound of 131,072 B holds at any thread count and nesting cannot occur. It no longer observes an allocation.
- **Fix.** Report the structural bound `(block_count + 1)·N_0·4 + payloads`, which does not depend on threads and never undercounts, or count live buffers. Also correct the field's comment (`recursive.rs:2622`, "`1` row + `q_open` columns").

### F4 — MEDIUM (INV-14; Workflow 03 question 5): tasks are `done` without the evidence their acceptance names

`agents/tasks/graph.yaml:4245`, `4398`, `4811`, `5167`, `5184` set all five tasks to `status: done` on the branch. The range adds nothing under `bench/`, and no ledger there names these tasks. Open lines:

- E18-10: "L2a prove time before and after in ledgers".
- E20-23: "the L2a proof has the same bytes before and after on two hosts", and the times "in ledgers".
- E22-10: "public and proof bytes unchanged on … L2a".
- E22-11: "verify time on L2a before and after".

The commit messages in the range state no number. Land the ledgers and the L2a comparison, or leave the tasks `in_progress`.

### F5 — LOW: the row-contiguous path has an unchecked precondition

`contract.rs:86-93` treats an operand as contiguous when its first `summed` index bits read the summed domain bits. It does not check that no higher index bit reads one too.

- Example: `vars = [0, 0]` with `free = 0`, `summed = 1`, `a = [1, 10, 100, 50]`, `b = [1, 1]`. The definition gives 51; `contract` returns 11 [ran].
- `Relation::validate` forbids a repeated bit, so `check` and the engine are safe. `eval_column` (`check.rs:209`) does not validate, and the loop it used before was exact for any `Ref`.
- Fix: check it in `low`, or state the precondition in the doc comment.

### F6 — LOW: rotation workers

- **Panics** (`rotary.rs:247-258`). A worker panic comes back as `Error::Capacity`. If an earlier block returned an error first, `scope` re-raises the panic instead [ran both]. The build without `std` panics in both cases. The pool helpers of `stele-sumcheck` propagate worker panics; do the same here.
- **Worker count** (`rotary.rs:227`). It comes from `available_parallelism`, not the pool. A run pinned with `RAYON_NUM_THREADS` still uses every CPU for the registry digest, which matters for a ledger that states a thread count.
- **Buffers** (`rotary.rs:230-235`). They are allocated for every worker whatever the length: 2 MiB per CPU at width 16,384, even to hash one row.

### F7 — LOW: `prove_base` narrowed, and two stale comments

- `selected.rs:386` returns `SourceShape` for a product built with `new` (extension selector). Before, it proved. No caller in the repository does this.
- The comment at `selected.rs:376-378` still names `Dense::new_mixed`.
- `recursive.rs:2622`: see F3.

### F8 — LOW (RFC-0027 §5, Workflow 12): one branch across lanes

The stack carries lanes P, C, E and N and a `scripts/` change (lane B). It adds `contract` and `Indexer` to `stele_ir::relation`, a listed lane interface, inside the stack. `Field` gained `Send + Sync` with no ADR. This is for the integrator to weigh.

Notes that are not findings:

- `matches_reference_basis_factors_on_a_long_row` runs the split only when `stele-code` is built with `std`. That holds in the workspace build, not under `cargo test -p stele-code`.
- A `Twiddles` of another size is reported as `RowShape`.
- The scan in `contract.rs:36-44` chooses an accumulation width in the prover and the plain checker. It is not a bound certificate and no verifier reads it.

## Review checklist

- **RFC section of each new public item:** `relation::contract` RFC-0028 §2.1; `relation::Indexer` RFC-0026 §3.2; `CircleCoeff::twiddles`, `encode_into_with` and `Twiddles` RFC-0029 §1.2 (commit message; the items cite none); `parallel::eq_table_scaled` RFC-0006 A1/A2; the `stele-cqis` `std` feature RFC-0025 §2.4. `rfc-status` passes on 2,067 references [ran].
- **Challenges:** none added, moved or relabelled; no absorb or label appears in the diff [grep].
- **Claims:** none added or moved; the factored strategies return the same finals in the same input order.
- **New bindings:** none, so no new control is due.
- **Ledger and accounting:** no line changes; `check.py native` passes, accounting included [ran].
- **Bound certificate:** no new instance; `Relation::validate` is untouched.
- **Padding and masks:** unchanged; the histogram skips unselected positions as before.
- **Determinism:** see item 3; F3 is the one thread-dependent value.
- **Parity:** CPU proofs equal the pins. SIMD and CUDA were not run.
- **Cost model:** no ledger in the range (F4).
- **Verifier:** `stele-verifier` untouched; the eight `--no-default-features` crates build [ran]; no new panic on a verifier path except as F6 describes.
- **Glossary:** `glossary-lint` passes [ran].
- **Tier:** development; nothing claims more.
- **Commit rule:** no column added or reclassified.
- **Plain checker:** the suites decide the same (`stele-ir` 41, `stele-reductions` 284) [ran]; the near-miss of F1 does not.
- **Segments:** unchanged.
- **Proof bytes:** unchanged against pins that the range does not touch; no amendment needed.
- **Ladder:** L0 and L1 through the pins; no ledger pair (F4).

## What I ran

- Everything in the table of item 3 and the differentials of items 4 and 7.
- Suites on the after tree:
  - `stele-field` 22; `stele-poly` 5; `stele-hash` 30; `stele-verifier` 78.
  - `stele-sumcheck` 48, and 55 with `std`.
  - `stele-ir` 41, with and without `std`.
  - `stele-cqis` 166, with and without `std`.
  - `stele-code` 35, with and without `std`.
  - `stele-pcs` 54, with and without `std`; its `recursive` test also at 2 and 16 threads.
  - `stele-lookup` 22 at 1, 2, 7 and 16 threads.
  - `stele-reductions --features std` 284 (6 ignored).
  - `stele-negative-controls --all-features` 148 (4 ignored).
- Gates:
  - `digest.sh` and `check.py native` (41 lines, exit 0).
  - `rust-policy`, `rfc-status`, `glossary-lint`.
  - `rustfmt --check` on the 22 changed files.
  - `cargo clippy --all-targets --all-features -- -D warnings` on the nine touched crates.
  - The CI `--no-default-features` check.
  - `cargo check --workspace --all-targets`.
- My parity and reference tests, the mutants of F2, and the instrumented runs of F3 and F6.

## Not checked

- L2a or any rung above L1, a second host, an x86 host, `stele-simd` parity and the CUDA parity gate.
- `cargo test --workspace`, the examples, `stele-controls --coverage`, `ledger-validate`, `docs-links`, `cargo deny`.
- Byte identity of dev-zk proofs, which draw fresh seeds. Only their accept tests ran.
- Intermediate commits beyond building and the seven L0 windows; L1 and byte 6 were not run per commit.
- The RFC texts behind the citations, beyond the `rfc-status` gate.
- Big-endian and 32-bit hosts.

## After the audited head

The branch was rewritten while this review ran: new base `09f4d509`, head `62b06745`.

- 14 of the 16 commits kept their `git patch-id`. The two `stele-lookup` commits did not (`25952e36` → `613835d6`, `ca8a1ba2` → `1da82f57`). `prove_base` now falls back to the reference rounds for an extension selector, which removes the first half of F7. The two summands gained a `validate_instance`.
- Four commits were added: `df873f39`, `9f3625f7`, `a017205d`, `62b06745`. Two change code the verifier runs: `a017205d` (the selector evaluation in `SelectedProduct`) and `62b06745` (rotation coefficients built by prover and verifier). The message of `a017205d` states a number, verifier peak RSS on L2a from 3.6 GB to 1.1 GB, with no ledger.
- A bounded recheck at `62b06745` [ran], which is not an audit of it:
  - The digest gate passes.
  - My parity and reference tests pass.
  - The codeword and certified-opening digests equal those of the tree before the change.
  - F1 reproduces unchanged; `contract.rs` is the same file.
- By reading only:
  - `rotary.rs`, `data.rs` and `relation_lookup.rs` are the same files, so F2 (d), (e) and F6 stand.
  - `recursive.rs:2845` still reports `current_num_threads().min(block_count)`, so F3 stands.
  - No ledger names the tasks, so F4 stands.
  - The new `crates/stele-lookup/tests/base_parity.rs` iterates `m = 0..=9`, every `b`, and `c = 1..=3`. It may close F2 (a) to (c); I did not run it against the mutants.

The rewritten lookup commits and the four added commits need their own review.

I tried to break it by proving the pinned windows at 1, 3, 5, 7 and 16 threads and at each of the 16 commits; by comparing the factored strategies with the dense one on 2,592 random trees and selected products across every group boundary; by driving every stored type to the int32 boundary and two operands past 2^128; by reversing rotation blocks, skipping histogram positions and mis-weighting layer rounds; by making a rotation worker fail or panic; by nesting pool work under the column recomputation; by sweeping `--tokens`, `--length`, `--checked` and `--next` through both binaries; and by 270 one-byte tampers through both verifiers. On every honest path the pinned digests, the dense parity, the plain checker's `G/argmax/margin` range and the verifier's header, Merkle, sumcheck and statement checks held. The operands past 2^128 are caught only by the test profile's overflow check, as a panic, and by nothing in a release build (F1). The mis-weighted rounds, the reversed rotation blocks and the skipped histogram positions are rejected by no test in the repository (F2).

## Resolution

By the author, in the commit that adds this record. The audited commits were rebased
onto the lane E review fixes, so their hashes changed; 14 of 16 kept their patch id (see
"After the audited head").

| Finding | Status | Change |
|---|---|---|
| F1 (BLOCKING) | Resolved | `contract`'s guard multiplies with `checked_mul` and returns `None` past `u128`, so the caller's checked loop answers `Error::Capacity` as before. `rejects_sums_past_i64_and_indices_past_the_column` has the `[i64::MIN; 4]`, `summed = 2` input. |
| F2 (a), (b) | Resolved | `crates/stele-lookup/tests/base_parity.rs` (from the lane E review) covers every `b ∈ 0..=m` and `c = 1..=3`. Mutants M1, M3 and M4 each fail it. |
| F2 (c) | Resolved | The same test compares `build_levels` + `prove_built` with `prove` for every `(m, b)`. |
| F2 (d) | Resolved | `matches_reference_rows_across_block_and_round_boundaries`: a per-row reference at lengths 1, 63, 64, 65, 129 and 200 with one, two and three blocks per round. Mutant M-rot fails it. |
| F2 (e) | Resolved | `matches_reference_range_multiplicities_past_one_histogram_piece`: a range over 2^17 positions against a direct count. A mutant that skips one position of later pieces fails it. |
| F3 | Resolved | `peak_codeword_bytes` is the structural bound `(blocks + 1)·N_0·4 + payloads`: a function of the shape, never below the live buffers. The field's comment says so. |
| F4 | Resolved | Ledgers below: L1 and L2a before and after on the reference class, verify time, and the same proof and public digests on two hosts. |
| F5 | Resolved | The contiguous path also requires that no higher index bit reads a summed bit. `matches_reference_definition_when_a_higher_index_bit_reads_a_summed_bit` is the review's example. |
| F6 | Resolved | A worker panic is re-raised after every worker is joined; otherwise the first error in worker order is returned (`stele_cqis::join_all`). The worker count is capped by `RAYON_NUM_THREADS`. Buffers are allocated per block in use, not per CPU. |
| F7 | Resolved | `prove_base` takes the reference rounds for an extension selector, and its comment describes what it does. |
| F8 | Recorded | ADR-156: the stack crosses lanes on purpose, and `Field: Send + Sync` is a decision. |

Commits added after the audited head, not covered by the record above:

- `write large tables once on the work pool` (`stele-sumcheck`, `stele-lookup`)
- `split the level-0 row and basis combinations over column blocks` (`stele-pcs`)
- `evaluate a base-field selector through split eq tables` (`stele-lookup`; verifier code)
- `certify the rotation coefficients of each position on the work pool` (`stele-reductions`; verifier code)
- `generate the exponential and activation tables in blocks on scoped threads` (`stele-cqis`; verifier code)
- `resolve a carry chain's factors once` (`stele-reductions`)
- this resolution commit

They are sent back to the same reviewer; its second record is appended below when it
returns.

## Ledgers

Recorded at `1b1676eb`, the parent of the commit that adds them. "Before" is the lane C2
tip (`01076e86`). Reference class: Xeon Platinum 8480CL, 24 allocated CPUs (12 physical
cores), singleton runs, profile byte 6. `bench/ledger/<name>.json`.

| Rung | Ledger | Prove s | Verify s | Peak RSS GB | Verify RSS GB |
|---|---|---|---|---|---|
| L1 | `e19-04-dev-synthetic-8layer-byte6-24t` (before) | 17.32 | 1.05 | 2.08 | 0.14 |
| L1 | `e22-10-dev-synthetic-8layer-byte6-24t` | 7.69 | 0.55 | 1.98 | 0.07 |
| L2a | `e19-04-dev-stories42m-t64-byte6-24t` (before) | 117.79 | 11.35 | 13.99 | 2.76 |
| L2a | `e22-10-dev-stories42m-t64-byte6-24t` | 36.33 | 2.05 | 12.67 | 0.69 |
| L2a | `e22-10-dev-stories42m-t64-byte6-24t-hugepages` | 31.85 | 1.57 | 12.56 | 0.70 |
| L2a | `e22-10-dev-stories42m-t64-byte6-mac` (arm64, 16 threads) | 23.53 | 1.13 | 18.14 | — |

- The L2a proof is 3,927,613 bytes with SHA-256 `afb3581b…67cb` and the public input
  `8da645cd…44b3` in every one of these ledgers, before and after, on both hosts.
- The huge-page ledger sets `GLIBC_TUNABLES=glibc.malloc.hugetlb=1` for prover and
  verifier; its host context says so. Nothing else differs from the ledger above it.
- Against Gate M2's L2a lines on the reference class: prove 36.33 s against 10 s and
  peak RSS 12.67 GB against 4 GB are not met; proof size is met; verify is 2.05 s
  against 2 s, and 1.57 s with huge pages.


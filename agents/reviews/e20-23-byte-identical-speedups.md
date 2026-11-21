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

| Rung | Ledger | Prove s | Verify s | Peak RSS GiB | Verify RSS GiB |
|---|---|---|---|---|---|
| L1 | `e19-04-dev-synthetic-8layer-byte6-24t` (before) | 17.32 | 1.05 | 2.08 | 0.14 |
| L1 | `e22-10-dev-synthetic-8layer-byte6-24t` | 7.69 | 0.55 | 1.98 | 0.07 |
| L2a | `e19-04-dev-stories42m-t64-byte6-24t` (before) | 117.79 | 11.35 | 13.99 | 2.76 |
| L2a | `e22-10-dev-stories42m-t64-byte6-24t` | 36.33 | 2.05 | 12.67 | 0.69 |
| L2a | `e22-10-dev-stories42m-t64-byte6-24t-hugepages` | 31.85 | 1.57 | 12.56 | 0.70 |
| L2a | `e22-10-dev-stories42m-t64-byte6-mac` (arm64, 16 threads) | 23.53 | 1.13 | 18.14 | 1.06 |

- The L2a proof is 3,927,613 bytes with SHA-256 `afb3581b…67cb` and the public input
  `8da645cd…44b3` in every one of these ledgers: before on the reference class, after
  on both hosts.
- The huge-page ledger sets `GLIBC_TUNABLES=glibc.malloc.hugetlb=1` for prover and
  verifier; its host context says so. Nothing else differs from the ledger above it.
- Against Gate M2's L2a lines on the reference class: prove 36.33 s against 10 s and
  peak RSS 12.67 GiB (13.60 GB) against 4 GB are not met; proof size is met; verify is
  2.05 s against 2 s, and 1.57 s with huge pages.

## Second pass

- **Audited commits:** `6cdb64dd` (the resolution) against F1 to F8; the six commits added after the first audited head, `d5162dca`, `63279d01`, `6072316e`, `b736dda9`, `c2665837` and `fd9ba1bb`; `1b1676eb`; and `c2db66aa`, which changes no file under `crates/` or `scripts/`. Line numbers are those of `c2db66aa`. "Base" is `7634d170`, the parent of the first commit of the stack; its tree equals that of `3937483f`.
- **Reviewer:** independent `soundness-auditor` agent; did not write the change.
- **How this record was made:** two reviewers ran the experiments and neither finished. The first stalled at the earlier head `a844135d`. The second audited `c2db66aa` and stopped before its last step. I wrote this record from their logs and scripts, re-ran what their built binaries could confirm, and read the code the conclusions rest on. I built nothing and ran no mutant of my own.
- **Verdict:** **CHANGES REQUESTED**, for S1.

### Summary

The claim held in every run. No proof byte, public byte or verifier decision differs between the base and the tip on any input that was run, at 1, 2, 3, 5 and 8 threads on arm64, and the ledgers record the same L1 and L2a digests on x86_64 at 24 threads. F1 to F7 are closed and F8 is recorded.

One gap of the kind F2 named is open on the commit added last. No committed test runs the split branch of `rows_in_blocks`, and two mutants of it pass (S1, MEDIUM). Two LOW items follow it.

### Evidence labels

- **[ran by the previous reviewer, arm64, `<log>`]**: the second reviewer, at `c2db66aa`, in detached worktrees that each log header reports clean (`dirty=0`). Host: aarch64 macOS, 16 CPUs. `<log>` is a file of its scratch directory `review-perf3/`. "digest step N" is step N of its command record `previous-reviewer-digest.txt`, for results that have no log file.
- **[ran by the first stalled reviewer at `a844135d`, arm64, `<log>`]**: in `review-perf2/`. `a844135d` is the earlier hash of the resolution commit. It differs from `c2db66aa` in code by `crates/stele-cqis/src/execution/data.rs`, which is commit `1b1676eb`, and by two lines of `scripts/gates/check.py` that came with the rebase [read: `git diff --stat a844135d c2db66aa`]. Its results carry over to every other file by inference, and say nothing about `1b1676eb`.
- **[re-ran, arm64]**: by me, with the test binaries and the two release `stele` binaries the second reviewer built from its clean worktrees of `c2db66aa` and `7634d170`.
- **[read]**: by reading the code, or the output of a `git` or `grep` query.

Both scratch directories are outside the repository and are not kept.

### What was run

**Bytes and decisions, base against tip**

| Check | Threads | Result | Label |
|---|---|---|---|
| Six pinned L0 and L1 proofs, `scripts/gates/digest.sh` | tip 1, 3, 8 | pass | [ran by the previous reviewer, arm64, `logs/digest-gate-t1.log`, `-t3.log`, `-t8.log`] |
| `stele prove-dev`, 15 flag combinations on three L0 fixtures | base 3; tip 8, 1 | same exit code, verdict lines, `public.bin` and `proof.bin` in 15 of 15; 9 write a proof, 6 are refused identically | [ran by the previous reviewer, arm64, `e2e.log`] |
| `stele verify-dev` on 8 of those windows | base 2; tip 8 | each accepts the other's proof; 560 one-byte tampers: same last line 560, accepted 0 | [ran by the previous reviewer, arm64, `e2e.log`] |
| L1 at bytes 6, 5 and 3 | base 3; tip 8, 3, 1 | identical; byte 6 equals the ledger's proof and public SHA-256; each verifier accepts the other's proof | [ran by the previous reviewer, arm64, `l1.log`] |
| L2a (stories42M, T = 64, byte 6) | tip 8, 3, 1 | proof and public SHA-256 equal the ledgers'; the base and the tip verifier accept; 32 tampers: same last line 32, accepted 0 | [ran by the previous reviewer, arm64, `l2a.log`] |
| Three L0 windows: bytes 3 and 6, and the grouped fixture | base 4; tip 5, 2 | `proof.bin` and `public.bin` equal across the three runs and equal the previous reviewer's base files; each verifier accepts the other's proof; 15 one-byte tampers: same last line 15, accepted 0 | [re-ran, arm64] |

The range changes neither `tests/digests/development.json` nor any fixture. The only data files it adds are four ledgers [read: `git diff --stat 7634d170 c2db66aa`].

**Suites at the tip** [ran by the previous reviewer, arm64, `suites-final.log`]

- `stele-cqis` 167, without `std` and with it at 1, 3 and 8 threads.
- `stele-lookup` 26 at 1, 3 and 8 threads.
- `stele-sumcheck` 52, and 59 with `std` at 1, 3 and 8 threads.
- `stele-pcs` 55, without `std` and with it at 1, 3 and 8 threads.
- `stele-ir` 42 and `stele-code` 35, each with and without `std`.
- `stele-field` 22, `stele-poly` 5, `stele-hash` 30, `stele-verifier` 78.
- `stele-reductions --features std` 293 (6 ignored) at 3 and 8 threads.

**Gates** [ran by the previous reviewer, arm64, `gates.log`]: `fmt`; `native` (`check.py native`, 41 gate lines, 149 tests passed, 4 ignored); the `stele-prover` release tests at 3 and 8 threads (25 passed, 13 ignored); the `stele-cli` release tests (9 passed, 1 ignored); `nostd`; `clippy` with no warning line. All exit 0. `ledger-validate`, `rust-policy`, `rfc-status` (2,077 references), `glossary-lint` and `docs-links` exit 0 [ran by the previous reviewer, arm64, digest step 164].

**Mutants** [ran by the previous reviewer, arm64, `mutants.log`]: 29 runs, one changed line each, in a clean worktree with no auditor test in it. The runner applies a mutant only when its pattern occurs exactly once, and the two logs I opened, of M-rows0 and M-join2, show the crate recompiled [read: `scripts/mutants.sh`, `logs/mutant-M-rows0.log`, `logs/mutant-M-join2.log`].

- Killed, 23: M1, M3, M4, M-rot (with and without `std`), M-hist, M-F1, M-F5; M-eq, M-build, M-fold, M-tree1, M-tree2, M-tree3; M-row, M-basis (with and without `std`); M-mle1, M-mle2; M-fill; M-rows-seq; M-rope; M-chain.
- SURVIVE, 6: M-rows0 and M-rows1 (S1); M-join and M-join2 (S2); M-mle1-roundtrip and M-mle2-roundtrip (S3).

**Instrumented runs in the scratch copy** [ran by the previous reviewer, arm64, `batch2.log`]

- `join_all` on Ok, Err and panicking workers in 9 orders and delays (`logs/audit-join.log`).
- The kernel and the plain checker on operands past 2^128, in the test profile and in release (`logs/audit-f1.log`, `logs/audit-f1-release.log`).
- `peak_codeword_bytes` of the E19-05 shape with the pool at 1, 2 and 8 threads and without it.
- Every projection of two rows or more forced to split (threshold 1, at most rows / 2 workers): the `stele-cqis` tests and the six pinned proofs at 3 and 8 threads, then the same with M-rows1.
- M-mle1 against the release prover tests.
- The auditor's own reference test for `mle_base` did not compile: it used `std::println!` and `vec!` in a `no_std` crate (`logs/audit-mle-t1.log`). The three `exit=101` lines of `batch2.log` are that. It gave no evidence.

**The first stalled reviewer, at `a844135d`**

- Digest-printing tests of `stele-code`, `stele-pcs`, `stele-sumcheck`, `stele-lookup` and the plain checker, on base and tip, without the pool and with it at 1, 2, 7 and 16 threads: identical in 10 of 10, 10 of 10, 10 of 10, 8 of 8 and 4 of 4 runs [`differential.log`]. The second reviewer repeated the base side at `7634d170` and got the same four digests [ran by the previous reviewer, arm64, `differential-base.log`]. The tip side was not repeated at `c2db66aa`.
- Errors and panics injected into the rotation workers, and live row buffers counted in `recompute_queried_columns` [`faults-buffers.log`].
- Each of the 23 commits up to `a844135d` builds without a warning and passes the 7 pinned L0 windows [`per-commit.log`]. Those are the hashes before the rebase.
- M-join and M-join2 survive there too [`mutants-own.log`].

**[re-ran, arm64] from the tip's test binaries.** All pass.

- `stele-ir`, filter `contract`: 4 tests, in both builds.
- `stele-cqis`, filter `rotary`: 4 tests. `matches_reference_rows_across_block_and_round_boundaries` also at `RAYON_NUM_THREADS=1` and in the build without `std`.
- `stele-reductions`: `matches_reference_range_multiplicities_past_one_histogram_piece`.
- `stele-pcs`: `matches_reference_row_and_basis_combinations_across_block_sizes`, in both builds.
- `stele-lookup`: `matches_reference_dense_sum_for_the_split_base_extension`.

### F1 to F8 at `c2db66aa`

| Finding | Status | Evidence |
|---|---|---|
| F1 (BLOCKING) | Closed | `contract.rs:81-86` multiplies with `checked_mul` twice and returns `None` [read]. The test has `[i64::MIN; 4]` at `summed = 2` (`contract.rs:260-271`) and passes [re-ran, arm64]. M-F1 fails `rejects_sums_past_i64_and_indices_past_the_column` [ran by the previous reviewer, arm64, `mutants.log`]. On a validated relation with operands 2^40, 2^62 and `i64::MIN` the checker answers `Err(Range { "a range", 0 })`, or `"c range"` when the virtual column's range is declared first, in the test profile and in release. That is the "Before" row of the first record's table. The kernel returns `None` on four inputs past 2^125 [ran by the previous reviewer, arm64, `batch2.log`]. |
| F2 (a), (b) | Closed | M1 and M3 fail `matches_reference_tree_for_every_group_boundary`; M4 fails `matches_reference_selected_product_and_rejects_the_same_selectors` [ran by the previous reviewer, arm64, `mutants.log`]. `tests/base_parity.rs:54-74`, `153-155`: `m = 0..=9`, every `b`, `c = 1..=3` [read]. |
| F2 (c) | Closed | `tests/base_parity.rs:90-94` compares `build_levels` and `prove_built` with `prove` for every `(m, b)` [read]. |
| F2 (d) | Closed | M-rot fails `matches_reference_rows_across_block_and_round_boundaries` with and without `std` [ran by the previous reviewer, arm64, `mutants.log`]. Lengths 1, 63, 64, 65, 129 and 200 at 1, 2 and 3 blocks per round [read: `rotary/tests.rs:192-202`]. Passes [re-ran, arm64]. |
| F2 (e) | Closed | M-hist fails `matches_reference_range_multiplicities_past_one_histogram_piece` [ran by the previous reviewer, arm64, `mutants.log`]. Passes [re-ran, arm64]. |
| F3 (MEDIUM) | Closed | `recursive.rs:2854` reports `(block_count + 1)·N_0·4 + payloads`, and `current_num_threads` no longer occurs in the file [read]. The E19-05 shape reports 105,472 B at 1, 2 and 8 threads and without the pool [ran by the previous reviewer, arm64, `batch2.log`]. Live row buffers never exceeded the reported count in 15 combinations of shape and thread count, the nested case included (5 live, 8 reported) [ran by the first stalled reviewer at `a844135d`, arm64, `faults-buffers.log`]. The field's comment says so (`recursive.rs:2695-2697`) [read]. |
| F4 (MEDIUM) | Closed, with three remarks | Six ledgers under `bench/ledger/` [read: the JSON]. "Before" is at `01076e86`, which differs from the base in no code file. "After" is at `1b1676eb`, which differs from `c2db66aa` in no file under `crates/` or `scripts/` [read: `git diff --stat`]. Each pair has the same rung, the same device (Xeon Platinum 8480CL) and 24 threads, which answers Workflow 03 question 5. Proof and public SHA-256 are equal before and after at L1 and at L2a, and equal on the arm64 ledger. The previous reviewer reproduced the L2a digests on arm64 [`l2a.log`]. Remarks below the table. |
| F5 (LOW) | Closed | `contract.rs:91-100` also requires that no higher index bit reads a summed bit [read]. M-F5 fails `matches_reference_definition_when_a_higher_index_bit_reads_a_summed_bit` [ran by the previous reviewer, arm64, `mutants.log`]. Passes [re-ran, arm64]. |
| F6 (LOW) | Closed in behaviour; its test is S2 | `lib.rs:28-43` joins every worker, re-raises the first panic, otherwise returns the first error in worker order [read]. Nine orders of Ok, Err and panic behave so [ran by the previous reviewer, arm64, `logs/audit-join.log`]. Through the rotation with injected faults, the first error in position order comes back, at one worker too, and a panic is re-raised in each order [ran by the first stalled reviewer at `a844135d`, arm64, `faults-buffers.log`]. `lib.rs:16-23` caps the worker count by `RAYON_NUM_THREADS`; nothing under `crates/*/src` sizes the pool another way [read: grep for `ThreadPoolBuilder`, `num_threads(`]. `rotary.rs:235-242` allocates `min(workers, blocks)` buffers [read]. |
| F7 (LOW) | Closed | `selected.rs:409-420`: an extension selector takes `self.prove`. The comment at `398-401` describes it [read]. |
| F8 (LOW) | Recorded | ADR-156 is at `agents/context/decision-log.md:4829` [read]. For the integrator. |

Remarks on F4:

- The "before" L2a proof exists on the reference class only. "The same bytes before and after on two hosts" is before on one host and after on two.
- The RSS columns of the ledger table hold GiB under a GB header: 13,604,892,672 B is 13.60 GB and 12.67 GiB. The Mac row shows "—" for verify RSS where the ledger has 1,142,276,096 B [ran by the previous reviewer, arm64, digest step 176].
- The message of `6072316e` says verifier peak RSS on L2a falls from 3.6 GB to 1.1 GB. The reference-class pair is 2.76 to 0.69 GiB and the Mac ledger has 1.06 GiB after. No ledger has the 3.6.

### The added commits

| Commit | Who runs it | Mutants | What I read |
|---|---|---|---|
| `d5162dca` tables written once on the pool | prover and, by item 4 of the first record, the verifier (`parallel::eq_table`) | M-eq, M-build, M-fold, M-tree1 to M-tree3 killed | message, new functions and callers only |
| `63279d01` level-0 row and basis combinations | prover: both callers are `close_fresh_level0_at_point` and `close_certified_level0` | M-row, M-basis (with and without `std`) killed | message, new functions and callers only |
| `6072316e` split selector evaluation | prover and verifier | M-mle1, M-mle2 killed by the unit test | `selected.rs:208-237` and its test |
| `b736dda9` rotation coefficients per position on the pool | prover and verifier | M-rope killed, 6 tests fail | the diff |
| `c2665837` tables in blocks | prover and verifier | M-fill killed, 4 tests fail | `fixed.rs:46-76`, `gaussian.rs:142-167`, `gaussian_exact.rs:126` |
| `fd9ba1bb` carry chain factors resolved once | prover (it assigns the carry columns) | M-chain killed | the diff |
| `1b1676eb` projection rows in blocks | prover: `verify` (`stele-prover/src/development.rs:1004`) builds no `Executor` | M-rows-seq killed; M-rows0, M-rows1 survive | `data.rs:28-73`, `243-262`, and the diff |

What holds by reading:

- **`mle_base` (`selected.rs:208-237`).** Entry `j = hi·2^|low| + lo` is weighted by `eq(point[..split], hi)·eq(point[split..], lo)`, which is `eq(point, j)` with the leading coordinate first. With no variable both tables are `[1]`. Sums and products are exact.
- **Tables (`fixed.rs:46-76`).** The exponential rows take no state. An activation block's state is a `Gaussian` whose cached normalizer is `normalizer(bits + 8)`, a function of the precision alone (`gaussian.rs:149-154`), and the exact interval reads it only where it requires it (`gaussian_exact.rs:126`). A block that starts with an empty cache computes the same rows. The table bytes equal the pinned fixtures at 1, 3 and 8 workers [ran by the previous reviewer, arm64, `suites-final.log`].
- **Rotation coefficients (`b736dda9`).** One task per position, collected in position order; `Rotation::coefficient` makes its own generator per call (`rotary.rs:196`).
- **Carry chain (`fd9ba1bb`).** The same products through `Indexer`, which the first pass covered. A missing column is still reported in position, term and factor order.
- **`rows_in_blocks` (`data.rs:36-73`).** Block `b` is rows `b·per` to `min((b + 1)·per, rows)`. Every slot has one writer. `join_all` returns the error of the lowest failing block, whose loop stops at its lowest failing row.

### Findings of this pass

#### S1 — MEDIUM (`1b1676eb`; Workflow 01 step 4): no committed test runs the split of `rows_in_blocks`

`crates/stele-cqis/src/execution/data.rs:56-67`. The branch runs when `rows·columns ≥ 2^22` (line 51), `rows ≥ 128` (line 52) and more than one worker is available.

- **Mutants** [ran by the previous reviewer, arm64, `mutants.log`]. M-rows0 replaces the spawned closure of line 62 by a panic. M-rows1 starts every later block one row early. Both pass `cargo test -p stele-cqis --features std`, 167 tests. M-rows-seq breaks line 45, which both paths share, and is killed. So the suite runs the loop and never the split.
- **The rest of the repository.** The previous reviewer's last step was M-rows0 against `cargo test --workspace --all-features` and the six pinned proofs. It did not run. By reading, I found no committed input that reaches the branch:
  - A matrix of 2^22 int8 cells is at least 4 MB. The tracked files of 4 MB or more are two `stele-cqis` fixtures, whose suite does not reach the branch, and one archive that only a Python script opens [read: `git ls-tree -r -l c2db66aa`, grep].
  - The 32,000-id case of `stele-reductions/src/argmax/tests.rs:401` declares a relation and runs no executor [read].
  - A model built in memory by a test outside `stele-cqis` is not excluded.
- **The code is right wherever it ran.**
  - With the threshold forced to 1 in the scratch copy, every `stele-cqis` test passes at 3 and 8 threads and the six pinned proofs match. M-rows1 under the same forcing fails `matches_reference_prefill_capture_and_rederives_every_column` on the accumulator, and the producer of the pinned proofs exits 101 [ran by the previous reviewer, arm64, `batch2.log`].
  - The L2a proof at 8 and 3 threads has the ledger's digest [ran by the previous reviewer, arm64, `l2a.log`]. Its head has 32,000 rows, which is above the threshold for any width of 132 columns or more. So those two runs took the split and the 1-thread run took the loop. This is inference from the code and the shape, not an instrumented run.
- **Effect of a wrong block.** The executor is not on the verifier's path, so no false statement can follow. By the forced M-rows1 run the capture's accumulator stops matching its reference. I infer that the plain checker would then refuse the witness and the prover would stop. That would happen on large models and multi-thread hosts only, which is where the committed tests cannot look.
- **Why MEDIUM.** It is the gap F2 (d) and (e) named, on a commit added after that finding. Workflow 01 step 4 asks for a `matches_reference_*` test when a scalar path exists.
- **Requested.** A unit test of `rows_in_blocks` against its own loop. Give the function a worker-count parameter, as `Rotation::data_digest_with` has, so that the test does not depend on the runner's CPU count or on `RAYON_NUM_THREADS`. Cases: a row count that is not a multiple of the worker count, at 1, 2, 3 and 7 workers; and two failing rows in different blocks with different errors, expecting the lower row's.

#### S2 — LOW (`6cdb64dd`, the fix of F6): `join_all` has no test

`crates/stele-cqis/src/lib.rs:28-43`.

- M-join makes line 34 keep the last error instead of the first. M-join2 makes lines 39-41 drop the panic payload instead of re-raising it. Both pass the `stele-cqis` suite [ran by the previous reviewer, arm64, `mutants.log`; and by the first stalled reviewer at `a844135d`, `mutants-own.log`].
- The behaviour at the tip is the documented one (F6 above).
- Under M-join2 the three callers would go on with a block left as it was. `data_digest_with` would hash the buffer (`rotary.rs:266-268`); `fill_rows` and `rows_in_blocks` would return zero-filled rows. So the re-raise is what keeps a worker panic from becoming a wrong digest, table or output. This is by reading; it was not run.
- **Requested.** A test of `join_all` on three workers with an error and a panic in each order. The second reviewer's is in its scratch directory (`audit-tests/audit_join.rs.inc`).

#### S3 — LOW (`6072316e`; verifier code): the reference test of `mle_base` draws its points from the base field

`crates/stele-lookup/src/selected.rs:555`. Each coordinate is `QM31::from_i64(a) * QM31::from_i64(b)`, the product of two embedded integers, so it lies in M31. Both `eq` tables then hold base-field elements. The test (line 544) checks `weight.mul_m31(value)` (line 228) and `high[hi] * inner` (line 231) on base-field weights only, and in QM31 only.

- What the test does establish: the index split and the order of the two tables, at 0, 3, 12 and 15 variables, on entries 0, 1 and arbitrary. M-mle1 and M-mle2 fail it [ran by the previous reviewer, arm64, `mutants.log`].
- Extension points are covered end to end only. M-mle1 fails 9 of 11 release prover tests with `SelectorMismatch` [ran by the previous reviewer, arm64, `batch2.log`]. The base verifier, which evaluates the dense sum, and the tip verifier agree on every honest and tampered file of the table above.
- M-mle1-roundtrip and M-mle2-roundtrip pass the crate's integration tests. Those tests stay at 9 variables or fewer (`tests/base_parity.rs:54`, `153`), where the leading table is `[1]`, and I infer that their selectors are Boolean.
- **Requested.** Draw all four limbs of each coordinate, and run the same loop in OM31.
- I ran no mutant for this. It is from reading the test.

#### Notes that are not findings

- **Which error a doubly failing projection returns.** `data.rs:243-253` now computes every row's `scaled_sum` before the first row's capture push and `output` (lines 254-261). Before `1b1676eb`, row `j`'s push and `output` ran before row `j + 1`'s `scaled_sum`. If row `i` fails in `output` and a later row fails in `scaled_sum`, the later row's error is now returned. Both are refusals, and the CLI prints `NO: Witness` for either. The quotient check of `scaled_sum` (`numerics.rs:115`) and `signed` (`numerics.rs:30-33`) both return `Error::Range`. I built no input where the kinds differ. This does not depend on the thread count [read].
- **An environment read on the verifier's path.** `workers()` reads `RAYON_NUM_THREADS` under the tables and the rotation digest, which the development-tier verifier regenerates. It chooses a schedule only: the suite and the pinned proofs are the same at 1, 3 and 8. The first record's statement that the added lines read no environment no longer holds.
- **`scope.spawn` panics when the OS refuses a thread** (`data.rs:62`, `fixed.rs:69`, `rotary.rs:258`). `Builder::spawn_scoped` returns the error, and the block could then run inline. By reading the standard library's documentation; not run.

### Review checklist, for the commits of this pass

- **RFC section of each new public item:** one new public item, `stele_sumcheck::parallel::build` (`d5162dca`), RFC-0006 A1 by the commit message. I did not read its doc comment. `rfc-status` passes.
- **Challenges:** no `absorb`, `challenge`, label or grind call is added, removed or moved in non-test code across `7634d170..c2db66aa`. The one added `challenge(` line is in a unit test [ran by the previous reviewer, arm64, digest step 226].
- **Claims:** none added or moved in the diffs I read. `mle_base` returns the value the dense sum returned.
- **New bindings:** none.
- **Ledger and accounting:** no line changes; `check.py native` passes.
- **Bound certificate:** no new instance.
- **Padding and masks:** unchanged in the diffs I read.
- **Determinism:** the lines added since `fdc70f17` contain no hash map, clock, float, `unsafe`, atomic or lock, and one environment read, in `workers()` [ran by the previous reviewer, arm64, digest step 183]. Every reduction I read is an exact sum.
- **Parity:** CPU proofs are equal on arm64 (the reviewers' runs) and on x86_64 (the author's ledgers). `stele-simd`, `stele-gpu`, `stele-kernels`, `stele-py` and `stele-verifier` have no changed file [ran by the previous reviewer, arm64, digest step 239]. The SIMD and CUDA gates were not run.
- **Cost model:** the ledgers of F4.
- **Verifier:** `stele-verifier` is untouched. The development-tier verifier runs `mle_base`, the rotation coefficients, the tables and `join_all`, and by item 4 of the first record `parallel::eq_table`. New panic sites on that path: a re-raised worker panic, and `scope.spawn`.
- **Glossary:** `glossary-lint` passes at the tip.
- **Tier:** development; nothing claims more.
- **Commit rule:** no column added or reclassified in the diffs I read.
- **Plain checker:** `stele-ir` 42 and `stele-reductions` 293 pass. The near-miss of F1 decides as it did before the stack.
- **Segments:** unchanged.
- **Proof bytes:** unchanged, against pins and fixtures the range does not touch.
- **Ladder:** L0 and L1 through the pins and the CLI; L2a through the ledgers and the previous reviewer's three runs. Each ledger pair is on the same rung, host class and thread count.

### Not checked

- M-rows0 and M-rows1 against the CI test set, and M-rows0 against the six pinned proofs. That was the previous reviewer's last step and it did not run.
- The tip side of the digest differential at `c2db66aa`. It carries over from `a844135d` by inference.
- `d5162dca` and `63279d01` line by line, and which callers of `parallel::eq_table` are on the verifier's path at the tip. Their evidence is the mutants, the suites at three thread counts, the differential and the proofs.
- An x86 host by a reviewer. Every reviewer run is arm64. The x86_64 evidence is the author's ledgers.
- `cargo test --workspace`, the examples, the `stele-simd` parity, the CUDA gate, `cargo deny`, `stele-controls --coverage`.
- Per-commit builds at the hashes after the rebase.
- Byte identity of dev-zk proofs, which draw fresh seeds.
- The ignored tests: 13 in `stele-prover`, 6 in `stele-reductions`. The main checkout carries an uncommitted edit of `crates/stele-prover/tests/development.rs`, the expected summary of the ignored test `enumerates_every_round_of_the_eight_layer_window` (11,687 rounds to 28,447). The range does not touch that file, and I did not run the test at either expectation.
- What the ledger field `plan_digest` covers. It differs between the Mac ledger and the reference-class ledgers, while the proof and public digests agree.
- Whether `b736dda9` changes which error a rotation with two different faults returns, as the first note describes for `1b1676eb`.
- The pull request's CI status, the RFC texts behind the citations, and big-endian and 32-bit hosts.
- The times and RSS figures of the ledgers, beyond reading them.

### Verdict

**CHANGES REQUESTED.**

The reviewers before me and I tried to break it by proving the pinned and L1 windows at 1, 2, 3, 5 and 8 threads against the base binary, and the L2a window at 1, 3 and 8 threads against the digest of the base's ledger; by 29 mutant runs over the resolved findings and every new split; by forcing every projection to split; by 607 one-byte tampers through the base and the tip verifier; and by injecting errors and panics into the rotation workers. The pinned digests, the reference tests named above and the verifier's header, Merkle, sumcheck, fraction and statement checks rejected everything that reached them.

Two changes reached no committed control. A wrong block boundary in `rows_in_blocks` passes every test that was run at the shipped threshold (S1). A `join_all` that keeps the last error or swallows a panic passes the `stele-cqis` suite (S2). Workflow 03 allows approval only with a control that rejected the attempt, and for `1b1676eb` there is none in the repository.

S1 holds the verdict. S2 and S3 are one small test each, and I ask for them in the same commit. With a committed test that kills M-rows0 and M-rows1, nothing in this record stands against approval.

## Resolution of the second pass

By the author, in the commit that appends the second pass.

| Finding | Status | Change |
|---|---|---|
| S1 | Resolved | `rows_in_blocks` chooses the worker count and calls `rows_on(rows, workers, row)`. `matches_reference_rows_at_every_worker_count_and_returns_the_first_failing_row` compares it with the loop for 0 to 101 rows at 1, 2, 3 and 7 workers, and expects the lower row's error from two failing rows in different blocks. A split that fills nothing and one whose later blocks start a row early both fail it. |
| S2 | Resolved | The reviewer's test of `join_all` is committed (`rejects_with_the_first_error_in_worker_order_and_re_raises_a_panic`). A `join_all` that keeps the last error and one that drops the panic both fail it. |
| S3 | Resolved | The reference test of `mle_base` draws its points from a transcript, every limb, and runs in QM31 and OM31. |
| F4, remarks | Resolved in the table above | The RSS columns are headed GiB, which is what they hold, and the Mac row has its verifier RSS. The first bullet says which host has the "before" proof. The message of `6072316e` states a verifier RSS of 3.6 GB that no ledger has; the ledger pair is 2.76 to 0.69 GiB. The message is left, because rewriting it would change the audited hashes. |

Notes of the second pass, left as they are: the order of two different errors in one
projection, the environment read of `workers()` on the verifier's path, and the panic of
`scope.spawn` when the OS refuses a thread.

The ignored test `enumerates_every_round_of_the_eight_layer_window` had gone stale with
E18-05: it is re-pinned in a commit of its own (28,447 rounds; floors `2^-99.8` and
`2^-99.6`).

The tests are sent back to the reviewer of the second pass for its confirmation, which
is appended below when it returns.

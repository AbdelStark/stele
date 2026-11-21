# Soundness Audit Review — the instance bound of a lookup check (RFC-0026 A30, task E20-26)

- **Task:** `E20-26` (registered in lane E; the code it changes, the relation engine, is lane P's); the change leaves it `in_progress`
- **Audited commit:** `34a73902` on `task/E20-26-check-instance-bound`, one commit above `ff75b89e`. Line numbers are those of `34a73902`.
- **Reviewer:** independent agent, as the reviewer from another lane that Workflow 02 step 4 requires and as `soundness-auditor` of the code; did not write the change
- **Claim under review:** a lookup check whose members hold `N` positions takes the bound `B_c = min(B, max(25, ceil(log2 N) − 2))` in place of A8's `B`. A check of at most `2^25` positions keeps its plan and bytes. A larger one is at most four independent RFC-0008 A5 instances up to `m = B + 2`. The verifier derives `B_c` from the relation; no round and no binding is added.
- **Governing specs:** RFC-0026 A3, A8, A15 §6.3, A16, A27, A28, A29 and the Draft A30; RFC-0008 A5; RFC-0027 §§2, 5; Workflows 02 and 03; `agents/templates/amendment-short.md`; INV-1, INV-2, INV-11, INV-14
- **Tier:** development
- **Verdict:** **CHANGES REQUESTED** (one BLOCKING finding, on what the amendment covers; none on soundness)

## Summary

I found no false statement that an engine verifier accepts under this rule, and no `N` on which the code and the amendment's formula differ.

- **The function.** `check_bound` equals the formula for every `B` in 1..=30 on 200,390 values of `N`, among them 0, 1, every power of two with its neighbours and `u64::MAX`.
- **The plans.** `N` is the sum over a check's members before any cut, per check and per segment. A planner written from A3, A8 and A30 equals the plain, segmented and recursive planners on 400 random relations of up to `12·2^30` positions per check.
- **Soundness.** Each instance is a `Check` with its own identifier, statement, multiplicities and draws. Coverage does not depend on the bound chosen. The verifier's ledger lists each instance's lines.
- **Below the floor.** The plan is the one A8 built. The six pinned L0 and L1 proofs reproduce.
- **L2a, byte 6.** The proof is 3,971,461 bytes and verifies. Four false statements, ten edited bytes and the proof made under the old rule are rejected.
- **Cut members.** With a test-only bound, the byte-6 engine proves and verifies cut members and rejects a false member value, swapped sections and an out-of-range weight.
- **The rule on the windows.** With the floor lowered to 3, the L0 windows prove and verify on split checks, and 147 of the 149 negative-control tests pass.

Why this is not an approval:

1. The rule changes byte-5 plans. Accepted A15 §6.3 and the independent replay keep one instance per check, and the replay rejects an honest window once a check is split (F1).
2. The soundness note says no round changes (F2).
3. Seven mutants of the rule's use pass every committed test (F3).
4. No committed test proves a split check through the byte-6 engine, and L2a's split cuts no member (F4).
5. The amendment's numbers have no ledger at this commit (F5).

I would approve this change with F1 decided and written into A30, F2 and F6 corrected while the text is a Draft, the tests of F3 and F4 committed, and the ledgers of F5 in the tree. F7 to F9 can ride in the same commits.

## Scope

1. `docs/rfcs/RFC-0026-development-end-to-end.md:2834-2866` (A30), read against A3 (`622-690`), A8 (`954-992`), A15 §6.3 (`1635-1656`), A27 (`2623-2720`) and A29 (`2750-2832`)
2. `crates/stele-reductions/src/relation.rs:651-664`, `892-989` and the planners that call it (`997-1088`, `3454-3580`); `relation_recursive.rs:354-510`; `relation_lookup.rs`
3. `crates/stele-reductions/src/relation_tests.rs:3964-4037`; `agents/tasks/graph.yaml:4531-4549`
4. Beside the change: `crates/stele-verifier/src/plan.rs`, `development.rs`; `crates/stele-reductions/src/zk_relation.rs`; `crates/stele-prover/src/accounting.rs`; `crates/stele-cli/src/main.rs:342-383`; `bench/dev_e2e.py`, `bench/scoreboard.py`

## Evidence labels

- **[read]**: by reading at `34a73902`.
- **[ran, arm64]**: on an Apple M4 Max (16 CPUs, 48 GB, rustc 1.90.0), in a detached worktree of `34a73902` with its own build directory and no changed file. The host ran other builds throughout (load 60 to 120), so no time or memory figure of mine is evidence.
- **[ran, arm64, instrument]**: the same host, on a scratch copy of `34a73902` with one instrument below.

Instruments, in scratch copies only:

- **Review tests** inside the crates' test modules, because they read private plan fields: `check_bound` against a loop written from the text; a planner written from A3, A8 and A30 against the three planners; the rule per segment; a last instance of one position; the engine's byte-5 plan beside `stele_verifier::plan::Plan::derive`.
- **Test-only bound** for `plan_recursive`, to run the byte-6 engine on split checks.
- **Plan dump**: one line per derived instance behind an environment variable, read through `verify-dev` on the L2a proof.
- **Lowered floor**: `SPLIT_FLOOR = 3` and nothing else, so that the rule splits test-sized checks.
- **Mutants**: 21, one changed statement each. A mutant *survives* a test set when every test passes.
- **Proof editor**: a script that re-encodes a `stele-dev-e2e-v2` container with one byte of one lookup section flipped.
- **Base build** of `ff75b89e`, for the ledger of the pre-amendment proof.
- **Size model**: a range instance of `m` bits over a `k`-bit table with `n` members is `32m² + 112m + 32k² + 48k + 112 + 16n` bytes, plus 4 of framing. It equals all 18 range sections of my L2a proof and the pre-amendment `range_8` section.

## What holds

### 1. `check_bound` is the amendment's formula (`relation.rs:661-664`) [read; ran, arm64, instrument]

- `m` is `ceil(log2 N)`: 0 for `N` of 0 or 1, `k` for `2^k`, `k + 1` for `2^k + 1`, 64 for `u64::MAX`.
- `m.saturating_sub(2)` is 0 where `m − 2` is negative; the maximum with 25 is 25 either way.
- The result lies between `min(B, 25)` and `B`, so `1 <= B_c <= 30` and `1usize << B_c` cannot overflow.
- Against the least `m` with `2^m >= N` in signed arithmetic, the function agrees for every `B` in 1..=30 on 200,390 values: 0, 1, every `2^k` with `2^k ± 1` and `2^k ± 2`, `u64::MAX`, and 200,000 random values of every bit length.

### 2. `N`, order and reach of the rule (`relation.rs:908-914`) [read; ran, arm64, instrument]

- `N` is the sum of `2^m_i` over the members the planner collected for the check, before any cut. The cut keeps the sum. Every `m_i <= 30` after `validate`, so the sum saturates only past `2^34` members, where `B_c = B` in any case.
- The bound is computed inside the loop from the function's parameter; the `let` shadows and does not carry to the next check.
- The three planners collect members per segment and call `build_a8_checks` (`relation.rs:1088`, `3572`; `relation_recursive.rs:502`). The prove and verify entry points derive their plan through them (`relation.rs:2230`, `3193`, `3960`, `4791`; `relation_recursive.rs:753`, `1420`). Nothing else reads the bound.
- Order is A8's: relation order, the blocks of a cut member at its place in block order, a stable sort by size, next fit. Sizes are powers of two in falling order, so every instance but the last is full and a check has `ceil(N / 2^B_c)` instances: one up to `2^25`, two at `m = 26`, three or four for `27 <= m <= B + 2`, A8's count above. The count is not monotone: exactly `2^27` positions give four instances, slightly more give three.
- A planner written from the three amendments (cut, order, next fit, names, identifiers) equals `plan` under two source sets, `plan_segmented` and `plan_recursive` on 400 random relations: 803 checks, 121 of one instance, 548 of two to four, 134 above `2^32` positions, 910 placed blocks.
- Per segment: with `2^28` positions of one table in segment 0 and `2^24` in segment 1, the segmented and recursive plans give four blocks of `2^26` in segment 0 and one unsplit check in segment 1. Counted over both segments, `B_c` would be 27.
- A last instance of one position proves and verifies (member sizes `2^2, 2^0` and four other shapes under bounds 1 and 2).

### 3. Nothing new to bind [read; ran, arm64]

- An instance is a `Check` of the plan with its own identifier. Its statement, absorbed before its `(β, α)` draw, holds the identifier, its size and each member's size (`relation_lookup.rs:27-44`, `352-380`). Its multiplicities are committed before any lookup draw: one source per instance (`relation.rs:3225-3241`), or one slot of the segment's stack under byte 6 (`relation_recursive.rs:871-888`).
- Every member, or every block of a cut member, lies in exactly one instance, and a block's value is the column's claim at `(bits(block) ‖ z_low)` (`relation_lookup.rs:467-479`). This holds for any bound in `1..=30`, so the choice of `B_c` affects cost and completeness, not soundness.
- The verifier's ledger has one LU, two RLC and three SC lines per instance (`relation_lookup.rs:708-737`, `854-879`).
- No proof byte and no input selects `B_c`. A bound is an argument only in tests and under the `controls` feature (`relation.rs:4734-4769`), as ADR-155 records.
- The dev-zk plan builds one lookup per table and does not split (`zk_relation.rs:199-291`). It is unchanged, as under A8.

### 4. A plan whose checks hold at most `2^25` positions is unchanged [read; ran, arm64]

- For `N <= 2^25` and `B = 30`: `B_c = 25`, no member exceeds it, one bucket, the unsplit name, the same index. Under a test bound `B < 25`, `B_c = B` for every `N`.
- `scripts/gates/digest.sh` reproduces the six pinned L0 and L1 proofs.
- The independent byte-5 replay accepts the one-layer and eight-layer windows dumped at this commit and rejects 48 one-byte tampers of each.
- `stele-reductions`: 317 tests pass. NC-1341 passes.

### 5. L2a under profile byte 6 [ran, arm64]

- The proof is 3,971,461 bytes, SHA-256 `511a4e8b725f0f2c0d6bc1ccb8c1762063ac700130c7eb0220ccebee3a764fa5`. The public file has the SHA-256 the committed L2a ledgers record (`8da645cd…44b3`). `verify-dev` answers YES.
- The verifier derives 23 instances. `range_8` (74,202,368 positions, 1,012 members, the largest of `2^24`) is three: 2 members in `2^25`, 56 in `2^25`, 954 in `2^23`. **No member is cut** [instrument].
- Lookup positions are unchanged (203,484,736). The lookups section grows by 43,840 bytes and the framing by 8.
- Ledger, against the pre-amendment proof `afb3581b…67cb` under the base verifier:

| | Before | After |
|---|---|---|
| LU, RLC, SC lines | 21, 1,358, 3,068 | 23, 1,362, 3,074 |
| `range_8` LU numerators | 134,217,983 | 33,554,687; 33,554,687; 8,388,863 |
| `Rlc s0/mu_stack` | 21 | 23 |
| Rounds | 39,725 | 40,455 |
| `eps_interactive` numerator | 298,487,204 | 239,769,396 |
| Worst round | LU `range_8`, `2^-96.9` | LU `range_16`, `2^-98.9` |

- Rejected: four statement tampers (`RoundSumMismatch` three times, `Recursive(Merkle(RootMismatch))`); ten single bytes in sections of the split check and after it (`MemberSumMismatch` five times, `FinalEvaluationMismatch` three, `RoundSumMismatch` two); the pre-amendment proof under the new verifier and the new proof under the base verifier (both `Fraction(Sumcheck(RoundSumMismatch))`).

### 6. The byte-6 engine with cut members [ran, arm64, instrument]

- On the composed two-segment fixture (carried column, virtual columns, weights, two tables that are not a power of two), bounds 1 to 6 give 92, 46, 23, 15, 11 and 9 instances with 92, 46, 16, 8, 4 and 2 placed blocks.
- At each bound the honest proof verifies. One member value of a later block gives `MemberSumMismatch`. Two swapped sections of equal length give `RoundSumMismatch`. A weight outside its range in a later block gives `Fraction(RootMismatch)`. A verifier at any of the six other bounds rejects, by `RoundSumMismatch` or `FinalEvaluationMismatch`.

### 7. The rule on the windows, with the floor lowered to 3 [ran, arm64, instrument]

- Every check above 8 positions then splits by `max(3, m − 2)`. The one-layer windows have 52 to 75 instances and up to 28 placed blocks.
- `stele-prover --test development`: 16 of the 25 tests that run pass, among them the byte-6 windows with their tampers, the segmented windows, the false witness and the statement and container tampers. Nine fail on pins: eight proof digests after a successful prove and verify, and one section count.
- `stele-negative-controls`: 147 of 149 tests pass. The two that fail are F1.

## Findings

### F1 — BLOCKING: the rule changes byte-5 plans, which A15 §6.3 fixes and the independent replay derives by itself

- `build_a8_checks` serves `Sources::CircleAllGrind` through `plan` and `plan_segmented` (`relation.rs:913`).
- A15 §6.3 is Accepted and normative (`RFC-0026-development-end-to-end.md:1635-1656`): one check per table or width, `m = ceil_log2(Σ 2^m_i)`, and only `m > 30` is `Unsupported`. The replay is written from it. `crates/stele-verifier/src/plan.rs:551-604` builds one check per key. `development.rs:504-512` and `621-629` return `ProofShape` unless the proof has one multiplicity and one lookup section per derived check.
- **Input** [ran, arm64, instrument]: 8-bit ranges over columns of `2^26`, `2^22`, `2^21` and `2^19` entries, the relation of the committed plan test. The engine's byte-5 plan has three instances; `Plan::derive` has one check of 27 bits. Sizes (25, 25), (24, 24, 24) and (27, 27) give two, two and four instances against one check of 26, 26 and 28 bits. Up to `2^25` positions both have one.
- **End to end** [ran, arm64, instrument]: with the floor at 3, production proves and verifies the byte-5 eight-layer window, and the replay answers `Err(ProofShape)` to it (`crates/stele-verifier/tests/development_replay.rs:443`). At the audited commit the same test passes. NC-1325 fails the same way, on its honest registered replay.
- **Consequence, by inference from the two results:** a byte-5 proof of L2a made at this commit is refused by `stele verify-registered` and by `stele_verifier::development::verify`. I did not run L2a at byte 5.
- A8 already differs from §6.3 above `2^30`. There the replay refuses with `Unsupported`, as §6.3 says, and no rung is that large. A30 moves the difference to `2^25`, inside the sizes §6.3 supports.
- This is not a soundness break: the replay rejects an honest proof and neither verifier accepts a false one. It is INV-1, because two Accepted texts would disagree, and INV-11. The gate that keeps the replay in step (E8-02f1) holds only L0 and L1 windows.
- The amendment's "so the verifier derives it" is true of the engine's verifiers only.
- Requested, one of:
  1. Apply the rule under profile byte 6 only. No independent replay exists there, and the L2a rung runs there. Bytes 0 to 5 keep A8's `B`.
  2. Keep the rule on every engine plan, add to A30 the replacement text for A15 §6.3, and register the lane V task that brings `stele-verifier` to A8 and A30 with a parity window that holds a split check.
  3. Keep the rule and make the replay refuse `m > 25` (`plan.rs:585` and §6.3), so that it fails with a named reason.

  I would take 1.

### F2 — MEDIUM: "no round is added, removed or changed" is not true of a split proof

- `RFC-0026-development-end-to-end.md:2851`. The template allows "no change" only if true.
- L2a [ran, arm64]: `range_8` runs three `(β, α)` rounds, three pairs of trees and three selected products where it ran one of each. The proof has 730 more rounds, two more LU lines, four more RLC lines, six more SC lines and two more claims in the multiplicity stack's batch (table in item 5).
- What is true: no kind of round, label or binding is added. Every instance has `m_j <= m`, so no round's error grows; on L2a the worst round improves. The summed numerators of `range_8` fall from 134,219,271 to 75,501,461. The number of rounds grows.
- Under byte 5 each instance also has its own nonce, with grinding bits from `(c, 2^m_j, t)` (`relation.rs:865-869`) [read].
- Requested: say so, with the per-instance lines named (LU numerator `c·(2^m_j + t) − 1`, the tree lines of an `m_j`-bit and a `k`-bit tree, the selected product, one stack claim, and one prefix sumcheck when `t < 2^k`).

### F3 — MEDIUM: seven mutants of the rule's use pass every committed test

Against the 58 tests of the relation engine; U1, U5, U8 and U11 also against all 317 tests of `stele-reductions` [ran, arm64, instrument].

| Mutant | Line | Result |
|---|---|---|
| floor 24; floor 26; `m − 1`; `m − 3`; `m` one too many at a power of two; `m = floor(log2 N)`; no cap at `B`; minimum for maximum; wrapping `m − 2`; rule off | `relation.rs:655`, `662-663` | all ten killed, by `matches_reference_instance_bound_of_a_check` or both new tests |
| `N` doubled; instances packed to `B`; members cut at `B`; ranges keep `B` | `913-914`, `930-935` | killed by `matches_reference_split_of_a_check_above_the_floor` |
| U1: `N` is the largest member | `910-912` | **survives** |
| U2: `N` is the first member | `910-912` | **survives** |
| U3: `N` halved | `913` | **survives** |
| U5: a check's bound carries to the checks after it | `907-913` | **survives** |
| U8: tables keep `B`, only ranges follow the rule | `913` | **survives** |
| U11: `N` is the number of members | `910-912` | **survives** |
| U10: wrapping sum | `911` | survives; equal unless a check holds `2^64` positions |

- The plan test's large check has `m = 27`, and `B_c = 25` for any `N` up to `2^27`. Its second check has `2^25` positions. Both are ranges. No other committed test holds a check above `2^25` positions.
- Requested: one more plan-only test. Table `ta` is read by one lookup of `2^26` positions; table `tb`, after it, by two lookups of `2^27`. Expected: `ta/inst0` and `ta/inst1` of 25 bits, then `tb/inst0` to `tb/inst3` of 26 bits, asserted on `plan`, `plan_segmented` and `plan_recursive`. It passes at the audited commit and kills U1, U2, U3, U5, U8 and U11 [ran, arm64, instrument]. The test was returned with this record.

### F4 — MEDIUM: no committed test proves a split check through the byte-6 engine, and L2a does not cut a member

- `plan_recursive_with_bound` takes a bound (`relation_recursive.rs:358`), but only `plan_recursive` calls it, at 30. The module's tests (`1972-2339`) and the byte-6 windows of `stele-prover` hold no check above `2^25` positions. The split is tested under small bounds in the plain and segmented engines only.
- The L2a ledger job covers the packing of whole members into three instances under byte 6. It does not cover a cut: L2a's largest member has `2^24` positions (item 5).
- Its four statement tampers are rejected before any lookup, by a zerocheck round or the model registration. They say nothing about the split.
- Requested: prove and verify entry points of the recursive engine that take a bound under `cfg(test)`, and the composed fixture under bounds 1 to 6 with the four rejections of item 6. Add one tamper inside a split instance to the L2a controls, for example the last member value of `range_8/inst1` (`MemberSumMismatch`).
- With those, the gap above the floor is acceptable at the development tier: the rule on real sizes by L2a, the cut by the fixture.

### F5 — MEDIUM (`forbidden.md`, INV-14): numbers without a ledger at the audited commit

| Statement | `RFC-0026…md` | In the tree | My check |
|---|---|---|---|
| 74,202,368 positions, `2^27`, 45% padding | `2839-2840` | `e20-03-dev-stories42m-t64-byte6-24t.json` | arithmetic holds |
| 3,927,613 bytes before | `2860` | same ledger | — |
| 3,971,461 bytes after | `2860` | none | reproduced, item 5 |
| its trees are the prover's peak memory; smaller instances run faster | `2840-2841` | none | not checked |
| 25 is the lowest floor within 4 MB | `2861` | none | size model: 4,025,565 bytes at floor 24, where `range_16` and `range_13` also split; not run |

- The commit message says the ledgers follow. Acceptance waits for them. The last row needs a measurement or the words "by the section sizes".

### F6 — LOW: sentences of the amendment that say more, or less, than the code

- **Title and `graph.yaml:4533`:** "at most four instances" holds up to `m = B + 2` only.
- **`N`** (`2845-2846`): say `N = Σ 2^m_i` over the check's members in its segment (A27), before any cut. The code does this; the text leaves the segment to A27 and A28.
- **"keeps its bytes"** (`2852`): true of a proof whose checks are all that small. In a proof with a split check, the checks after it take later identifiers. On L2a `range_1` moves from index 6 to 8.
- **"has another shape and is rejected"** (`2856-2857`): rejected, yes. In the plain engine by `ProofShape` at the multiplicity sections (`relation_tests.rs:4251-4266`). Under byte 6 the multiplicity list does not show the instance count, and the first instance whose statement differs fails a tree round (`RoundSumMismatch`; items 5 and 6).
- **25** is a literal where `B` is a named profile parameter. Name it.
- **Reach:** A8's Scope line names `plan` and `plan_segmented` (`991-992`). A30 does not say that it also reaches the recursive plan and leaves dev-zk alone.
- **A8's note** "At `B = 30` only a check above `2^30` positions splits" (`985`) is Accepted text that A30 makes false. Give its replacement.

### F7 — LOW: the per-check counters change shape, and the static accounting does not

- The engine's `lookup_checks` has one entry per instance in the plain and recursive provers (`relation.rs:2385-2392`; `relation_recursive.rs:779-788`). The segmented prover merges by name (`relation.rs:4020-4030`).
- L2a [ran, arm64]: 23 counters, `lookup_positions_check_5_range_8_inst0 33554432` to `…check_7_range_8_inst2 7093504`, then `…check_8_range_1`. `e18-05-static-accounting-l2a.json` has 21, with `…check_5_range_8 74202368` and `…check_6_range_1`.
- `accounting.rs:85` promises the engine's order, and its test asserts equality on L0 (`accounting.rs:631`). With the floor lowered that test fails.
- `bench/dev_e2e.py:134` only sums the counters, and the sum holds. The scoreboard reads totals.
- Requested: sum the instances of a check under its name in the engine's report, or say in the ledger note that the counters are per instance.

### F8 — LOW: comments, and a counter beside the change

- `relation_tests.rs:3993-3996` and `graph.yaml:4548` call the test's relation "the shape of L2a's largest check". The instance sizes agree. L2a's check has 1,012 members and no cut; the test's has four members and cuts one.
- The plan test asserts `plan` only.
- `relation.rs:995-996` still says unsplit plans are those whose targets total at most `2^B`.
- Not in the diff, reachable through it [read]: the recursive prover counts the weight reads of a selected member without the block base (`relation_recursive.rs:895-905`). The plain and segmented provers add it (`relation.rs:2402-2412`, `4054-4066`). Counters only.

### F9 — LOW: process

- The code implements a Draft (Workflow 02 step 6, INV-1). The commit message says so; the branch must not merge while A30 is a Draft.
- At acceptance: the status line with its ADR and this record, RFC-0000's list for RFC-0026, and F6's note on A8.
- The ADR should record that a lane E task edits lane P's relation engine and sits on E18-11 and E20-25 (RFC-0027 §5).

## Design questions

- **A floor fixed at 25.** Sound, because any deterministic function of the relation is. Not stable: 25 is where one proof on one rung meets one gate with 28,539 bytes (0.7%) to spare. One more instance of `2^25` positions over an 8-bit table costs 25,348 bytes, and `range_16` is 2.5% under `2^25`. When L2a's relation moves, the floor will move, and each move changes the bytes of every proof above it. Name the parameter and say in the ADR what triggers a change.
- **Bytes on larger shapes.** Counted from the positions per check of the `e18-05-static-accounting-*` ledgers with the size model. These ledgers treat a window as one segment; a segmented run counts per segment, so this is not a prediction of an L3 proof. Table checks are costed as ranges.

| Rung | Instances, A8 → A30 | Added lookup bytes | Padded leaves over positions | Largest instance |
|---|---|---|---|---|
| L2a | 21 → 23 | 43,848 (measured) | 1.45 → 1.16 | `2^27` → `2^25` |
| L2b | 21 → 44 | about 0.63 MB | 1.38 → 1.05 | `2^29` → `2^27` |
| L3a | 29 → 56 | about 0.74 MB | 1.10 → 1.05 | `2^30` → `2^30` |
| L3b | 85 → 104 | about 0.54 MB | 1.04 → 1.02 | `2^30` → `2^30` |

- **Simpler or safer rules.**
  - A plan-wide `B = 25` gives the same L2a plan and about 2.0, 9.1 and 61.6 MB more on L2b, L3a and L3b. The `m − 2` term is needed.
  - `max(25, m − 1)` gives 3,947,857 bytes on L2a by the model, the same padded leaves, and a largest instance of `2^26`. I have no measurement of its time or memory. If the comparison exists, record it.
  - The same rule under byte 6 only (F1, option 1) has the same effect on the L2a rung and leaves bytes 0 to 5 and the replay alone. That is the safer form.
  - Most of the gain on L2a is padding. A tree builder that skips an all-padding suffix would get that with no byte and no amendment, in lane E's own crate. It would not lower the largest real tree. Worth one line in the ADR as the alternative considered.

## Review checklist

- **RFC section of each new public item:** `SPLIT_FLOOR` cites RFC-0026 A30, a Draft (F9). `rfc-status` passes.
- **Challenges:** none added or relabelled. A split check draws `(β, α)` once per instance, after that instance's statement, units, multiplicity binding and repetition absorbs.
- **Claims:** an instance's member values become column claims at `(bits(block) ‖ z_low)`; its table claim goes to its multiplicity source, or to the stack under byte 6. Same consumers as A8.
- **New binding:** none. NC-1341 runs at `B = 2`, where the rule is inert; it passes.
- **Ledger:** per-instance lines; L2a in item 5; F2. `soundness-accounting.sh` not run as a whole.
- **Bound certificate:** no new instance. `B_c` is static.
- **Padding and masks:** unchanged per instance; padded leaves fall.
- **Determinism:** no hash map, clock or environment read; stable sorts. My L2a proof has the digest the commit message states.
- **Parity:** CPU, arm64 only. SIMD and CUDA not run.
- **Cost model:** no term claimed.
- **Verifier:** `no_std`, no new panic path, lengths from the plan. The independent replay: F1.
- **Glossary:** `glossary-lint` passes.
- **Tier:** development; the amendment says so and claims no level.
- **Commit rule:** no column added or made virtual.
- **Plain checker:** untouched; its tests are among the 317.
- **Segments:** the rule is per segment; no read across segments is added.
- **Proof bytes:** unchanged below the floor, pins reproduced. Changed above by A30. No L2a digest is pinned; the ledgers will carry it (F5).
- **Ladder:** L0 and L1 digests, L2a prove and verify. No ledger pair in the tree (F5).

## What I ran

arm64, at `34a73902`, no file changed:

- `cargo fmt --check`; `cargo clippy -p stele-reductions --all-features --all-targets -- -D warnings`.
- `cargo test -p stele-reductions --all-features`: 317 pass (206 library, 84 integration, 27 doc).
- `scripts/gates/digest.sh`; the gates `rfc-status`, `glossary-lint`, `docs-links`, `ledger-validate`, `rust-policy`; `scripts/tests/test_task_graph.py`.
- `cargo test -p stele-negative-controls --all-features --lib`: 25 pass.
- The E8-02f1 replay: `dumps_byte5`, then `stele-verifier --test development_replay`.
- L2a at byte 6: `prove-dev`, `verify-dev`, `rejects_tampers_on_a_supplied_proof`, ten edited proofs, the pre-amendment proof.
- At `ff75b89e`: `verify-dev` of both L2a proofs.

arm64, instrumented:

- Six review tests; the plan dump through `verify-dev`.
- 21 mutants against the 58 relation-engine tests; four survivors against all 317; the proposed test against seven mutants.
- Floor 3: `cargo test --release -p stele-prover --all-features`; `cargo test -p stele-negative-controls --all-features`; the E8-02f1 replay.

## Not checked

- x86, the reference class, and the ledgers being recorded. Time and memory: my host was loaded.
- L2a at byte 5 or at bytes 0, 2 and 3. A segmented L2a. L2b, L2c and L3 beyond the static accounting ledgers.
- `cargo test --workspace`, `scripts/gates/native.sh` as a whole, `soundness-accounting.sh`, `scripts/ci_tests.py`, and the full negative-control suite at the audited commit.
- CUDA, SIMD parity, the dev-zk provers beyond reading that their plan does not split.
- The weight-read counter of F8 by a run.

I tried to break it by comparing `check_bound` with the text on 200,390 values of `N` under every bound; by planning 400 random relations through the three planners against a planner written from the amendments; by proving L2a and editing ten bytes of its split sections, feeding it four false statements and the proof made under the old rule; by running the byte-6 engine on cut members under six small bounds with a false member value, swapped sections and an out-of-range weight; by lowering the floor so that the L0 windows and the 149 negative-control tests ran on split checks; and by 21 mutants. The engine's verifiers rejected every false proof, the two new tests rejected every mutant of `check_bound`, and with the floor lowered every negative control but the registry's still rejected for its stated reason. Nothing committed rejected seven mutants of the rule's use, nothing committed runs a split check through the byte-6 engine, and the independent replay rejected an honest byte-5 window once its check was split, which is why this is not an approval.

## Resolution

By the author, in the commit that adds this record. The audited commit is unchanged; the
fixes are in this commit, above three commits of other tasks on the same branch
(E18-12, E22-12, E20-24).

| Finding | Status | Change |
|---|---|---|
| F1 (BLOCKING) | Resolved, option 1 | The rule applies under profile byte 6 only: `build_a8_checks` takes a check's own bound when the sources are `CircleRecursive` and A8's `B` otherwise. A30 says so, and names A15 §6.3 and the independent replay as the reason. The plan test asserts one instance per check for bytes 3 and 5. |
| F2 | Resolved | The soundness note says that the number of rounds grows, names the lines of each instance, and gives the L2a counts of item 5. |
| F3 | Resolved | The proposed test is committed as `matches_reference_bound_of_each_check_from_the_sum_of_its_members`, on the recursive plan, with the unsplit plans of the plain and segmented planners beside it. Mutants U1, U3, U8 and U11 fail it, and so does the rule applied under every profile. |
| F4 | Resolved | `prove_recursive_with_bound` and `verify_recursive_with_bound` take the plan bound; only tests pass another one than the profile's. `rejects_tampers_of_split_checks_under_small_bounds` is the reviewer's test of the composed fixture under bounds 1 to 6. The supplied-proof control changes one member value of every lookup instance: on the L2a proof, 23 instances, each refused by the engine. |
| F5 | Resolved | Ledgers `e20-26-*` (this rule, at the audited commit) and `e18-11-*` (the commit below it) are in the tree, and A30 cites them. The proof at floor 24 was measured: 4,025,565 bytes, one arm64 run; A30 says so. The two sentences on peak memory and speed are replaced by the ledger figures. |
| F6 | Resolved | Title, `N` per segment and before any cut, what "keeps its bytes" covers, how a differently split proof is rejected, the named floor `F`, the reach of the rule, and the replacement of A8's note are in A30. |
| F7 | Resolved | The recursive prover reports one counter per check: the instances of a split check are summed under its name, as the static accounting has them. |
| F8 | Resolved | The plan tests are in the recursive module and say what they share with L2a. The comment on unsplit plans is corrected. The weight-read counter of a cut member's selector reads its block. |
| F9 | Open until acceptance | A30 stays a Draft in this commit. The status line, ADR-158, RFC-0000 and this record's link are added with the second pass. |

Design questions:

- The floor is a named parameter of the amendment (`F`, `SPLIT_FLOOR`). ADR-158 will record that it is set by L2a's proof budget and what moves it.
- `max(F, m - 1)` was probed and not recorded in a ledger, so no figure is given for it.
- A tree builder that skips an all-padding suffix is the alternative without new bytes. It would not lower the largest real tree, and is not built.

The resolution is sent back to the same reviewer; its second record is appended below
when it returns.

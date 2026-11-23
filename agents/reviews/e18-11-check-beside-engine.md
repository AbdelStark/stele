# Soundness Audit Review — byte-identical prover stack on `task/E20-26-check-instance-bound` (tasks E18-11, E20-25, E18-12, E22-12, E20-24, E20-27, E21-11)

- **Tasks:** `E18-11`, `E20-25`, `E18-12`, `E22-12`, `E20-24` (reverted), `E20-27`, `E21-11`
- **Audited commits**, oldest first, at the tip `7ae31794` (branch merged with `main`). Line numbers are those of `7ae31794`.
  1. `b6a238b5` (E18-11) the plain check beside the engine for relations with virtual columns
  2. `73ce0e35` (E18-11) a computed column of the plain checker in 32-bit entries
  3. `795b4024` (E20-25) the verifier evaluates a lookup selector's extension from its members
  4. `89995c5c` (E18-12) the model commitment beside the executor's passes
  5. `2a43f239` (E22-12) a block of the point cache per table descriptor
  6. `aa00db2b`, `0ce36ea0`, `c8747289`, revert `3155d46e` (E20-24): net diff only
  7. `9ff19d58` (E20-27) folds release their half; the batch folds its coefficients first; the eq suffix is halved on the pool
  8. `1f2bfba1` (E21-11) the CLI re-executes itself once with `GLIBC_TUNABLES`
- **Out of scope:** the kernel commits up to `bc476b45` and the A30 commits `34a73902`, `c4907fe6`, `cc2c8ebc` (own records).
- **Reviewer:** independent `soundness-auditor` agent; did not write the change
- **Claim under review:** no proof byte, no public byte and no verifier decision changes
- **Tier:** development
- **Verdict:** **CHANGES REQUESTED** (no BLOCKING finding)

## Summary

I found no input on which a proof byte, a public byte or a verifier decision differs.

- **Pinned digests.** `scripts/gates/digest.sh` passes at the tip: six L0 and L1 proofs by bytes, FNV-1a and SHA-256. The CLI path that commit 4 changed reproduces the pinned L0 digests of profile bytes 3 and 6.
- **Commit 3, the one that changes verifier code.** Old and new selector evaluation agree on 9.3 million points over 578,752 checks of 6,460 plans from the three planners, instance bounds 1 to 12, and on every refusal of an entry other than 0 or 1. Eleven one-line mutants of the new arithmetic and of the new constructor fail a committed test.
- **Commit 1.** One changed witness value ends in `Check` and returns no proof, under the default sources and under profile byte 6, for a value a committed-column constraint catches and for a value only a virtual column's definition catches, also when the engine itself errs on that witness. With the check's result ignored the committed test fails. The CLI writes no file for a false statement under either profile.
- **Commits 4, 5 and 7.** Each mutant of a guarded behaviour fails a committed test.
- **Commit 6.** Nothing of the experiment remains.

Why this is not an approval: Workflow 03 lets me approve only when a control rejects what I break. One break has no control. A verifier whose selector closure answers the proof's own values at both points, and never evaluates the selector, passes every committed test I ran and all 164 registered negative controls; it accepts a forged proof of a false statement on the plain, the segmented and the recursive engine (F1). Commit 3 rewrote exactly that call. Two smaller things block as well: a decision record that is cited and does not exist (F2), and a re-exec whose "once" I could not confirm and believe is false in one deployment (F3, read only).

I would approve this tree with F1 and F2 closed and F3 closed or refuted by one run on Linux. F4 to F8 are LOW.

## Evidence labels

- **[arm]**: ran on this host: Apple arm64, 16 CPUs, rustc 1.90.0, `--locked --offline`, own target directories.
- **[read]**: by reading only.
- Nothing ran on Linux, on x86 or on a GPU. Commit 8's function is compiled on Linux with glibc only, so every statement about it is [read].

Instruments, in scratch copies only (`<scratch>` is the directory of this file):

- `src`: the tip, untouched. `mut`, `mut2`: the tip, one mutant at a time, restored after each (`tools/mut.py`, `tools/mutants.json`, `tools/run_mutant.sh`). A mutant *survives* a test set when every test passes after a successful build.
- `exp`: the tip plus review seams and tests that touch no verifier function:
  - `fraction::review_mle_base`, a public door on the private `mle_base`;
  - `REVIEW_CHECK_WITH_HOOK`, which keeps the plain check on when a hook tampers with the witness;
  - `review_forge`, a test-only prover that clears one entry of its selector before it builds its tree and its selected product;
  - tests `tools/review_selector.rs`, `tools/review_false_witness.rs`, and the forgery tests of `tools/apply_exp_forge.py`.
- `tools/review_controls.rs`: runs the committed `(control.run)()` of registered controls by id. The committed catalog-wide test needs more than 168 s here, longer than one command may run in this environment.

## What holds

### 1. `b6a238b5`: the plain check beside the engine [read; arm]

- Both unsegmented paths with virtual columns call `parallel::gated(plain_gate, engine)?` (`development.rs:839-850`, `928-940`). `gated` returns the gate's error before it looks at the engine's result, and catches an engine panic (`parallel.rs:200-217`; unit tests at `parallel.rs:445-463`).
- The engines take lent values (`Borrow<Values>`); the diff reads the same values and changes no transcript call.
- **One changed value** (scratch seam, L0 one-layer, T = 4: 365 witness columns, 315 virtual columns, 787 constraints of which 369 read a virtual column). Each value stays inside its declared width. Under `CircleAll` and under `CircleRecursive` alike:

| Change | Caught by | Checked run | Without the check |
|---|---|---|---|
| `L0/norm1/sigmaX[63]` 0 → 1 | a committed-column constraint | `Check(Lookup "L0/norm1/sigmaX", 63)` | proof written; verifier: `Fraction(RootMismatch)` |
| `L0/norm1/h[196]` 0 → 1 | a committed-column constraint | `Check(Range "L0/norm1/pos/range", 3)` | engine error `Sumcheck(RoundSumMismatch)` |
| `G/embedding/sigma[21]` 0 → 1 | only constraints that read a virtual column | `Check(Lookup "G/embedding/sign", 21)` | proof written; verifier: `RootMismatch` |
| `L0/norm1/X1[49]` 0 → 1 | only constraints that read a virtual column | `Check(Range "L0/norm1/X0/range", 49)` | engine error `Sumcheck(RoundSumMismatch)` |

  "Only virtual" means: with every constraint that reads a virtual column skipped, `check_except` accepts the changed witness. In every checked run the error equals the plain checker's first violation and no proof bytes come back. Rows 2 and 4 show the gate winning over a real engine error.
- **Committed test under mutation.** With the check's result ignored at the recursive site (P1) or at the segmented site (P2), `rejects_false_witness_with_check` (`tests/development.rs:428`) fails: a proof comes back ("CircleRecursive next: None", "CircleAll next: None").
- **CLI.** `stele prove-dev` on L0, T = 16, with a false next token and with a false checked token, under profile byte 3 and under `--dev-profile 6`: exit 1, last line `NO: Check(Range { relation: "G/argmax/margin", .. })`, and neither `public.bin` nor `proof.bin` exists afterwards. The CLI writes both files only after `prove` returned `Ok` (`main.rs:421-438`).

### 2. `73ce0e35`: narrow computed columns [read; arm]

- `ColData::computed` returns the narrow form only when every entry is `Some` and fits `i32`; otherwise it returns the vector it was given (`check.rs:47-56`). `get` and `eval_column` widen a narrow entry with `i128::from` and `i64::from`.
- A narrow column is now a typed operand of `contract`. The kernel returns `None` unless its magnitude bound keeps every sum inside `i64`, and the caller then takes the checked loop (`contract.rs:78-86`, `check.rs:164-170`).
- Mutants: an entry truncated to `i32` (I1) and a narrow entry read as its absolute value (I4) fail `stele-ir`'s tests. F6 lists what survives.

### 3. `795b4024`: the selector's extension from the members [read; arm]

- **Inputs.** `sigma_at(check, relation, z)` (`relation_lookup.rs:74-93`) reads the plan's `check`, the public `relation` and a point. Its two callers pass the point of the left tree's reduction and the point of the selected product's sumcheck, both drawn by the verifier (`selected.rs:328`, `413`). No proof byte reaches it.
- **Why it is the vector's extension.** `check()` sorts members by size and adds their sizes, so every block is aligned and disjoint (`relation.rs:851-856`). On a block the vector is one for an absent selector, and `v[r.index(block | local)]` for a public one. Summed against `eq`, the bits the reference does not read sum to one, which leaves the sum over the read bits (`relation_lookup.rs:105-135`). `eq_table` is MSB-first (`stele-poly/src/lib.rs:58-75`), as the coordinates are ordered.
- **Refusals.** Old: `SourceShape`, then `Selector` for any entry other than 0 or 1, then `SelectorMismatch`. New: the same three in the same order; the set of entries read is the same, because bits a reference does not read do not change its index.
- **Differential, old against new.** Old is `Selector` for a non-binary entry of `sigma_base`, else the private `mle_base` of the vector, both untouched by the commit. New is `sigma_at`.

| Planner | Relations | Plans | Checks | Points | Cut members | Selectors reading a block bit | Padded checks | Refusals by both |
|---|---|---|---|---|---|---|---|---|
| plain (CircleAll, CircleAllGrind, Expander) and segmented | 160 | 5,440 | 508,788 | 8,168,508 | 493,456 | 170,968 | 4,516 | 13,901 |
| recursive (profile byte 6) | 120 | 1,020 | 69,964 | 1,123,890 | 66,800 | 25,122 | 874 | 2,987 |

  - Shapes: absent, natural, permuted and narrower selectors, with all-zero, all-one and random entries; one to three tables; instance bounds 1 to 12.
  - Points: extension points with every limb drawn from a transcript; every Boolean point of a check up to 2^9 positions (5,241,134 Boolean points, each also compared with the vector's entry); mixed and base-field points; points one coordinate short and one long (`SourceShape` for both).
  - Entries set to 2, 3, −1, p−1, p, p+1, p+2, −p, 2p, 2p+1, `i64::MAX`, `i64::MIN`: same answer from both every time.
  - No difference. With the block bits read as zero the two tests fail at their first case, so the differential sees what it should.
- **Mutants killed by committed tests.**

| Mutant | Line | Killed by |
|---|---|---|
| M3a member coordinates from the front of the point | `relation_lookup.rs:85` | `matches_reference_selector_extension_of_the_selector_vector` |
| M3b read bits not reversed | `:115-119` | same |
| M3c block bits of a cut member read as zero | `:121` | same |
| M3d an entry other than 0 or 1 read as 0 | `:131-133` | same |
| M3e absent selector counts zero | `:82` | same |
| M3i block weight dropped | `:90` | same |
| M3j a block bit taken for a local bit | `:109` | same (panic) |
| M3f no comparison at the incoming point | `selected.rs:328` | `matches_reference_selected_product_and_rejects_the_same_selectors` |
| M3g final value taken at the incoming point | `:413` | same |
| M3h no comparison at the final point | `:415` | same |
| M3p proving from the evaluated form not refused | `:516` | same |

- **The forgery, on the tip.** A selected lookup into {0, 1}; position 2 is selected and holds 2 (in range, out of table); the plain checker says `Lookup, point 2`. The honest prover's proof is refused with `Fraction(RootMismatch)`. A forging prover that clears that selector entry before building its tree and its product is refused with `Fraction(SelectorMismatch)` by `verify` (plain and segmented) and by `verify_for_stack` (joined recursion). The binding holds; F1 is about what guards it.
- `crates/stele-verifier` has no changed file between `bc476b45` and the tip.

### 4. `89995c5c`: the model commitment beside the executor [read; arm]

- `complete_statement` is the moved code. `Committed::new(&weights)` reads only the weights; the executor's closure owns `statement` (`development.rs:1401-1415`).
- **Bytes.** The debug CLI binary of the tip proves L0 with SHA-256 `6614e2d3…87aa` (byte 3) and `b2437e14…68f3` (byte 6), the pinned digests. `accepts_one_layer_measured_with_unchanged_proof_bytes_and_stage_counters` pins bytes 3 and 5 through this path.
- **Error order, acceptable.** A weight decode error now precedes an executor error. Under dev-zk the `segment_layers > 0` refusal precedes statement completion. The capture's error still precedes the commitment's. A failing executor pass now waits for the commitment before it returns. Every case ends in an error and no proof.
- Mutants: capture before completion (C4a) and no completion (C4b) fail three committed tests each.

### 5. `2a43f239`: point-cache blocks [read; arm]

- A hit still requires `old == d && input == t` (`points.rs:51`); `Descriptor` derives equality over kind, parameters and shape. `slot < BLOCKS << 16` always. So a hit returns a value certified earlier for the same descriptor and input.
- `Gaussian` keeps lazily built normalizers; each is a function of its precision alone, and the first certification of each point happens in the same order as before [read].
- Mutants: a hit on the input alone (C5a), a fifth descriptor sharing the first block (C5b), one block for all (C5c) fail `matches_reference_points_of_descriptors_that_share_inputs`; C5a also fails a capture test.

### 6. E20-24, reverted [arm]

- `git diff 2a43f239 3155d46e -- crates/stele-sumcheck` is empty.
- The whole-tree diff `2a43f239..3155d46e` equals `git diff aa00db2b c4907fe6`, the A30 resolution commit alone, after hunk offsets are normalised (1,697 lines each, `cmp` identical). The task entry is back to `ready`.

### 7. `9ff19d58`: released folds, pooled suffix [read; arm]

- `release` calls `shrink_to_fit` only: capacity changes, values do not (`parallel.rs:316-320`).
- The batch folds `coeff` and makes the folded table from the untouched base table; the two do not read each other (`claim_batch.rs:252-254`).
- `halve_suffix` adds `high[start + i]` to `low[start + i]` per chunk: the same sums (`tree.rs:227-240`).
- Callers of `fold`, `halve_suffix` and `release` outside tests are `Summand::fold` implementations and the batch and zerocheck provers [grep; `zk_claims.rs:2237` not opened].
- Mutants: never release (S7a) and always release (S7b) fail `matches_reference_fold_and_releases_the_folded_half_of_a_large_table`; a suffix chunk reading the first entries (S7c) fails `large_trees`; a table folded with another challenge (S7d) fails `matches_reference_base_first_round_zerocheck_and_claim_batch`.

### 8. `1f2bfba1`: the re-exec [read]

- A set variable is kept, including an empty one (`var_os(..).is_some()`, `main.rs:673`).
- The exec is the first statement of `main`: before any file is opened or locked and before the pool starts.
- Arguments go through `args_os`, so bytes that are not UTF-8 survive. The environment is inherited with one addition.
- The process image is replaced in place: same PID, so the caller sees the new image's exit status and signals.
- `current_exe` failing skips the exec. An exec that fails returns and the run continues.
- To my knowledge a glibc that predates the tunable ignores it.
- What does not hold is F3 and F4.

## Findings

### F1 — MEDIUM (INV-4, Workflow 03): no control sees the selector binding at the relation level

- **Where:** `crates/stele-reductions/src/relation_lookup.rs:667-674` (`verify`) and `:842-849` (`verify_for_stack`).
- **Mutant W3.** In both functions the closure handed to `new_evaluated` answers `lookup.claims[0].1` at the incoming point and `leaf_proof.final_values[1]` at any other; `sigma_at` is never called.
- **It passes** [arm]:
  - `stele-reductions --all-features`: 207 of the 208 library tests (the one left out is a plain-checker survey) and the 17 integration binaries (84 tests);
  - `stele-prover --test development`: 25 of 25;
  - all 164 registered negative controls, executed by id: 162 in one piece, NC-1302 and NC-1308 alone. The same 164 pass on unmutated code.
- **It accepts a false statement** [arm]: the forged proof of section 3 returns `Ok(())` from the plain, the segmented and the recursive verifier under W3.
- **Why nothing notices.** Tests expect `SelectorMismatch` only from the A5 lookup verifier (NC-0402), inside `stele-lookup` (NC-0409, `base_parity.rs`, `selected.rs`) and from the independent verifier's own fraction corpus. None reaches these two functions with a selector that differs from the plan's.
- The tip is right. The commit rewrote the verifier's side of this binding, and its two tests stop one level below the call.
- **Smallest fix I would accept:** one control, three verdicts.
  - *Where it runs:* `relation::tests` for `verify_with_instance_bound` and `verify_segmented_with_instance_bound`, and `relation::recursive::tests` for `verify_recursive`; registered in `tests/negative-controls` under a new id citing RFC-0026 §3.3 and RFC-0008 A3.
  - *What it tampers:* a prover seam of the kind `Check` already has (`skew`, `split`, `shift`, `count_override`; under `test` and the `controls` feature). The prover clears exactly one selected entry of its selector vector, at a position holding an in-range, out-of-table value, before it builds the left tree and the selected product. Everything else is honest.
  - *What it must see:* `Error::Fraction(fraction::Error::SelectorMismatch)` from each of the three verifiers, and `RootMismatch` for the same witness from the unforged prover.
  - `tools/apply_exp_forge.py` is such a control in 90 lines; it fails under W3.

### F2 — MEDIUM: `ADR-159` is cited and does not exist

- **Where:** `crates/stele-cli/src/main.rs:666` and `bench/dev_e2e.py:394`. `agents/context/decision-log.md` ends at ADR-158 (line 4905).
- Every ledger that `bench/dev_e2e.py` writes from now on carries the citation in its note.
- The decision is a real one: the CLI changes its own process by default.
- **Fix:** append ADR-159 (the default, the kept variable, what bounds the re-exec), or drop both citations.
- **Seen while writing this record, not audited.** The working tree of the main checkout (HEAD `aabe78dc`, after the audited tip) now holds an uncommitted `ADR-159` of 33 lines. F2 closes when it is committed. I read it once and did not review it. Two of its sentences meet findings below: "A variable the user set, to any value, is kept, so the re-execution cannot repeat" is the premise F3 questions, and "A failed `exec` … leaves the run as it is" is what the third line of F4 qualifies.

### F3 — MEDIUM, read only: the single re-exec rests on a variable the process does not control

- **Where:** `crates/stele-cli/src/main.rs:673-682`. The only thing that stops a second exec is `GLIBC_TUNABLES` being present in the new image.
- **Scenario.** A `stele` binary that runs in secure-execution mode: setuid or setgid bits, or file capabilities, for example granted to lock memory. As far as I know, glibc 2.39 and later remove `GLIBC_TUNABLES` from the environment in that mode, where earlier versions left an emptied variable. Then the variable is unset again after every exec, and the CLI replaces itself without end: no output, no exit, one busy core.
- **Not run.** This host has no Linux. The glibc behaviour is my recollection of its source, not an observation. One run on the Linux node of a `setcap` copy settles it.
- **Fix, right either way:** set a second, private marker on the exec and return when it is present, or skip the exec when `getauxval(AT_SECURE)` is set. Two lines.

### F4 — LOW, read only: other edges of the re-exec

- `current_exe` is `/proc/self/exe`. Under an explicit loader (`ld-linux-x86-64.so.2 ./stele …`) it names the loader. That exec succeeds, the loader is run with the CLI's arguments, and a run that worked before fails.
- `argv[0]` becomes the resolved path; `CommandExt::arg0` would keep the caller's.
- "A failed exec changes nothing" is not exact: `Command::exec` sets `SIGPIPE` to its default before `execvp`, so after a failed exec a write to a closed pipe kills the process by signal instead of failing a `println!`.
- The new image's environment is the one std re-encodes: entries without `=` are dropped and duplicates collapse.
- No test asserts the variable, the single exec or the failed-exec path. On Linux the CLI's integration tests spawn the binary, so the exec path runs there; nothing checks it.
- The e20-27 ledgers predate the commit (`ea232178`), so no ledger was yet produced by the binary that re-executes itself. The task is `in_progress`.

### F5 — LOW: the prover's test does not exercise "whatever the engine does"

- **Where:** `crates/stele-prover/src/development.rs:839-850`, `928-940`; test at `tests/development.rs:428-463`.
- With both sites turned into a plain join whose engine error is examined first (P5), `stele-prover --test development` passes 25 of 25: on the two committed false statements the engine does not err.
- It does err on other false witnesses (rows 2 and 4 of the table in section 1), and there P5 returns `Engine(Sumcheck(RoundSumMismatch))` where `Check` is due.
- `gated` itself is unit-tested, which is why this is LOW.
- **Fix:** one case whose engine errs, for example `L0/norm1/h[196]` 0 → 1, with the check on.

### F6 — LOW: three properties of the narrow form have no test

- **Where:** `crates/stele-ir/src/relation/check.rs:47-56`, `284`; test at `relation/tests.rs:798-824`.

| Mutant | `stele-ir` (43) | `stele-reductions` lib (207) | `stele-prover` (25) |
|---|---|---|---|
| I2 an overflowed entry (`None`) stored as 0 | survives | survives (with I3) | survives (with I3) |
| I3 `i32::MAX + 1` stored as `i32::MIN` | survives | survives (with I2) | survives (with I2) |
| I5 `eval_column` zero-extends a narrow entry | survives | killed (argmax, attention) | not run |

- The new test's narrow vector has no negative value. Its wide vector has `i32::MAX + 1` next to wider entries, so the first entry already decides the form. No test has an overflowed entry in a column whose other entries fit.
- **Fix:** three vectors in that test: a negative narrow entry; a column whose only wide entry is `i32::MAX + 1`, and one with `i32::MIN − 1`; a column with one overflowed entry, expecting the range to fail.

### F7 — LOW: the weight decode is counted in two stages

- **Where:** `crates/stele-prover/src/development.rs:1327` and `1409` (`witness_pre_timer`), `1394-1395` and `1413` (`model_commit_timer`).
- `witness_pre_timer` starts before the executor is made and now also spans `Weights::from_artifact_sources`. That decode is inside `model_commitment_ns` as well.
- The L2a ledgers show stage `witness` at 3.97 s in `e20-26-*` and 4.58 s in `e20-27-*` (3.58 s and 4.14 s with huge pages), while commit 5 made the executor's passes cheaper. `witness_recompute_ns` equals that stage. I did not measure how much of the rise is the decode and how much is the shared pool.
- The ledger note says the two stages overlap. It does not say that one interval is in both.
- **Fix:** start the witness span after the decode, or say so in the note.

### F8 — LOW: branches of the new verifier code that no plan can reach, and no test does

- Combined mutant U (the four below together) passes the `stele-reductions` lib (207) and `stele-prover` (25); M3n alone passes `stele-lookup` (27):
  - `relation_lookup.rs:75-77`: a point of another length is not refused (M3m);
  - `:87`: a selector column that is not public counts as one (M3l);
  - `:111-112`: no deduplication of read bits (M3k);
  - `selected.rs:322-326`: no shape check in `new_evaluated` (M3n).
- `Relation::validate` makes a lookup selector a public 0/1 column read through distinct domain bits (`stele-ir/src/relation.rs:1393-1422`, `1487-1496`), and every planner validates first. So the first three are unreachable, and the fourth compares two shapes the verifier derived.
- **Fix:** a comment at each naming that reason, or a test. Not blocking.

Notes that are not findings:

- P4 (`single_segment` lends any index) survives; a one-segment plan asks for index 0 only.
- The point cache is now four blocks. The fixed 2^26-byte term of `Executor::admit` did not change. I did not measure an entry's size.
- With lent values the engine no longer frees a segment's values at the end of its reductions; the caller holds them to the end. That is memory, not bytes; commit 2 is the answer to it.
- `/tmp/claude-501/net.diff` (104 KB) was written outside the scratch directory by a mistyped redirect of mine. It is left in place.

## Review checklist

- **RFC section of each new public item:** `SelectorAt` and `SelectedProduct::new_evaluated` cite RFC-0008 A3; `sigma_at` cites RFC-0008 A3 and RFC-0026 §3.3. `parallel::release` cites none in its comment (the commit names RFC-0006 A1). `huge_pages` cites ADR-159 (F2).
- **Challenges:** none added, moved or relabelled. `bind` and every absorb of the lookup section are unchanged.
- **Claims:** none emitted or moved. The selector's claim and its final value meet the same two comparisons, now against a public evaluation computed from the relation.
- **New binding and its control:** no new binding. The existing selector binding has no control at the relation level (F1).
- **Ledger and accounting:** no ledger line changes in the diffs [read]. `soundness-accounting.sh` not run.
- **Bound certificate:** no new instance.
- **Padding and masks:** padding stays unselected: `sigma_at` sums members only. The differential covers 5,390 padded checks.
- **Determinism:** no hash map, clock or float in the diffs. Pooled sums are exact field sums over disjoint ranges. The order in which cache blocks are owned does not reach a value. The CLI reads one environment variable that no computed value depends on.
- **Parity:** arm64 only; six pinned digests reproduce. x86 and CUDA not run.
- **Cost model:** time and memory claims rest on ledgers `e18-11-*`, `e20-27-*` (L1 and L2a, same host class, 24 threads) [read]; none reproduced. F7 on one stage.
- **Verifier:** `stele-verifier` untouched. `sigma_at` takes its lengths from the plan and indexes what the vector indexed; no new panic for a planned check [read]. `alloc` only.
- **Glossary:** `glossary-lint` not run.
- **Tier:** development; nothing claims more.
- **Commit rule:** no column changes kind.
- **Plain checker:** ran; `stele-ir` 43 pass; honest and false cases decide as before (section 1).
- **Segments:** unchanged; lent values serve one-segment plans only.
- **Proof bytes:** unchanged; `tests/digests/development.json` untouched and reproduced.
- **Ladder:** L0 and L1 ran here. L2a not run; the ledger pairs are on one rung, host class and thread count [read].

## What I ran

All [arm], at `7ae31794`. Logs are in `<scratch>/out/`, mutant logs in `out/mutants/`, CLI runs in `runs/`.

- `bash scripts/gates/digest.sh`: exit 0, "verified L0 and L1 development proof digests (6 proofs, SHA-256 + FNV-1a)". It runs `cargo test --release -p stele-prover --test development dumps_development_digests --locked --offline -- --ignored --exact --nocapture`.
- `cargo test -p stele-ir -p stele-sumcheck -p stele-lookup -p stele-cqis --all-features --locked --offline`: every binary ok.
- `stele-reductions --all-features`: library 208 passed, 1 ignored (207 in one piece, `rejects_every_constraint_deletion` alone); 17 integration binaries, 84 passed, 5 ignored.
- `stele-prover`: 3 and 25 passed, 13 ignored. `stele-cli`: 9 passed, 1 ignored.
- `stele-negative-controls --all-features`: library 25 passed; the 164 registered controls by id, all pass.
- Scratch tests: the selector differential (two tests); the false-witness test; the forgery tests on the tip and under W3.
- CLI: honest L0 under bytes 3 and 6; four false statements.
- 35 mutants, each against the committed tests named in the sections above: M3a, b, c, d, e, i, j, m; M3f, g, h, n, p; W1, W3; U; P1, P2, P4, P5; I1 to I5, I23; C4a, C4b; C5a, b, c; S7a, b, c, d. P5 and W3 also against the scratch tests.
- `git diff` of the reverted experiment, normalised and compared.

One command, the whole `stele-reductions` suite, was moved to the background by the environment after 180 s. I stopped it at once and reran the suite in pieces. Every later command was capped below 170 s.

## Not checked

- **Linux.** Commit 8 was neither compiled nor run. F3 and F4 are from reading, and F3's glibc behaviour is from memory.
- x86, AVX2 and AVX-512 hosts; CUDA parity; the Python verifier.
- L2a and any rung above L1; prove time, peak RSS and every ledger number.
- `scripts/gates/native.sh` as a whole; `soundness-accounting.sh`; `cargo fmt`, `clippy`, `cargo deny`; `rfc-status`, `glossary-lint`, `docs-links`, `ledger-validate`.
- `cargo test --workspace`. Crates not run: `stele-pcs`, `stele-gkr`, `stele-hash`, `stele-field`, `stele-poly`, `stele-code`, `stele-simd`, `stele-proof`, `stele-verifier`, `stele-bench`.
- The committed catalog-wide control test and `stele-controls --coverage` as such, and the 90 per-control test binaries. The same control functions ran by id.
- A whole-proof differential of the old verifier against the new on tampered proofs.
- W2; W1 beyond the prover's tests; U, I23, P4 and P5 against the controls; M3k and M3l alone (inside U only).
- Each commit built and tested alone; only the tip was built.
- Thread counts other than this host's.
- The previous reviewers' logs. I read them as leads and rest nothing on them.

I tried to break it by changing one witness value under both engines, by proving false statements through the CLI, by comparing old and new selector evaluation on 9.3 million points, by 35 mutants, and by a forging prover that leaves one selected position out of its tree. The plain check rejected every false witness, the committed tests rejected every mutant of the selector arithmetic, of the selected product, of the gate's result, of the cache, of the folds and of the capture order, and the tip's verifiers rejected the forgery with `SelectorMismatch`. Nothing committed rejected the verifier that never evaluates the selector, which is why this is not an approval.

## Resolution

Written by the author of the change, after the review above; the second pass below reads
it. Commits `aabe78dc` to `6671fb59` on `task/E20-26-check-instance-bound`, above the
audited tip `7ae31794`.

| Finding | Resolution |
|---|---|
| F1 | `Forge` gains `deselect`: the prover reads a public selector column with one selected entry cleared, under the plan and digest of the published relation. `prove_forged` and `prove_segmented_forged` apply it; `prove_recursive_forged` is new, over a `prove_recursive_with_plan` split of the recursive prover (`controls` feature only; the split moves no statement). Control NC-1342 (`tests/negative-controls/src/development.rs::run_selector`, catalogue row under RFC-0026 §3.3 and RFC-0008 A3) is the review's forgery: position 2 is selected and holds 2, inside the range and outside the table `{0, 1}`, and the prover clears that selector entry. `verify`, `verify_segmented` and `verify_recursive` each answer `SelectorMismatch`; the same value under the unforged prover is `RootMismatch`; the honest witness is accepted. With the review's mutant W3 applied to both verifiers of `relation_lookup.rs`, the control fails with `plain: TamperAccepted` (run once by the author, then reverted). It is a two-value exception like NC-1310, stated in its doc comment and in the catalogue. |
| F2 | ADR-159 is in the decision log (`d7743b01`). |
| F3 | Confirmed on Linux and fixed. The replacement carries `STELE_HUGE_PAGES_EXEC`, and a process that sees it is never replaced (`stele_cli::replaces_itself`, with a unit test of its four cases). Cluster job 7695 on the reference node (glibc 2.39, `strace -f` restricted to `execve` calls): at `7ae31794` a set-group-ID copy of the CLI did not finish within 60 s (exit 124); at `6671fb59` the same copy wrote its proof. The other cases at `6671fb59`: variable unset, 2 `execve` calls, the second with the tunable and the marker; `GLIBC_TUNABLES` preset, 1; marker preset, 1. The L0 proof has the pinned SHA-256 in every case. |
| F4 | The program name is kept (`arg0`). The explicit-loader case and the `SIGPIPE` disposition after a failed `exec` are recorded in ADR-159 as known and not handled. |
| F5 | `prove_false_witness` keeps the plain checker on under a hook. `rejects_false_witness_with_check_when_the_engine_errs` sets one more entry of the first norm's one-hot under the default sources and under profile byte 6: `prove_tampered` answers an engine error, `prove_false_witness` answers `Check`. |
| F6 | The narrow-form test has negative entries, an entry just past `i32` in each direction as the only wide entry, and a definition that overflows `i128` (`Missing`, never zero). |
| F7 | The ledger note says the weight decode is counted in both stages (`bench/dev_e2e.py`). The timers are unchanged. |
| F8 | Each of the four refusals carries a comment naming why no plan reaches it. |

Also in this range: the lock file of `research/gpu-gating/masked` names `stele-simd` under
`stele-cqis` (`aabe78dc`; the first CI run of the pull request failed on it).

Gates at `6671fb59`: `cargo fmt --check` and `cargo clippy -D warnings` on the workspace
pass locally (arm64); the pull request's CI run decides the rest. Its GPU parity job
passed on the H100 runner.

## Second pass

By the independent `soundness-auditor` agent that did not write the change, on the
resolution `7ae31794..6671fb59` and on the follow-up commit `f5eeb046` (parent
`6671fb59`), which answers two findings the reviewer raised while it ran (P0-A, P0-B).
Evidence labels: **[arm]** ran on the reviewer's host (Apple arm64, 16 CPUs, rustc 1.90.0,
`--locked --offline`, own target directories); **[read]** by reading only; **[quoted]** the
author's evidence, not reproduced. The same record reviews tasks E18-13 and E18-15, which
are not part of this change; that part is not reproduced here.

**Verdict of the second pass: APPROVE** at `f5eeb046`, with three LOW findings left
(P0-C, P0-D, P0-E).

### Part 0 — the resolution, row by row

#### F1 — control NC-1342, `Forge::deselect`, `prove_recursive_forged`: closed

- **The control passes and dies under the mutant** [arm]. `cargo test -p stele-negative-controls --features controls --lib rejects_nc_1342`: 1 passed at `6671fb59` and at `f5eeb046`.

| Mutant (in `crates/stele-reductions/src/relation_lookup.rs`) | NC-1342 |
|---|---|
| W3: both closures answer the proof's own values, `sigma_at` never called (the first record's mutant) | FAILS, `NC-1342: "plain: TamperAccepted"` (at both commits) |
| W3a: W3 in `verify` only (plain and segmented engines) | FAILS, `plain: TamperAccepted` |
| W3b: W3 in `verify_for_stack` only (joined recursion) | FAILS, `recursive: TamperAccepted` |
| W1: the closure answers the proof's claim at the incoming point only | passes |
| W2: the closure answers the proof's final value at the final point only | passes |

  - W3b shows the recursive verdict is live on its own. The segmented verdict shares `relation_lookup::verify` with the plain one.
  - W1 and W2 are not seen by this control and cannot be: its forger uses the cleared selector in the tree and in the product, so the comparison left standing still rejects it. Each single comparison is guarded one level down: with the comparison at the incoming point removed (`crates/stele-lookup/src/selected.rs:330`, the first record's M3f) and with the one at the final point removed (`:417`, M3h), `matches_reference_selected_product_and_rejects_the_same_selectors` (`crates/stele-lookup/tests/base_parity.rs:313`) fails, `left: None, right: Some(SelectorMismatch)` [arm, `f5eeb046`]. A note, not a finding.
- **The whole catalogue runs** [arm]. `cargo test --release -p stele-negative-controls --all-features --test catalog` at `f5eeb046`: 8 passed in 151 s, among them `accepts_repository_catalog_without_crediting_stub`, which executes the registered controls and asserts `87/129 bindings; 165/261 controls`. Library tests with `--features controls`: 26 passed, 4 ignored.
- **The split is a pure move** [read; arm]. `git diff 7ae31794 6671fb59 -- crates/stele-reductions/src/relation_recursive.rs` is one hunk. Everything below `let plan_ns = …` is textually unchanged and now sits in `prove_recursive_with_plan(t, relation, plan, plan_ns, segment_values, model)`; `prove_recursive_with_bound` makes the plan and calls it with the same relation. No statement of the honest prover changed. The absorbed digest is `plan.digest` (`relation_recursive.rs:866`), which is why the forging prover's transcript starts as the verifier's. The pinned L0 and L1 digests of profile byte 6 reproduce at `f5eeb046` (`bash scripts/gates/digest.sh`: 6 proofs) and at `bb057662`.
- **The seam does not leak** [read; arm].
  - `Forge`, `deselected`, `prove_forged`, `prove_segmented_forged`, `prove_recursive_forged` and its re-export are each under `#[cfg(feature = "controls")]` (`relation.rs:39, 2255, 2278, 2292, 3889`; `relation_recursive.rs:780`).
  - `deselect` and `prove_recursive_forged` are named only in `stele-reductions` and in `tests/negative-controls/src/development.rs` (grep over `crates` and `tests`).
  - `cargo tree -e features` for `stele-cli` and for `stele-prover` names `controls` on no line; `tests/negative-controls` is the only manifest that turns `stele-reductions/controls` on. `cargo check -p stele-reductions` without features passes.
  - No verifier function reads `Forge`. `crates/stele-verifier` has no changed file. With no `deselect`, `deselected` returns the clone the two older forging provers made before, so they are unchanged.
- **Is it a legitimate two-value exception?** It is a sound control, and the exception is avoidable: P0-C below.
- **"NC-1344" in two comments**: corrected in `f5eeb046` (P0-B, closed).

#### F2 — ADR-159: closed [read]

- ADR-159 is in `agents/context/decision-log.md` (`d7743b01`), after ADR-158. Both citations (`crates/stele-cli/src/main.rs:666`, `bench/dev_e2e.py:394`) now resolve.
- Its numbers are the ledgers': `bench/ledger/e20-27-dev-stories42m-t64-byte6-24t.json` prove 24.75 s, verify 1.26 s; `-hugepages.json` 20.67 s, 1.13 s; both at `ea232178`.
- Its sentences match the code: a set variable is kept, empty included; the marker decides; `argv[0]` is kept; the two edges it does not handle are named.

#### F3 — the single re-exec: closed [read; quoted]

- `huge_pages` (`main.rs:672-694`) returns unless `stele_cli::replaces_itself(tunables_set, marker_set)`, which is `!tunables_set && !marker_set` (`lib.rs:186-188`). The exec sets `GLIBC_TUNABLES` and `STELE_HUGE_PAGES_EXEC`.
- **No loop left.** The replacement's environment is the caller's plus the two variables and reaches the new image through the kernel. Only the loader edits it, and only in secure-execution mode, and only names of its own list; `STELE_HUGE_PAGES_EXEC` is not one. So the second image always sees the marker and returns.
- **Linux evidence** [quoted]: cluster job 7695 as the resolution table gives it (set-group-ID copy: no end within 60 s at `7ae31794`, proof written at `6671fb59`; 2, 1 and 1 `execve` calls for the three other cases; pinned L0 SHA-256 each time). I read the job script (`scratchpad/cluster/clitest2.sbatch`); it does what the row says. Not rerun: no Linux here.
- [arm] `cargo test -p stele-cli` at `f5eeb046`: 10 passed, 1 ignored, with `replaces_itself_once_and_never_under_a_user_variable`. On this host `huge_pages` is not compiled (`cfg(all(target_os = "linux", target_env = "gnu"))`).
- What is left is P0-D (no committed test sees the marker on the exec) and P0-E (the ledger note).

#### F4 — other edges: closed as recorded [read]

- `argv[0]` is kept (`command.arg0(name)`, `main.rs:683-685`); with an empty `argv` the program path stands in.
- The explicit-loader case and `SIGPIPE` after a failed exec are in ADR-159 under "Known edges, not handled". The first record did not ask for more. Under `ld.so ./stele …` the CLI now fails where it ran before `1f2bfba1`: the replacement runs the loader with the CLI's arguments.
- Other things I looked for and did not find: a path where the marker is set and the tunable was wanted (none: the marker is set only by the exec that also sets the tunable); a child process started by the CLI that would need the re-exec (the CLI starts none of its own binary).

#### F5 — the engine that errs: closed [arm]

- `rejects_false_witness_with_check_when_the_engine_errs` passes at `6671fb59` and `f5eeb046` (`stele-prover --test development`: 26 passed, 13 ignored at `f5eeb046`).
- P5 (both sites a plain join whose engine error is examined first): KILLED, `CircleAll: Some(Engine(Sumcheck(RoundSumMismatch)))`. P5r (recursive site only): KILLED, `CircleRecursive: …`. P5s (segmented site only): KILLED, `CircleAll: …`. Each site has its own case.
- `prove_false_witness` is `prove_inner(…, Some(hook), true)`. `checked` was `hook.is_none()` and is now a parameter: `prove`, `prove_measured` and the window path pass `true`, `prove_tampered` passes `false`, as before [read]. It is a public, ungated function of the prover crate, like `prove_tampered`; it can only refuse more than `prove_tampered` does.

#### F6 — the narrow form: closed at `f5eeb046` [arm]

| Mutant (`crates/stele-ir/src/relation/check.rs`) | `stele-ir` at `6671fb59` (43 tests) | at `f5eeb046` |
|---|---|---|
| I2: an entry that overflowed `i128` stored as 0 (`:50`) | **survives** | KILLED, `left: Ok([0, 0, 0, 0])`, `right: Err(Missing(ColumnId(3)))` |
| I3: `i32::MAX + 1` stored as `i32::MIN` | KILLED | KILLED |
| I3b: `i32::MIN − 1` stored as `i32::MAX` | KILLED | KILLED |
| I5: `eval_column` zero-extends a narrow entry | KILLED | KILLED |

- At `6671fb59` the resolution row said "`Missing`, never zero", and the test did not show it: the vector `acc = [0, 1, i64::MAX, 0]` puts `3·i64::MAX` at index 1, a wide entry that chooses the checked form before the overflowed entry at index 2 is reached. This was my finding P0-A. `f5eeb046` makes the vector `[0, 0, i64::MAX, 0]`; I applied I2 in my own copy and the test fails as the table says. Closed.

#### F7 — the ledger note: closed [read]

- `bench/dev_e2e.py:383-384` now says the weight decode is counted in both stages. That is what the timers do: `witness_pre_timer` starts before the executor is made and spans `Weights::from_artifact_sources`; `model_commit_timer` starts just before the decode. The first record accepted either fix. The file parses.

#### F8 — the unreachable refusals: closed [read]

- The four comments are at `relation_lookup.rs:75-76`, `:89-90`, `:116` and `selected.rs:322-323`. Each names a reason that the code bears out: `Relation::validate` admits a lookup selector only as a public 0/1 column (`stele-ir/src/relation.rs:1487-1496`) and refuses a `Ref` that names a bit twice (`validate_ref_fixed`, `:1398-1422`); the selected product asks at its own points; the engine builds `original` from the descriptor's tree.

#### Findings of Part 0

Closed by `f5eeb046`:

- **P0-A (was LOW)** — F6's overflow vector did not kill I2. Closed, see F6.
- **P0-B (was LOW)** — two comments named the control "NC-1344" (`relation.rs:2271`, `relation_recursive.rs:778`). On the next branch of the stack (`a6134008`) NC-1344 is another control (development passport profile, A31), so the citation would have pointed at it after the merge. `f5eeb046` says NC-1342; no "NC-1344" is left in the tree. Closed. `bb057662` was merged before `f5eeb046` and still carries the old comments; the next merge of the stack brings the fix.

Open, none blocking:

##### P0-C — LOW (INV-4): NC-1342 does not need its two-value exception

- **Where:** `tests/negative-controls/src/development.rs:1737-1740` (doc comment), `:1906` (the tamper of `Forged1342`), `tests/negative-controls/catalog.md:234`, `:465-471`.
- The doc comment says two things must change "because a false value alone never reaches the selector comparison". True, and the other single change does reach it: clear the selector entry and keep the honest value.
- **Run** [arm, `6671fb59`]: with the tamper `(1, true)` in place of `(2, true)` (scratch mutant T1) the control passes, so each of the three verifiers answers `SelectorMismatch` for that one-value tamper; with W3 added (T1W3) it fails with `plain: TamperAccepted`, as the committed form does.
- So the binding has a control of the form INV-4 asks for, at the same strength, and no exception is needed. NC-1310's exception existed because no single-value tamper met its row, and it was granted by an Accepted amendment and an ADR (A10, ADR-110). NC-1342's is declared in the catalogue alone.
- **I would like it changed; it does not block.** Smallest fix: `check_control` tampers `(1, true)`; the false statement stays as two added assertions the control already half has, `(2, true)` gives `SelectorMismatch` and `(2, false)` gives `RootMismatch`, per engine; the doc comment and the two catalogue places drop "exception". About six lines. If the author keeps the present form, I accept instead one ADR line that records the exception, as ADR-110 does for NC-1310.

##### P0-D — LOW: no committed test sees the marker on the exec

- **Where:** `crates/stele-cli/src/main.rs:681-692`; test at `crates/stele-cli/src/lib.rs:298-307`.
- The unit test is the truth table of `replaces_itself`. With `.env(stele_cli::HUGE_PAGES_MARKER, "1")` removed from the exec, every committed test passes on every host [read], and the set-group-ID loop of F3 is back. Job 7695 is the only thing that has seen the marker in an `execve`.
- **Smallest fix:** build the `Command` in a function of `lib.rs` and assert in a unit test that `get_envs()` holds both variables and that `get_args()` are the caller's; or state in ADR-159 that the exec is covered by the cluster job alone.

##### P0-E — LOW (INV-14): the ledger note states the default without looking

- **Where:** `bench/dev_e2e.py:393-394`.
- Every ledger gets the sentence "On Linux with glibc the CLI runs with `GLIBC_TUNABLES=glibc.malloc.hugetlb=1` unless the variable is already set". Since `d7743b01` there are two more cases in which it does not: `STELE_HUGE_PAGES_EXEC` present in the harness's environment (no exec, no tunable), and a secure-execution binary (the loader drops the tunable). The harness reads neither variable, so such a record would claim the huge-page default for a 4 KiB-page run.
- **Smallest fix:** name the marker in the sentence and have the harness refuse, or record, an environment that holds it.

Notes that are not findings:

- ADR-159 says of F3 "read from the glibc rules and not run"; the resolution table says job 7695 confirmed it. Both are true at their dates. The job's output is quoted in the review record only.
- In secure-execution mode the exec buys nothing (the loader drops the tunable) and runs a path read from `/proc/self/exe`. I found no way to turn that against the binary on Linux (a replaced link reads as `… (deleted)` and the exec fails; a renamed one is followed). Skipping the exec when `AT_SECURE` is set would remove the question.

#### Part 0 verdict: APPROVE

At `f5eeb046` every row of the resolution table holds, and the three MEDIUM findings of the first record (F1, F2, F3) are closed. P0-C, P0-D and P0-E are LOW and fit the next commit.

I tried to break it by applying the first record's mutant W3 to both verifiers of `relation_lookup.rs` and to each alone, by removing each selector comparison of the selected product, by turning the plain check's gate into a join at each site, and by the four mutants of the narrow form; control NC-1342 rejected W3, W3a and W3b with `TamperAccepted` on the engine each one breaks, `matches_reference_selected_product_and_rejects_the_same_selectors` rejected the two removed comparisons, `rejects_false_witness_with_check_when_the_engine_errs` rejected the joins, and `matches_reference_virtual_values_in_the_narrow_and_the_checked_form` rejected I2, I3, I3b and I5.

## Resolution of the second pass

Written by the author; not reviewed. Commit `4659489b`, above `f5eeb046`.

| Finding | Resolution |
|---|---|
| P0-C | The tamper of NC-1342 is the cleared selector entry alone; the honest value stays. The value outside the table behind the cleared entry (`SelectorMismatch`) and under the unforged prover (`RootMismatch`) are two more assertions per engine. The doc comment and the catalogue no longer call it an exception. |
| P0-D | `stele_cli::replacement` builds the command; `matches_reference_replacement_environment_and_arguments` requires the program, the caller's arguments and exactly the two variables. `main` calls it. |
| P0-E | The ledger note names `STELE_HUGE_PAGES_EXEC`, and `bench/dev_e2e.py` refuses an environment that holds it. A secure-execution binary is not detected by the harness. |

The ledgers `bench/ledger/e21-11-*` are recorded at `4659489b` on the reference class:
L2a 20.52 s with the CLI's default and 23.64 s with `GLIBC_TUNABLES=glibc.malloc.hugetlb=0`
set before the run, L1 6.51 s. The L2a proof has the SHA-256 of the earlier ledgers,
`511a4e8b…4fa5`.

# Soundness Audit Review — host SIMD kernels, slice 1 (task E20-03)

- **Task:** `E20-03` (lane E), slice 1; the change leaves it `in_progress`
- **Audited commits:** the 11 commits `ff533e98..520762ee` of `task/E20-03-simd-kernels` above `c2db66aa`. The review was requested at `ede5b6eb`. Two commits were pushed while it ran and are covered: `707c8ba4` (int8 dot kernel, RFC-0020 A16, ADR-157) and `520762ee` (task E20-23, fraction-tree levels freed early). Line numbers are those of `520762ee`.
- **Reviewer:** independent `soundness-auditor` agent; did not write the change
- **Claim under review:** every kernel returns exactly the limbs of its scalar reference for every input the callers can supply, so every proof byte, public byte and verifier decision is unchanged on every host and thread count
- **Governing specs:** RFC-0003 §§1, 2, 6; RFC-0014 §§1, 2, 5; RFC-0006 A1; RFC-0008 A3; RFC-0029 §1.2; RFC-0004 A15; RFC-0020 §2 and A16; `agents/guardrails/security.md`, `forbidden.md`. INV-3, INV-8, INV-14
- **Tier:** development
- **Verdict:** **CHANGES REQUESTED** (no BLOCKING finding)

## Summary

I found no input on which a kernel and its reference differ, no load or store outside a slice, no instruction outside the feature set its dispatcher checked, and no verifier decision that can change.

- **Arithmetic.** `mul4` is the QM31 product (derivation below). Its largest 64-bit lane is `2^64 − 30,064,771,060`, so none wraps, and every limb it writes is below `p` for any input.
- **Kernels on hardware.** On Sapphire Rapids, for AVX2 and AVX-512 each, the kernels equal arithmetic written from the definition on:
  - all `7^8 = 5,764,801` ordered pairs of elements with limbs from `{0, 1, 2, p−2, p−1, 2^30, 2^30+1}`, and 4·10^6 random pairs;
  - folds, 2,040 layer ranges, and butterflies on all 1,000 edge triples in every lane;
  - the int8 dot on all 65,536 byte pairs and on rows whose sum leaves `i32`.
- **Hosts.** One digest over the field kernels is `9eb092a8036e64d7` on arm64 (scalar, NEON) and x86 (scalar, AVX2, AVX-512).
- **Proofs.** The six pinned L0 and L1 proofs reproduce by SHA-256 at each of the three tips, on arm64 and on x86 with the callers on AVX-512, forced to AVX2 and forced to the scalar references.
- **Call sites.** Digests of folds, 3,352 dense rounds of 700 random instances, 84 fraction trees up to 2^14 leaves and 177 codewords equal those of the base commit `c2db66aa`. They are the same on x86 for three backends at 1, 3, 5 and 8 threads.
- **Memory.** AddressSanitizer reports nothing on the kernels (AVX2, AVX-512, NEON) or the call sites; a control over-read aborts.
- **Dispatch.** Each kernel's machine code assembles under exactly the feature set its dispatcher checks.
- **Verifier.** No verifier runs a kernel.

Why this is not an approval: Workflow 03 lets me approve only when a control rejects what I break. Seven one-line mutants pass every committed test (F1, F3, F6), and one of them also passes the six pinned proofs. ADR-157 also states a speed-up with no ledger (F4).

I would approve this tree with F1, F3 and F4 closed and A16 linked to its review. F2 can stay an open acceptance line of E20-03.

## Scope

1. `stele-field` (`m31.rs:8`, `tower.rs:11-12`, `lib.rs:54-58`); `stele-hash/src/lib.rs:416-454`
2. `stele-simd`: `x86.rs`, `kernels.rs`, `slices.rs`, `tests.rs`, `lib.rs`
3. `stele-poly/src/lib.rs:12-17`; `stele-sumcheck` `parallel.rs:248-328`, `dense.rs:238-290`; `stele-lookup/src/tree.rs:256-301, 525-628, 875-891`; `stele-code/src/lib.rs:428-475`
4. `stele-cqis/src/execution/data.rs:216, 262`; `deny.toml`; RFC-0020 A16; ADR-157; `agents/tasks/graph.yaml`

## Evidence labels

- **[x86]**: ran on `h100-sxm-8-0` (Xeon Platinum 8480CL, 8 CPUs), Slurm jobs 7560–7586, each a fresh clone. rustc 1.90.0; nightly 2025-07-13 for the sanitizer. Backends Scalar, AVX2, AVX-512.
- **[arm]**: ran on an Apple M4 Max (16 CPUs, rustc 1.90.0) on `git archive` exports. Backends Scalar, NEON.
- **[read]**: by reading only.

Instruments, in scratch copies only:

- **Review tests**: seven test files over public API; no source file changed.
- **Forced backend**: 19 lines in `Backend::detect()` that read `STELE_REVIEW_BACKEND` once. Used only where a line says "forced"; kernels and call sites are the commit's.
- **Counters** in the changed entry points, for the verifier call count.
- **Mutants**: one changed line each. A mutant *survives* a test set when every test passes.
- **Feature check**: each kernel's vector instructions, taken from release binaries, re-assembled by GNU as 2.42 limited to a feature set. Control instructions needing AVX-512DQ, BW or VL are refused.
- **Exact model** of `mul4`'s lanes in Python integers.

## What holds

### 1. `mul4` is the QM31 product (`x86.rs:63-93`) [read; model; x86]

With `x = a + b·u`, `y = c + d·u`, `i² = −1`, `u² = 2 + i`: `x·y = (ac + (2+i)·bd) + (ad + bc)·u`, and `(2+i)(e0 + e1·i) = (2e0 − e1) + (e0 + 2e1)·i`.

Each element is one 128-bit lane. 64-bit lane A holds the `a` limbs (and `c`), lane B the `b` limbs (and `d`). `mul_epu32` multiplies low halves; `shuffle_epi32(0x4E)` swaps A and B. A subtracted product `x·y` enters as `x·(p − y)`.

| Value | Lane A | Lane B | Largest |
|---|---|---|---|
| `v1` | `a0c0 + a1(p−c1) ≡ ac0` | `b0d0 + b1(p−d1) ≡ bd0` | `(p−1)(2p−1) < 2^63` |
| `v2` | `a0c1 + a1c0 = ac1` | `b0d1 + b1d0 = bd1` | `2(p−1)² < 2^63` |
| `fold2(v1)`, `fold2(v2)` | | | `p + 1` (any 64-bit lane: `p + 3`) |
| `r0 = ac0' + 2·bd0' + (4p − bd1')` | used | discarded by the blend | between `3p − 1` and `7p + 3` |
| `r1 = ac1' + bd0' + 2·bd1'` | used | discarded | `4p + 4` |
| `s0 = ad0 + bc0` | discarded | used | `2(p−1)(2p−1) = 2^64 − 30,064,771,060` |
| `s1 = ad1 + bc1` | discarded | used | `4(p−1)² = 2^64 − 34,359,738,352` |

- **Canonical output.** Each of the four ends with `canonical(fold2(·))`. `fold2` of any 64-bit lane is at most `p + 3 < 2p` with a zero upper half. The 32-bit `min(a, a − p)` maps `[0, 2p)` into `[0, p)` and a zero upper half to zero. So a non-canonical limb cannot be written into an `M31`, whatever the input.
- **Equal to the reference.** `s0` and `s1` are the integers the scalar product sums (`tower.rs:174-175`), and `canonical∘fold2` is `M31::from_u64` (`m31.rs:55-61`). For `r0`, `r1` the reference reduces `ac` and `bd` first; the kernel combines two-fold values with the same residues.
- **Worst limbs.** `s1` peaks with all eight limbs `p − 1`. `s0` peaks at `x = (p−1, p−1, p−1, p−1)`, `y = (p−1, 0, p−1, 0)`. A fold of `p + 3` is reached by `s0`.
- **Evidence.** The model over `{0, 1, p−2, p−1}^8` shows every lane fits and every output equals the definition. On hardware, the edge and random products above pass.

### 2. Memory safety [read; x86; arm]

| Block | Touches | Kept in bounds by |
|---|---|---|
| `fold`, `mul_assign` (`x86.rs:103-143`) | whole vectors below `done = ⌊n/per⌋·per` | `n = min(len)` (`slices.rs:26`, `246`) |
| `layer_round` (`x86.rs:149-201`) | tables at `[x, x+per)` and `[x+half, x+half+per)`, `e` at `[x, x+per)`, for `x < start + done ≤ end`; a stack array of one vector | `start ≤ end ≤ half`, tables `≥ 2·half`, `half = e.len()` (`slices.rs:112-114`) |
| `butterflies` (`kernels.rs:39-60`) | one vector of each slice below `done` | `n` = min of three lengths (`slices.rs:199`) |
| `dot::avx2`, `dot::avx512` (`x86.rs:260-305`) | 16 or 32 bytes of each below `done` | `n = min(len)` (`slices.rs:293`) |

- The largest table index the layer kernel reads is `end − 1 + half ≤ 2·half − 1`.
- Loads and stores are unaligned forms; NEON needs only `u32` alignment.
- Pointers come from the slices passed in. Tails go to the reference through the same slices after the unsafe block.
- `low` and `high` are two `&mut` slices; the kernel loads before it stores.
- Under AddressSanitizer, the crate's tests, the review tests (reversed, over-long and short-table ranges included) and the `stele-cqis` suite produce no report.

### 3. Dispatch [read; x86]

- `available` checks `avx2` or `avx512f` (`lib.rs:74-76`). Every wrapper returns `UnsupportedBackend` before any kernel.
- The `avx512` instantiation names only AVX-512F intrinsics; the `avx2` one only AVX and AVX2.
- `dot::avx512` uses `_mm512_cvtepi8_epi16` and `_mm512_madd_epi16`, which are AVX-512BW. It is entered only after `is_x86_feature_detected!("avx512bw")` (`slices.rs:303`); otherwise an AVX-512 host takes `dot::avx2`.
- Machine code, in six release test binaries and the prover's test binary:
  - the AVX2 kernels assemble under AVX2 alone;
  - the AVX-512 field kernels assemble under AVX-512F with no xmm/ymm16+ or masked narrow operand;
  - the wide dot assembles with BW and is refused under AVX-512F alone (`vpmaddwd`, `vpmovsxbw`), as its dispatcher assumes.
- A host with `avx512f` only would not fault. I could not run one.

### 4. Call sites keep their meaning [read; x86; arm]

- **`parallel::fold`**: kernel only when challenge and both halves are QM31; the same `a + c·(b − a)`.
- **`Layer::round`**: kernel only under `left == right == 1`. The reference's term is the loop's unit term (`slices.rs:87`, `tree.rs:268`).
- **`BaseLeafSummand::round`**: with unit weights the loop computes `q1·p0 + q0·p1 + γ·q0·q1`. The block path computes `q1·(p0 + γ·q0) + p1·q0` on `one.mul_m31(σ)`. These are the same element for any selector in M31, not only 0 and 1. Both `BaseLeaves` variants take denominators from the same `denom_at`.
- **Dense block round**: per term, `product = coefficient`, then one `mul_assign` per factor. A repeated factor multiplies twice, a term without factors adds its coefficient per column, and no terms leaves zeros. Entries past `n` in a short block are never read.
- **`forward_butterflies`**: the old loop reversed the upper half and paired `j` with `width−1−j`; the new one pairs `low[j]` with `high[j]` then reverses. Both leave `low[j] ± t` at `j` and `width−1−j`. Blocks below one vector take the reference inside the wrapper.
- **`prove_built_base` (`520762ee`)**: levels are moved out and dropped after `split_children`. The shape check precedes the move; no value or transcript call changes.
- **Executor (`707c8ba4`)**: the same products and the same sum. The old `.sum()` and the wrapping reference agree whenever the sum fits, which the width bound gives.

### 5. The verifier [read; arm, instrumented]

- `crates/stele-verifier` has no changed file.
- The development verifier reaches `forward_butterflies` from:
  - `stele-pcs/src/recursive.rs:1697`, `3267`, `3490`, `5377`;
  - `certificate.rs:173` and `opening.rs:634`.
- Every row there is in the challenge field, so `m31_slice_mut` is `None` and the generic loop runs.
- Counted on the one-layer window for all five source sets and both dev-zk profiles, accept and reject: the verifier makes 48, 2 or 10 calls of `forward_butterflies`. It makes none into any kernel, `parallel::fold`, `Dense`, `Layer`, `BaseLeafSummand` or `dot_i8`.

## Findings

### F1 — MEDIUM: the checks between the safe API and the unsafe loads have no test

| Mutant | Line | `cargo test -p stele-simd`, both profiles [x86] | Review test |
|---|---|---|---|
| drop `range.start <= range.end` | `slices.rs:112` | survives | killed |
| tables `>= half`, not `>= 2·half` | `slices.rs:114` | survives | killed |
| drop `range.end <= half` | `slices.rs:113` | survives | killed |
| `twiddles` not clamped | `slices.rs:199-200` | survives | killed |
| dot's `w` not clamped | `slices.rs:293-294` | survives | killed |

- For comparison, the committed tests kill a missing canonical step on `s1` or `r0` and zero-extended dot weights.
- The code is right: reversed ranges return zeros, and ranges past the half and short tables panic in the reference.
- Requested tests:
  - a reversed range, `half..half+per`, and a table one element short, at a half of 8, so that no reference tail panics in the kernel's place;
  - unequal lengths with each operand the shortest, for `butterflies`, `mul_assign` and `dot_i8`.

### F2 — MEDIUM (INV-3): CI requires neither AVX-512 nor NEON, and no test can choose a call site's backend

- `.github/workflows/ci.yml:77-81` requires `avx2` only. AVX-512, the BW dot included, runs only if a hosted runner happens to have it.
- The self-hosted Sapphire Rapids runner is not selected by these paths (`scripts/ci_scope.py:60-65`). ADR-157 records this as open.
- No job runs on aarch64, where the NEON butterflies are on every committer's path.
- Call sites follow `detect()`. On an x86 runner the scalar loops of `Dense` and `BaseLeafSummand` never run; on arm64 the block paths never run. The pinned proofs go through one kernel set per run.
- Requested: `STELE_REQUIRE_SIMD=avx2,avx512` on a runner that has it and `neon` on an arm64 runner, for changes under the touched crates. Once the trait of the first acceptance line exists, run the digest test once per available backend.

### F3 — MEDIUM: the block boundaries of the two block-wise call sites

| Mutant | `stele-sumcheck` + `stele-lookup` suites (86 tests), 4 and 8 threads | Six pinned proofs, 4 and 8 threads | Review tests |
|---|---|---|---|
| `dense.rs:282`: add `sums`, not `sums[..n]` | survives | **survives** | killed at 3 threads; survives at 8 |
| `tree.rs:597`: first block's suffix for every block | survives | killed | killed |

- A partial block after a full one occurs only when a pool range is not a multiple of 64 columns. That never happens at 1, 2, 4, 8 or 16 threads; it does at 3, 5, 6, 12 or 24.
- `base_parity` stops at `m = 9`, one leaf block.
- Requested: a `Dense::round` reference test inside a 3-thread local pool at 13 variables; `base_parity` at `m ≥ 11`, and at `m = 14` on that pool.

### F4 — MEDIUM (`forbidden.md` 7 and 16, INV-14): a number without a ledger

- `agents/context/decision-log.md:4870-4871` says probes show the AVX-512 kernels "at three to six times the scalar loops per core". Nothing under `bench/` changed, and `bench/simd_ops.py` measures only the packed ops.
- Remove the multiplier or land its ledger.
- Not a measurement, but a reason to want one: in each of three jobs the six-proof test took about 30 s on AVX-512, 26 s forced to AVX2 and 30 s forced to the scalar references. That is 8 threads, one sample per mode, always in that order.

### F5 — LOW: RFC-0020 A16 and the task record

- A16 (`RFC-0020-monorepo-and-crates.md:293-295`) is marked Accepted by the commit that introduces it and links no review. Workflow 02 step 4 asks for a reviewer from another lane.
- On substance I accept it at the development tier: the kernel equals its reference for every input, wrap included.
- `graph.yaml:4512` does not list the dot kernel.
- The stack edits lane C (`stele-code`, `stele-hash`) and lane N (`stele-cqis`) files; RFC-0027 §5 asks for their review.

### F6 — LOW: counts and extremes in the committed parity tests

- RFC-0003 §6 asks 10^6 random cases per op per backend. The new product gets 19,800.
- The product test comes within `2p` of both lane maxima and reaches the `p + 3` fold, but has no all-`p−1` pair.
- A saturating lane sum in `dot::avx2` survives the committed tests: no committed row wraps.

### F7 — LOW: comments and assertions

- The kernel's SAFETY comment (`x86.rs:159-161`) omits `start <= end`, without which `done` wraps (`x86.rs:157`).
- `slices.rs:6-9` asserts size and alignment only. Limb order rests on `repr(C)` in another crate; `offset_of!` would pin it.
- `x86.rs:47` says `p + 4`; the bound is `p + 3`.
- `tree.rs:525` says 32 KiB; a block is 16 KiB of QM31.
- `layer_kernel_available` also gates the dense product path.

### F8 — LOW: integration

- Seven of the eleven commits (`c7a112fa..2d1cb649`) fail `cargo deny check bans`, because `stele-sumcheck` imports `stele-simd` directly. Checked at `ebbeca35`.
- `stele-code`, `stele-poly` and now `stele-cqis` are `no_std` crates calling a `std` crate. The manifests already had the edge for the first two; it is now load-bearing.

Notes that are not findings:

- One L0 prove enters the butterflies kernel 7.3 million times, about `N − 1` per transform, most on blocks below one vector, each with a `detect()`.
- `enumerates_every_round_of_the_eight_layer_window` (`stele-prover/tests/development.rs:252`, ignored) fails the same way at `c2db66aa`: 28,447 rounds against a pinned 11,687.

## Review checklist

- **RFC section of each new public item:** RFC-0003 §6 on the two trait additions; RFC-0003 §§2, 6, RFC-0014 §2, RFC-0008 A3, RFC-0029 §1.2 and RFC-0004 A15 on the kernels and references. The three `parallel` helpers cite none of their own. `rfc-status` passes.
- **Challenges, claims, bindings:** none added, moved or relabelled; no control due.
- **Ledger and accounting:** no line changes; `soundness-accounting.sh` passes [arm, `ede5b6eb`].
- **Bound certificate:** no new instance. The executor's `|dot| < 2^28` is existing.
- **Padding and masks, segments, commit rule:** unchanged.
- **Determinism:** no hash map, clock, float or environment read in the diff. The backend chooses among functions returning the same limbs.
- **Parity:** scalar, NEON, AVX2 and AVX-512 agree on kernels and pinned proofs. CUDA not run.
- **Cost model:** no term claimed; F4.
- **Verifier:** item 5; no new panic path; F8 on `no_std`.
- **Glossary:** `glossary-lint` passes.
- **Tier:** development; nothing claims more.
- **Plain checker:** untouched; `stele-ir` 42 and `stele-reductions` 314 pass.
- **Proof bytes:** unchanged; pins untouched and reproduced.
- **Ladder:** L0 and L1 on both hosts; no ledger pair.

## What I ran

x86, at `ede5b6eb` unless noted:

- Unpatched: `cargo test -p stele-simd` in both profiles with `STELE_REQUIRE_SIMD=avx2,avx512`; the review kernel tests; fmt and clippy `-D warnings` on the touched crates. All repeated at `707c8ba4` and `520762ee`.
- Seven crates' suites, all features, test profile: 204 tests on the detected backend, forced AVX-512, forced AVX2 and forced scalar. At `707c8ba4`, with `stele-cqis` and `stele-ir`: 414 tests in three modes.
- Review call-site tests: three backends at 1, 3, 5 and 8 threads, 89 digest lines identical 12 times. Again at `520762ee` at 1, 3 and 8 threads.
- Six pinned proofs in three modes at all three tips: 6 of 6 each.
- `stele-prover` development tests (25) in three modes at `ede5b6eb` and `707c8ba4`, and on the detected backend at `520762ee`.
- Six pinned eight-layer windows on AVX-512 and forced AVX2.
- `stele-reductions` 314 on AVX-512 and forced AVX2; negative controls `--lib` 25; `stele-cqis` and `stele-ir` 209 at `707c8ba4`.
- AddressSanitizer at `ede5b6eb` and `707c8ba4`; the feature check; eleven mutants.

arm64:

- At `ede5b6eb`: nine crates 256; `stele-ir` 42; `stele-reductions` 314; `stele-negative-controls` 149; development tests 25; `digest.sh`; `soundness-accounting.sh`; fmt, clippy, `cargo deny`, the `--no-default-features` check, `rust-policy`, `rfc-status`, `glossary-lint`; the verifier call count; the base-commit differential; AddressSanitizer on NEON.
- At `707c8ba4` and `520762ee`, fresh builds: the touched crates' suites, the review tests, `digest.sh`, and the development tests.

## Not checked

- L2a or any rung above L1. ADR-157 says L2a reproduces on both hosts; I did not run it.
- A CPU that picks AVX2 by itself, an AVX-512F CPU without BW, AMD, other aarch64 cores.
- `cargo test --workspace` on x86. The full negative-control suite on x86.
- `stele-reductions`, the accounting gate and the eight-layer windows after `ede5b6eb`.
- CUDA parity, `stele-gpu`, the Python verifier.
- Intermediate commits beyond the `bans` gate at `ebbeca35`.
- Performance. 32-bit, big-endian and other targets. Miri.

I tried to break it by driving every limb of both operands to the lane bounds on AVX2 and AVX-512, by forcing each call site through the scalar references and both kernel sets at 1, 3, 5 and 8 threads, by passing reversed, over-long and short-table ranges to the safe wrappers under AddressSanitizer, and by eleven one-line mutants. The committed parity tests rejected the three mutated arithmetic kernels, and the pinned L0/L1 proofs rejected the mutated leaf block. Nothing committed rejected the five mutated bounds checks, the saturating dot or the mutated dense tail, which is why this is not an approval.

## Resolution

By the author, in the commit that adds this record. The audited commits are unchanged;
the fixes are the two commits above them, `3bd59dea` (tests, comments, assertions) and
`040fbfc7` (CI), and this one (records). Two lines of the record above say "call
count" where the reviewer used a word `glossary-lint` rejects.

| Finding | Status | Change |
|---|---|---|
| F1 | Resolved | The review's tests are committed as `crates/stele-simd/tests/kernels.rs` and `tests/dot.rs`: a reversed range, a range past the half, a table one element short at a half of 8, and unequal lengths with each operand the shortest. Mutants S1, S2, S3, S8 and T2 each fail one of them. |
| F2 | Resolved in part | CI executes each backend on a host that has it. A hosted arm64 job (`simd-neon`) requires NEON. The dedicated Sapphire Rapids node (`gpu-parity`) requires AVX2 and AVX-512 and is now selected by a change under `crates/stele-simd`. Still open, as a line of E20-03: a call site follows its host's backend, so the pinned digests run through one kernel set per host until the trait lets a test choose. |
| F3 | Resolved | `crates/stele-sumcheck/tests/kernel_parity.rs` runs the dense round against a loop on the default pool and on a three-thread pool, up to 13 variables. `crates/stele-lookup/tests/base_parity.rs` (`large_trees`) runs trees of 2^3 to 2^14 leaves through the three provers, also on three threads. `parallel::with_threads` pins the pool size. Mutants D1 and L1 fail them at 8 and at 4 threads. |
| F4 | Resolved | ADR-157 no longer states a multiplier. The reference-class ledgers are listed under "Ledgers" below. |
| F5 | Resolved | A16 links this record. The task record lists the dot kernel. ADR-157 records the call sites in lanes C and N and the CI change in lane B, which this review covers (RFC-0027 §5). |
| F6 | Resolved | `kernels.rs` multiplies every pair of elements with limbs from seven edge values (5,764,801 pairs, all limbs `p − 1` included) per backend and operand order, and 4·10^6 random pairs per backend. `dot.rs` has rows whose sum leaves `i32`. Mutant T3 fails it. |
| F7 | Resolved | The SAFETY comment names `start <= end`. `offset_of!` pins the limb order of `CM31` and `QM31`. The fold bound reads `p + 3` and the leaf block 16 KiB. `layer_kernel_available` is `kernels_available`. |
| F8 | Recorded | The seven intermediate commits that fail `cargo deny check bans` are left as audited: rewriting them would orphan the hashes this record cites. The tip passes. `stele-simd` stays a `std` crate under three `no_std` crates, as it was under `stele-code` and `stele-poly` on `main`; a bare-metal build is an open line of E20-03. |

Mutants against the committed tests, on `h100-sxm-8-0` (AVX2 and AVX-512 required) at
`040fbfc7`, Slurm job 7587. A mutant is killed when the tests fail after a successful
build. The unmutated tree passes all 28 test binaries of the three crates.

| Mutant | Killed by |
|---|---|
| S1 reversed range, S2 short tables, S3 range past the half | `matches_reference_definition_of_the_layer_round_and_rejects_ranges_outside_the_tables` |
| S5, S6 missing canonical step | `tests::matches_reference_qm31_products_on_seeded_and_edge_slices` |
| S8 butterflies clamp | `matches_reference_definition_of_the_butterflies_on_every_edge_triple_and_random_rows` |
| T1 unsigned dot weights | `tests::matches_reference_int8_dot_on_seeded_and_edge_bytes` |
| T2 dot clamp, T3 saturating lane sum | `matches_reference_exact_sum_of_the_int8_dot_and_its_wrap` |
| D1 dense stale sums (8 and 4 threads) | `matches_reference_dense_round_loop_on_random_instances_and_on_three_threads` |
| L1 leaf block suffix (8 and 4 threads) | `large_trees::matches_reference_large_trees_across_provers_and_on_three_threads` |

Two notes of the record, outside the findings:

- The kernel entry per small butterfly block is left as it is; no measurement asks for
  a change.
- `enumerates_every_round_of_the_eight_layer_window` went stale with E18-05. It is not
  changed here: its re-pin is a change for pull request 482, to be pushed with that
  pull request's second review record.

The three commits are sent back to the same reviewer; its second record is appended
below when it returns.

## Second pass

- **Audited commits:** `3bd59dea` (tests, comments, assertions, `parallel::with_threads`), `040fbfc7` (CI) and `deb502bc` (records), above `520762ee` on `task/E20-03-simd-kernels`. `deb502bc` was the tip on origin when the pass began and when it ended. The eleven commits of the first pass keep their hashes. Line numbers are those of `deb502bc`.
- **Reviewer:** the same independent `soundness-auditor` agent; did not write the change
- **Verdict:** **APPROVE** (three LOW findings, none blocking)

### Summary

F1, F3, F4, F5, F6 and F7 are closed. With no review file installed, each of the eleven mutants of the first pass fails a committed test, and so do fifteen new ones. The three commits change no proof byte, no verifier decision and no unsafe code. F2 and F8 stay open in part on the task record, which is acceptable for slice 1.

Three LOW findings follow (F9 to F11). F9 asks for one small test and F10 for four sentences; both fit the commit that appends this section.

Evidence labels are those of the first pass. **[x86]** is `h100-sxm-8-0`, Slurm jobs 7591, 7592, 7593, 7595, 7597 and 7601: 8 CPUs, a fresh clone of `deb502bc` each. **[arm]** is the same Apple M4 Max, on `git archive` exports of `deb502bc` with fresh build directories.

### 1. The lift against the review's files [read; arm; x86]

- **Nothing lost.** `tests/kernels.rs`, `tests/dot.rs`, `tests/kernel_parity.rs` and the `large_trees` module differ from the review's files in test names, formatting, removed digest prints, two redundant casts, one unused `mut`, and one index loop rewritten as `enumerate().take(end).skip(start)`. Every case, edge value, length, bound and assertion is present.
- **Added.** The dense rounds and the large trees run a second time inside `with_threads(3, …)`.
- **Not lifted.** The review's `stele-code` test (177 codewords against the generic loop and the definition). No finding asked for it, and the crates' own tests kill the three mutants I tried on that call site (item 2).
- **`with_threads` moves the split.** With `std`, `sum_ranges` over 4,096 columns hands out 16 ranges of 256 on the ambient pool and 12 ranges of 342 (the last 334) inside `with_threads(3, …)`. That holds on x86 at 4 and 8 ambient threads and on arm64 at 4 and 16. Over 16,384 columns the three-thread ranges are 1,366 long. Up to 2,048 columns the three-thread split equals the ambient one. Without `std` there is one range, and `with_threads` is `f()`.

### 2. Mutants against the committed tests only [x86 unless marked]

No review file was installed. `stele-simd` ran in the test profile and in release with AVX2 and AVX-512 required. The call sites ran the `stele-sumcheck` and `stele-lookup` suites with all features at 1, 4 and 8 ambient threads. The unmutated tree passes 15 tests of `stele-simd` and 90 of the two suites.

The eleven of the first pass, all killed:

| Mutant | Line | Killed by |
|---|---|---|
| S1, S2, S3: each clause of the layer bounds test | `slices.rs:114-116` | `matches_reference_definition_of_the_layer_round_and_rejects_ranges_outside_the_tables` |
| S5, S6: no canonical step on `s1`, on `r0` | `x86.rs:89`, `88` | five and four tests, `tests::matches_reference_qm31_products_on_seeded_and_edge_slices` among them |
| S8: `twiddles` not clamped | `slices.rs:201` | `matches_reference_definition_of_the_butterflies_on_every_edge_triple_and_random_rows`, also on NEON [arm] |
| T1: dot weights zero-extended | `x86.rs:272` | both dot tests |
| T2: dot `w` not clamped. T3: saturating lane sum | `slices.rs:295`, `x86.rs:279` | `matches_reference_exact_sum_of_the_int8_dot_and_its_wrap` |
| D1: dense round adds stale sums | `dense.rs:282` | the dense three-thread test and `large_trees`, at 1, 4 and 8 threads |
| L1: first block's suffix for every leaf block | `tree.rs:597` | `large_trees`, at 1, 4 and 8 threads |

New ones:

| Mutant | Line | Result |
|---|---|---|
| `mul_assign` operand not clamped | `slices.rs:248` | killed by the random-pairs product test |
| `fold` operand not clamped | `slices.rs:28` | killed by `tests::matches_reference_qm31_fold_on_seeded_and_edge_tables` |
| wide dot weights zero-extended | `x86.rs:296` | killed by both dot tests |
| layer kernel given `0..range.end` | `tree.rs:281` | killed by `large_trees` alone, at 1, 4 and 8 threads, and on arm64 |
| dense block loaded from `range.start` | `dense.rs:261` | killed by nine tests |
| scalar dense loop evaluates the steps | `dense.rs:313` | killed by 22 tests, 13 of them OM31; killed on arm64 too |
| scalar leaf loop takes `p0a` for `p0b` | `tree.rs:615` | killed by three tests; killed on arm64 too |
| generic fold loop adds `b + a` | `parallel.rs:329` | killed [arm] |
| generic butterflies loop, the one verifiers run, writes `y − x` | `stele-code/src/lib.rs:442` | killed by five `stele-code` tests and by `stele-pcs` [arm] |
| pool butterflies without the reverse; with twiddle chunks of half the grain | `lib.rs:468`, `466` | killed with `std` [arm] |
| NEON `canonical` compares with `p + 1`; NEON `mul` shifts the low lanes by 32 | `neon.rs:18`, `35` | killed by five tests each, with the command of `simd-neon` [arm] |
| butterflies kernel reads the first twiddles for every vector; the tail reads them from index 0 | `src/kernels.rs:53`, `slices.rs:223` | killed by three tests each, with the command of `simd-neon` [arm] |
| `with_threads` made `f()` | `parallel.rs:173-176` | **survives**, alone and with D1 (F9) |
| `MIN_CHUNK = 2^11` | `parallel.rs:43` | passes alone, as it should; **D1 survives with it** (F9) |

One sentence of the first pass was too broad: it said the scalar loops of `Dense` and `BaseLeafSummand` never run on an x86 runner. On x86 the dense loop runs for OM31, and the leaf loop for OM31 and for weights other than one. That is how the two loop mutants die there.

### 3. The CI change [read; arm]

- **It fails closed at job level.** `ci_result.py` accepts `success` for a selected job and `skipped` for an unselected one, for `simd-neon` as for `gpu-parity`. A selected job that is skipped, failed or cancelled fails `gates` (checked by calling `accepts`). `test_ci_readiness.py` runs every combination of the scopes and forbids `continue-on-error`.
- **Not at step level.** With `if: false` added to the two SIMD steps, each job would report `success`, and `python3 scripts/ci_tests.py` still passes all 141 tests (F11).
- **The AVX-512 step** (`ci.yml:184-187`) is an unconditional step of `gpu-parity`, after the CUDA gate. A host without a required backend fails it: the `backends()` helper of each of the crate's three test binaries asserts `STELE_REQUIRE_SIMD`.
- **Selection.** `simd-neon` runs for a change under `stele-simd`, `stele-field`, `stele-poly` or `stele-cqis`, or of the workspace manifest, the lockfile, the toolchain file, `.cargo` or the workflow. `gpu-parity` now also runs for a change under `stele-simd`. Every file that holds kernel code selects both.
- **Not selected for AVX-512:** `stele-field`, the toolchain, the manifests and the workflow (F11). The hosted AVX2 step (`ci.yml:78-81`) runs on every change, and both x86 kernel sets are one macro body (`x86.rs:206`, `229`).
- **Not yet executed.** The branch has no pull request, so the changed workflow has never run. I ran its two commands by hand: `STELE_REQUIRE_SIMD=neon` passes on arm64 macOS, and `avx2,avx512` on the Sapphire Rapids node.
- `python3 scripts/ci_tests.py` passes.

### 4. The Resolution against the tree

- **F1, F3, F5, F7:** the rows state what the tree shows. The mutant table matches the log of job 7587 and reproduces at `deb502bc`. D1 and L1 die at one ambient thread as well. "28 test binaries" is right.
- **F4:** the multiplier is gone. The row's second sentence is a promise (F10).
- **F6:** accurate but for one phrase (F10).
- **F2:** accurate as a description of the workflow. The open part is on the task record (`graph.yaml:4513`), where the first pass said it could stay.
- **F8:** accurate. The seven commits cannot be repaired without rewriting audited hashes, and the tip passes `cargo deny check bans` [arm]. The `std` edge is an open line (`graph.yaml:4514`).
- Both open parts are acceptable for an approval of slice 1.
- The record above the Resolution is the text I returned, apart from the two disclosed lines [diffed].

### 5. Proof bytes, verifier decisions, memory safety

- **Source changes** are comments, a rename (`kernels_available`), one compile-time assertion of two limb offsets, and `with_threads`, which only tests call. No manifest, lockfile or pinned digest moved. No verifier code is touched.
- **Proofs.** The six pinned L0 and L1 proofs reproduce by SHA-256 at `deb502bc` on arm64, and on x86 on AVX-512, forced to AVX2 and forced to the scalar references.
- **Suites.** Eleven crates, all features: 477 tests pass on arm64 and on x86 in the three modes. The `stele-prover` development tests (25) pass on both hosts.
- **Gates.** `scripts/gates/native.sh` passes on arm64, with the pinned digests, the accounting gate and the 149 tests of `stele-negative-controls`.
- **Memory.** No new `unsafe`. AddressSanitizer reports nothing on the crate's tests, `kernel_parity` and `base_parity`, on x86 with AVX2 and AVX-512 required and on arm64. A control over-read aborts on both.

### Findings

#### F9 — LOW: the three-thread runs rest on a premise that nothing checks

- F3's kill needs a pool range that is not a whole number of blocks. The tests get one from three conditions at once: `with_threads(3, …)`, `MIN_CHUNK = 2^8`, and a round of at least 4,096 columns. In `kernel_parity.rs` only the first round of the ten 13-variable instances is that large.
- **The helper.** With `with_threads` reduced to `f()`, all 90 tests pass at 1, 4 and 8 ambient threads, and D1 passes with it. A pool that cannot be built takes the same path (`parallel.rs:175`).
- **The grain.** With `MIN_CHUNK = 2^11`, the three-thread split of 4,096 columns is two ranges of 2,048, and D1 passes all 90 tests. At `2^9` the ranges are already 512 long [arm, probe].
- **The feature.** Without `std`, D1 passes `cargo test -p stele-sumcheck` (55 tests). CI runs the workspace with all features (`ci.yml:70`), so CI kills it.
- Such ranges occur at 3, 5, 6, 12 or 24 threads (first pass, F3). At 1, 4 and 8 threads nothing else committed sees them.
- Requested, not blocking: under `std`, assert inside `with_threads(3, …)` that `sum_ranges` over the tests' largest round (4,096 columns) hands out a range whose length is not a multiple of 64. A 22-line test file doing that passes at the tip and fails with the helper reduced and with the grain raised [arm].

#### F10 — LOW: four sentences say more than the repository shows

- **Resolution, F4 row:** "Reference-class ledgers of the final tip are added with the second record." Nothing under `bench/` cites a commit of the slice. ADR-157's sentence that the L2a digests reproduce on both hosts rests on those ledgers too. Land them in the commit that appends this section, or drop the sentence.
- **Resolution, second note:** the stale test "is re-pinned on the branch of tasks E18-10 to E22-11". The head of that branch on origin (`c2db66aa`, pull request 482) still pins 11,687 at `development.rs:259`. The re-pin is not pushed.
- **ADR-157** (`decision-log.md:4889-4890`): "No other change is open on those files." Pull request 482, the base of this stack, is open on `stele-code/src/lib.rs`, `stele-cqis/Cargo.toml` and `stele-cqis/src/execution/data.rs`. Say that the stack sits on it.
- **Resolution, F6 row:** "per backend and operand order" holds for the edge pairs. The 4·10^6 random pairs run in one order (`tests/kernels.rs:176-180`).

#### F11 — LOW: what the CI change leaves out

- **Scope.** A change of toolchain, workspace manifest, lockfile or workflow selects `simd-neon` but not the AVX-512 step (`ci_scope.py:60-68`).
- **Step-level skip.** `test_ci_readiness.py:101-103` pins the text of the two steps, not the absence of a step-level `if:`. The test already counts `if:` in `native` and `native-union` (lines 104-107). The same count for `simd-neon` and `gpu-parity` closes it.
- **Call sites on arm64.** Both steps run `stele-simd` alone, so no call site and no pinned proof runs on arm64 in CI. That is the open F2 line. One more command in `simd-neon`, the L0 window of `ci.yml:72` or the `stele-sumcheck`, `stele-lookup` and `stele-code` suites, would put the NEON and scalar kernel set end to end in CI before the trait exists.

### What I ran

x86, at `deb502bc`, jobs named `stele-ledger` with `--dependency=singleton`:

- 7591: fmt; clippy `-D warnings` on eight crates; `stele-simd` in both profiles; twelve mutants.
- 7592, 7593, 7597: the two suites at 1, 4 and 8 ambient threads, and `stele-sumcheck` without `std`; ten mutant sets.
- 7595: the split probe; eleven crates' suites in three modes; the six pinned proofs in three modes; the development tests.
- 7601: AddressSanitizer (nightly 2025-07-13) with its control.

arm64, at `deb502bc`:

- fmt; clippy; `cargo deny check bans`; the `--no-default-features` check; eleven crates with all features (477 tests); `stele-sumcheck` and `stele-simd` with default features (70).
- `python3 scripts/ci_tests.py`, also on a workflow with both SIMD steps skipped; `scripts/gates/native.sh`; `rfc-status`, `docs-links`, `glossary-lint`, `rust-policy`, `ledger-validate`.
- The development tests; the `simd-neon` command; the split probe, also at `MIN_CHUNK` 2^9, 2^10 and 2^11; fourteen mutants; AddressSanitizer.
- A line diff of the record against the text I returned.

### Not checked

- A run of the changed workflow on GitHub: the hosted arm64 runner, the AVX-512 step on the dedicated node, and the CUDA gate before it.
- `stele-reductions` and the eight-layer windows at `deb502bc`. `cargo test --workspace` on x86.
- L2a, ledgers, performance, and pull request 482 beyond its file list.
- As in the first pass: a CPU that picks AVX2 by itself, AVX-512F without BW, AMD, other aarch64 cores.

I tried to break it by applying the eleven mutants of the first pass and fifteen new ones with no review file installed, by forcing the committed suites and the pinned proofs through the scalar references, AVX2 and AVX-512, by running the committed tests under AddressSanitizer on both hosts, and by disabling the three-thread pool. The committed tests rejected every mutant of a kernel, a bounds check or a call site, and the pinned L0/L1 digests held in every mode. Only the disabled pool went unnoticed (F9).

## Resolution of the second pass

By the author, in the commit that appends the second pass.

| Finding | Status | Change |
|---|---|---|
| F9 | Resolved | The reviewer's test is committed as `crates/stele-sumcheck/tests/split_shape.rs`: inside `with_threads(3, …)` a sum over 4,096 columns must hand out a range that is not a multiple of 64. It fails with the helper reduced to `f()` and with the grain raised to 2^11. |
| F10 | Resolved | The four sentences are corrected in this commit: the ledgers are listed below, the stale test's re-pin is stated as a change for pull request 482, ADR-157 says that the stack sits on pull request 482, and the random pairs are per backend. |
| F11 | Resolved in part | `test_ci_readiness.py` counts the `if:` of `simd-neon` and `gpu-parity`: one each, the job's. A change of `rust-toolchain.toml` selects the AVX-512 step. `simd-neon` also runs the `stele-sumcheck`, `stele-lookup` and `stele-code` suites, so the NEON and scalar kernels run through their call sites on arm64. Left as it is: a lockfile, manifest or workflow change does not select the dedicated node; the hosted AVX2 step runs on every change, and both x86 kernel sets are one macro body. |

## Ledgers

On the 24-thread reference class (`h100-sxm-8-0`, 24 allocated CPUs, profile byte 6), at
`deb502bc`, the last of three runs each. "Before" is the base of this stack (`1b1676eb`,
ledgers `e22-10-*`).

| Rung | Ledger | Prove | Before | Verify | Peak RSS | Before |
|---|---|---|---|---|---|---|
| L1 | `e20-03-dev-synthetic-8layer-byte6-24t` | 7.03 s | 7.69 s | 0.54 s | 1.94 GiB | 1.98 GiB |
| L2a | `e20-03-dev-stories42m-t64-byte6-24t` | 30.11 s | 36.33 s | 2.04 s | 10.22 GiB | 12.67 GiB |
| L2a, malloc on huge pages | `e20-03-dev-stories42m-t64-byte6-24t-hugepages` | 25.76 s | 31.85 s | 1.57 s | 10.15 GiB | 12.56 GiB |

The RSS columns were first committed as "10.7 GB" and "10.6 GB" against "12.7 GB" and
"12.6 GB": the first two were kilobytes read as megabytes, the last two GiB. The table
above is in GiB from the ledgers.

- The L2a proof is the same 3,927,613 bytes as before the stack (SHA-256 `afb3581b…67cb`),
  in all three runs of both jobs; the L1 proof is the same in its three runs.
- The peak RSS gain is the freed tree levels (`520762ee`), not the kernels.
- No arm64 ledger is recorded for this stack. The L2a digest was reproduced on arm64 at
  `520762ee`, before the test and record commits, which change no prover code.

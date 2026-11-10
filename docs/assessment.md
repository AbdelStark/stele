# State of the project: assessment at `6441a90`

This is the evidence base for the build program ([`docs/plan.md`](plan.md), RFC-0027).
Every Stele number below comes from a `bench/ledger/` record or from a command stated
here. External numbers are quoted with their source and statement (RFC-0018 rule 3).

The assessment was made at `6441a90` and merged with `main` at `21710de`. In between,
`main` gained a rayon work pool (E16-17, ADR-090), new ledgers with the model
commitment timed alone (E16-18) and the row-block split of matmuls past 30 bits
(E16-19, RFC-0026 A6). Section 3 is restated at the merged tree. Sections 1, 4 and 5
are unchanged by those three changes. Work that was under review at the merge is
listed in [plan §6](plan.md#work-under-review-at-the-merge).

## 1. Verdict

Stele has strong primitives, a rigorous integer semantics with real fidelity
evidence, and one working end-to-end proof of a real small Llama. It does not yet
have a prover that claims a security level, hides anything, runs on a GPU, or proves
a model anyone serves. The original critical path is gridlocked on unresolved
amendments. The working path is architecturally the opposite of the thesis.
Meanwhile a system with the thesis's shape shipped publicly (FlashProve, section 6).

Three facts decide the plan:

1. **The end-to-end proof that exists is a commit-everything proof.** It commits about
   1,000 cells and runs about 600 lookups per token, per layer, per unit of model
   width (section 3). The floor for a sound design is near 20 to 45 cells and 45 to
   65 lookups (section 5). More than an order of magnitude sits in protocol and
   numerics design, before any GPU work.
2. **The thesis's "nothing intermediate is committed" was wrong as stated.** A value
   produced by rounding, clamping or a table is advice. A sumcheck cannot discharge a
   claim on advice that nobody committed. The correct rule is narrower and still
   cheap (section 5). The blocked "virtual column" question (Q31) is this issue.
3. **No proof is admitted to any security level, and the old rule could never admit
   one.** The treaty definition (error at most 2^-128 after 2^100 hash queries) needs
   228-bit rounds. A 256-bit hash already gives 2^-56 under that rule (RFC-0019 Q12).
   The standard convention is round-by-round error times queries.

## 2. What exists

| Area | State | Evidence |
|---|---|---|
| Fields, SIMD, MLE | M31, CM31, QM31, OM31, KoalaBear; AVX2/AVX-512/NEON parity | E1 tasks done; `crates/stele-field`, `stele-simd`, `stele-poly` |
| Transcript, Merkle | BLAKE3 hash chain with a label registry; byte-column Merkle | E2 done; Python byte oracles |
| Sumcheck | dense, batching, eq-factored zerocheck with skip, small-value, streaming | E3-01..05 done; both-field Rust/Python corpora |
| Lookups | LogUp fraction trees, selected product, grouped lookup; r = 1 and r = 2 | E3-07, E3-07a/b, E12-02 done |
| Codes and PCS | circle-RS encoder; v2 expander encoder; Ligero-style source with certificate and functional opening; retained-row fused opening | E4-01..04, E4-08 done |
| CQIS | integer semantics for Llama and GPT-2 families; quantiser; tables; native and NumPy executors; real GPT-2-small and Llama-3.1-8B conversion | E5-01..04 done; RFC-0025 |
| Fidelity | Llama-3.1-8B, full protocol, paired standard errors, attribution | `harness/eval/REPORT.md`; E5-05..05g |
| End to end | one prefill window, greedy exact-match, development profile, CPU; matmuls past 30 bits split into row blocks | E16-01..19 merged; RFC-0026 (A1 to A6) |
| GPU, distribution, wrapper, passport, `stele-verifier` | empty scaffolds (9 to 10 lines each) | `crates/stele-{gpu,dist,wrapper,passport,kernels,py,verifier}` |

Volume (tracked files at `6441a90`, counted with `git ls-tree -r` and `wc -l`): about
100,000 lines of Rust (a third of it in test files), 74,000 lines of Python (oracles,
research checks and tooling; 55,000 of them under `research/`) and 63,000 lines of
Markdown. 27 RFCs with 19 full-model appendices, 89 ADRs, 279 review notes, 37
ledgers, 142 control catalogue rows (71 done).

The workspace is healthy. `cargo test --workspace --locked` passed 718 tests with 0
failures (8 ignored) on a 4-core host in 559 s, build included. The quick tooling
suite (`python3 scripts/ci_tests.py`) passes with `cargo-deny` 0.20.2 installed and
the locked crates fetched. One defect was found in the exhaustive suite: the two
mutation tests of the `docs-links` gate failed at `6441a90`, because their fixture did
not copy `harness/` and RFC-0004 links into it. The fixture is fixed on the branch
that adds this assessment. The mutation tests that rebuild Rust sources were not
rerun here.

## 3. The end-to-end prover, measured

Ledgers, all for one prefill window of 64 tokens:

- 24 hardware threads (Intel Core Ultra 9 285K), commit `e813ce1`:
  [`e16-18-dev-synthetic-8layer`](../bench/ledger/e16-18-dev-synthetic-8layer.json),
  [`e16-18-dev-stories42m`](../bench/ledger/e16-18-dev-stories42m.json);
- the same host class before the work pool, commit `f6db15e`:
  [`e16-11-dev-synthetic-8layer`](../bench/ledger/e16-11-dev-synthetic-8layer.json),
  [`e16-11-dev-stories42m`](../bench/ledger/e16-11-dev-stories42m.json);
- 4 cores (Intel Xeon at 2.1 GHz), this assessment:
  [`e17-00-dev-synthetic-8layer-4core`](../bench/ledger/e17-00-dev-synthetic-8layer-4core.json)
  at `6441a90`,
  [`e17-00-dev-synthetic-8layer-4core-21710de`](../bench/ledger/e17-00-dev-synthetic-8layer-4core-21710de.json)
  and
  [`e17-00-dev-synthetic-8layer-1thread-21710de`](../bench/ledger/e17-00-dev-synthetic-8layer-1thread-21710de.json)
  at the merged tree.

| Run | Host, threads | Commit | Prove | Verify | Proof | Peak RSS (prove) |
|---|---|---|---|---|---|---|
| synthetic 8-layer, d 64, V 256 | Core Ultra 9, 24 | `e813ce1` | 21.9 s | 3.95 s | 45.0 MB | 3.0 GB |
| same | Xeon, 4 | `21710de` | 59.8 s | 7.0 s | 45.0 MB | 2.6 GB |
| same | Xeon, 1 | `21710de` | 103.6 s | 7.9 s | 45.0 MB | 2.6 GB |
| same, before the work pool | Xeon, 4 | `6441a90` | 55.7 s | 7.0 s | 45.0 MB | 2.6 GB |
| same, before the work pool | Core Ultra 9, 24 | `f6db15e` | 34.3 s | 5.1 s | 45.0 MB | 2.6 GB |
| stories42M, d 512, V 32000 | Core Ultra 9, 24 | `e813ce1` | 474 s | 24.3 s | 113.4 MB | 38.4 GB |
| same, before the work pool | Core Ultra 9, 24 | `f6db15e` | 719 s | 45.2 s | 113.4 MB | 37.4 GB |

Findings:

- **Determinism holds across hosts, commits and thread counts.** The synthetic proof
  has the same bytes (SHA-256 `478300a1…a7f4`) in all five records: two hosts, four
  commits, and 1, 4 and 24 threads.
- **Threads help, but not much.** On the 4-core host the merged tree proves in 59.8 s
  with four threads and in 103.6 s with one, a factor of 1.7. The work pool of E16-17
  cut the 24-thread time from 34.3 s to 21.9 s and stories42M from 719 s to 474 s. It
  left the 4-core time where it was: 55.7 s before, and 59.8 s, 57.1 s and 61.0 s in
  three runs after (the repeats are in the ledger's host context). The pool splits
  the work inside one sumcheck or one encoding. The 750 matmul sumchecks and the 21
  lookup checks still run one after another.
- **The PCS is 91% of the proof.** Section bytes of the synthetic proof (ledger
  counters): stacked certificate 19.28 MB, source openings 16.05 MB, multiplicity
  certificates 5.77 MB, lookup proofs 3.48 MB, matmul sumchecks 0.29 MB, zerochecks
  0.09 MB. The stacked and model sources use the v2 expander code. Its proven
  distance needs up to 13,472 certificate and 6,714 opening queries (13,469 and 6,713
  at this proof's stacked geometry). The circle code at rate 1/4 needs 314 and 130
  under the same rule (RFC-0010 A3).
- **Lookups are the largest phase of the prover.** A sampling profile at the merged
  tree (56 stack samples during proving; a diagnostic, not a benchmark) put 23 samples
  in the lookup argument, 9 in the stacked-source claim batch and opening, 8 in the
  zerochecks and 4 in preparing the sources. At `6441a90` the same method put 11 of 22
  in the lookup argument and 9 in the batch and opening, so E16-17 shrank the
  opening's share and left the lookups. Method: the release test
  `accepts_eight_layer_window` of `stele-prover` ran while
  `gdb -p <pid> -batch -ex "thread apply all bt 14"` attached to it in a loop with a
  one-second pause (29 samples at `6441a90`; 60 at the merged tree, where the loop's
  limit ended it before verification finished). Each sample is counted under the
  outermost `stele_reductions::relation` frame of the main thread. Attaching slows
  the run, so the counts rank the phases and do not time them. Task E17-01 replaces
  this with phase timers in the ledger.
- **The witness is more than an order of magnitude too large.** For 64 tokens of the synthetic
  model the proof commits one stacked source of 2^25 cells (derived from the
  certificate size and the RFC-0026 A4 geometry rule) and runs lookups over about
  20 million padded positions (the 21 LU numerators in the verifier's ledger sum to
  20.6 million, tables included). That is roughly 1,000 cells and 600 lookup
  positions per token, layer and unit of width.
- **Memory is one shot.** Every column is `i64`, every sumcheck table is a dense
  QM31 vector, and the whole window is resident. stories42M at T = 64 needs 38 GB.
- **The verifier is linear in public data and slow.** 24 s for stories42M on 24
  threads. On the synthetic model, 3 of the 6 samples taken during verification at
  `6441a90` (same method) were in re-deriving the relation (table generation
  included); the rest were in lookup and certificate checks.

What the development profile does not claim (RFC-0026 §1.2): any security level, zero
knowledge, a passport, GPU parity, or a cost-model term.

## 4. Why the original path is stuck

At `6441a90`, `agents/tasks/graph.yaml` had 157 tasks: 87 done, 53 `ready` and 17
`blocked`. Only four were pickable (all dependencies done): E4-07, E5-05h, E5-06 and
E15-07. None was on the path to an inference proof. The prover task of that path,
E8-01, had 22 unfinished prerequisites. Eleven of them were blocked on amendments:
RFC-0004 A3 and A6 to A9, RFC-0003 A3, RFC-0007 A8, RFC-0009 A2, the Q31
virtual-column amendment, RFC-0010 A7, RFC-0013 A1 and the lowering contracts of
E6-00.

The causes are structural, not a lack of effort:

1. **Evidence before integration.** Each primitive was specified, reviewed, measured
   and controlled to audit grade before any proof of a model existed. Many tasks
   state that they grant "no credit" toward the thing the project is for.
2. **A premise that did not hold.** INV-6 and the claim flow of RFC-0001 §4.1 assume
   lookups over uncommitted tensors. Making that sound is the open Q31. RFC-0023 and
   RFC-0024 worked around it with per-operation advice cuts, which cost more than
   committing the output once.
3. **An unsatisfiable security target** (section 1, fact 3), so nothing could be
   admitted and every dependent task stayed open.
4. **A code with a 2% proven distance** on the per-proof path (v2 expander), chosen to
   avoid an FFT that a GPU performs in milliseconds.
5. **Serial execution.** One task and one PR at a time, with exact-surface fingerprints
   on crates that had no real gate yet.

E16 broke the gridlock by setting all five aside. Its commits run from the accepted
RFC-0026 on 2026-11-09 to a proved real checkpoint on 2026-11-10. That is the working
method; the plan generalises it and then restores rigour where rigour pays.

## 5. First principles, corrected

**What must be committed.** Soundness of a sumcheck reduction needs every final
evaluation claim to land on a committed oracle, a public polynomial, or a column that
is a fixed polynomial function of those. So:

- arithmetic results stay virtual: matmul accumulators, linear recombinations, products;
- advice is committed: outputs of rounding, clamping, selection, digit splitting;
- a table output is committed, or reduced by an indexed-lookup argument that commits
  only a table-sized vector per claim (Q35).

For one rounding `acc = 2^k·y + rem`, commit `y`; `rem` is virtual and range-checked.
For one activation, commit the table index; the remainder and the table output are
looked up. That is one or two committed cells and two or three lookups per nonlinear
value.

**The floor for a Llama layer.** Nonlinear values per token and layer are about
`8d + 4f` (two norms, Q/K/V, attention output, O, gate, up, SiLU, gated product, down)
plus `T·h/2` attention probabilities. With `f ≈ 3.5d` that is about `22d` values, so
about `22d` to `45d` cells and `45d` to `65d` lookups. The development prover is at
about `1000d` and `600d`.

**What the cost model missed.** `docs/cost-model.md` counts `C_cut = n·d·L` committed
cells and `N_act` lookups. The honest count commits about `N_act` cells as well. For
W1 that is about 1.3·10^10 cells per proof at one cell per value (the `n·L·N_act` of
its §3), more than the weights. Commitment cost
`c_c` therefore matters and the PCS must stream. The planning throughput
`R = 3·10^12` Mops/s is unmeasured.

**Security.** State soundness as "an adversary making Q hash queries wins with
probability at most Q·ε_round + Q²/2^256", where ε_round is the largest round-by-round
error. Then QM31 gives 100 bits when every round's numerator is at most
`⌊p^4/2^100⌋ = 2^24 − 1` (RFC-0030 §3, Draft). For a lookup that means instances of at
most 2^23 positions against tables of up to 2^16 rows. A larger check is split into
instances of that size, each with its own multiplicity source, so no second challenge
pair is needed. The same cap applies to every commitment row and every batch. The
split and the row cap both cost proof bytes unless RFC-0019 Q49 and Q50 are resolved
(plan §2, bet B3). 128 bits needs a wider challenge field (OM31) throughout: a QM31
sumcheck round is already at 2^-122.

## 6. The bar moved

FlashProve v0.16.0 (Anthropic, Apache-2.0, published 2026-11-02, unmaintained) proves
greedy next-token claims on Llama 4 Maverick, a 400B mixture-of-experts model with
about 17B weights active per token, on one H100. Source: its README,
`guide/performance.md`, `docs/model.md`, `lean/THEOREM.md` and technical report. Its
statement differs from Stele's (zero-knowledge, GPU, fixed 1,024-token window).

| Property | FlashProve (reported) | Stele today |
|---|---|---|
| Throughput | 111 tok/s of prefill at 24 requests per batch; 17.4 tok/s for one request (58.8 s) | 0.135 tok/s on a 42M model, CPU (64 tokens in 474 s) |
| Proof, verify | 18.78 MB per request; 17 to 21 s | 113 MB; 24 s |
| Zero knowledge | masked sumcheck and bounded-query encodings; a declared leak list; Lean proof for single requests | none |
| Soundness | "about q/2^124 + 2^-101", machine-checked for the Lean verifier; the C++ verifier and CUDA prover are not covered | no level claimed |
| Field, PCS | Goldilocks with a cubic extension; interleaved Reed–Solomon, fold and code-switch, list-decoding regime | M31/QM31; Ligero-style over a v2 expander |
| Numerics | 13-bit weights from a 4-bit file, 12-bit activations, static power-of-two shifts; top token differs from the float model at 6.81% of positions; no task benchmark | int8 weights, int24 residual, grouped dynamic rows; perplexity +1.57%, ARC −1.54 pp, MMLU-Pro −1.40 pp on Llama-3.1-8B |
| Limits it states | fixed window, greedy only, one architecture, one GPU, 257 to 300 GB host RAM, 39 min commit, a commitment that wears out, no float reply passes exact match | section 3 |

Its report says it "does not claim to be a paradigm shift" and that "meaningful
optimizations" were left out. Its design confirms section 5: it commits the step
values per segment, keeps arithmetic virtual, opens the weights once per batch, and
streams one segment at a time.

Other reference points, each self-reported: Attestable (closed) claims 53 to 77 tok/s
on a dense 31B model with 4 to 8 MiB proofs and sub-second verification. SASH (open,
commit-everything Circle STARK) proves Llama-3.1-8B at 1.25 positions/s with 18.5 GiB
proofs. DeepProve (CPU) proves GPT-2 at 174 tok/min.

**Where a new system can be better.** Per-request latency and dense models (one weight
pass, 31-bit field); proof size and verifier time (succinct opening); context beyond
1,024; fidelity measured on tasks; sampling; multi-GPU; 100 bits without grinding;
zero knowledge that covers batches; a maintained specification with a public control
corpus.

## 7. What to keep, change and stop

**Keep.** M31/QM31 and the tower. The transcript, Merkle, sumcheck and LogUp crates.
The circle encoder. CQIS, its executors and the fidelity harness. The relation model
and its plain checker (the best idea in E16). Negative controls, determinism, ledgers.
Spec-first for anything that claims security.

**Change.** The commit rule (INV-6). One weight pass becomes a measured target (INV-7).
The security convention. The per-proof code (circle-RS, succinct opening). The task
graph (vertical slices on a workload ladder). The working rhythm (lanes, tiers).

**Stop.** New work on the v2 expander path. Per-operation advice-cut reductions
(RFC-0023/0024 style) for new operations. Double-challenge LogUp as the route to
100 bits. Micro-ledger campaigns for sub-primitives with no end-to-end consumer.
GPT-2-specific proving work before the Llama line reaches a GPU. Dual-prime
accumulation and epoch beacons before M6.

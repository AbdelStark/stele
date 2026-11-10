# The Stele build program

Governing RFC: [RFC-0027](rfcs/RFC-0027-build-program.md). Evidence:
[`docs/assessment.md`](assessment.md). Work queue: `agents/tasks/graph.yaml`, epics
E17 to E23. This document is the narrative; where it and an Accepted RFC disagree,
the RFC wins.

Targets in this document are projections until a ledger records them
(`docs/cost-model.md` §5). There are no dates. Order is by dependency.

## 1. Goal

Be the best open, maintained prover of language-model inference: faster per GPU than
any published system on the same workload, with proofs small enough to post and a
verifier small enough to audit, proving a model whose fidelity is measured on tasks.

The bar is set by FlashProve v0.16.0 (statement, numbers and sources in
[assessment §6](assessment.md#6-the-bar-moved)).

| Axis | Published frontier | Stele target | Gate |
|---|---|---|---|
| Throughput, same workload | 111 tok/s, Maverick shape, one H100, batch 24 | at least that, then 2x | M6 |
| Throughput, dense 8B | 1.25 positions/s in the open (SASH); 195 tok/s claimed at batch 4, closed and unreproduced (Attestable) | 230 tok/s on one H100 at batch 24, the frontier's rate per active weight; stretch 460 (PRD §7) | M4 |
| Single-request latency | 58.8 s (400B MoE) | under 30 s on that shape; under 10 s on 8B | M4, M6 |
| Proof per 1,024-token request | 18.78 MB | at most 4 MB | M2 |
| Verify | 17 to 21 s | at most 2 s | M2 |
| Context | 1,024 fixed | 16,384, every generated token checked | M6 |
| Soundness | "about q/2^124 + 2^-101", Lean-checked for a Lean verifier; 96 bits without grinding by its own accounting | 100 bits without grinding (standard); 128 (treaty); machine-checked statement | M3, M7 |
| Zero knowledge | single-request proof; batches open | weights and activations hidden, batches included | M5, M7 |
| Fidelity | top token differs from float at 6.81% of positions; no task benchmark | PRD G7 on Llama-3.1-8B (three task benchmarks within paired SE) | lane N |
| Statement | greedy, post-hoc prefill | greedy and committed-seed sampling; multi-turn | M6 |

## 2. Strategy

**Make it work.** Push the model people serve, Llama-3.1-8B, through the engine that
already runs. Accept hours of CPU and a large proof. Real scale surfaces the real
problems (memory, table sizes, row splits) before any optimisation is designed.

**Make it fast.** In this order, because each step is worth more than the next and
changes what the next should be:

1. the protocol (commit less, look up less);
2. the commitment scheme (proof bytes and verifier time);
3. the CPU engine (typed small values, one thread pool, tight lookups);
4. the GPU (kernels for the loops that remain hot).

**Make it right.** Rigour rises with maturity. A capability lands in the development
tier with tests, an integer oracle, determinism and controls. It is promoted to
`standard` and then `treaty` through review, accounting, an independent verifier and
formal statements (section 7). Soundness-critical habits never relax: negative
controls with every binding, challenges only from the transcript, no bypass flags.

### The five bets

Each bet has a kill criterion. A killed bet triggers its fallback, not a debate.

| # | Bet | Kill criterion | Fallback |
|---|---|---|---|
| B1 | **Commit only advice.** Virtual columns for every arithmetic result (accumulators, recombinations, masks, remainders) cut committed cells per token by at least 10x and lookups by at least 5x with the numerics unchanged (RFC-0028). | On L2, after E18-05, cells per token fall by less than 4x. | Keep committed accumulators where virtualisation loses; spend the effort on the engine. |
| B2 | **A 31-bit field with exact lookups beats a 64-bit field with approximate range checks.** Small values, memory-bound sumchecks and 4-byte cells outweigh the extra lookups. | After M2, lookups exceed 70% of prove time on L3 and E20-02 cannot bring a lookup under 150 M31 multiplications. | Random-projection range checks where slack exists (Q37); revisit the field only with a ledger. |
| B3 | **Interleaved circle-RS with a recursive succinct opening** gives at most 4 MB proofs with proven unique-decoding parameters, and the weight opening costs one row combination (RFC-0029). | The parameter script cannot reach 100 bits under 6 MB at 2^30 cells, or the recursion costs over 15% of prove time on L3. | Non-succinct circle sources (already implemented) for the witness; succinct mode for weights only. |
| B4 | **Numerics co-designed with the proof.** Static power-of-two scales with channel equalisation and 16-bit inputs to norms and softmax hold G7 while removing attained maxima, variable division and the limb chains of wide scaled products (Q36). With B1 that reaches 1/20 of today's cells and 1/8 of today's lookups. | The best static configuration misses the grouped-dynamic baseline by more than 0.5% perplexity or 1 pp on ARC or MMLU-Pro. | Keep grouped dynamic rows; make them cheaper with a zero-product attained-max argument (Q43) and accept a lower M4 rate. |
| B5 | **Lanes, a scoreboard and tiers.** Agents working in parallel lanes against one scoreboard deliver faster than one serial queue, without losing soundness discipline. | Two consecutive milestones slip on integration conflicts, or a control regression reaches `main`. | Fall back to one integration queue for protocol crates; keep lanes for bench, numerics and GPU. |

## 3. Target design

### 3.1 Statement

Unchanged in substance from RFC-0001 §3 and RFC-0026 §1.1: a committed model, under
CQIS, maps the published tokens to the published continuation under the decoding
policy. A proof covers a batch of windows. Each window has a checked range. Greedy
first; committed-seed sampling when the seed is revealed after the reply (the noise
becomes a public column, so the check stays an argmax).

### 3.2 The commit rule and relation IR v2 (RFC-0028, Draft)

A column is **committed** exactly when it is advice: the output of rounding, clamping,
selection, digit splitting or a table. Every other column is **virtual**: a declared
polynomial function of other columns (linear map, product of at most three, or a
two-factor contraction). Claims on virtual columns are reduced, never opened.

- A linear virtual column costs nothing: the claim moves to its operands at the same
  point.
- A contraction (matmul) first batches all claims on its output to one point, then
  runs one Thaler sumcheck. Each operand is read once.
- Lookups and range checks may read virtual tuples. The remainder of a rounding is
  never committed.
- The witness is split into **segments** (one or a few layers). A segment commits,
  proves and is dropped. Only the residual stream at segment boundaries is carried.
  Prover memory is two segments and the model stream.
- The plain checker computes virtual columns from their definitions. It stays the
  integer oracle for every module.

Migration is incremental. Each step keeps `prove → verify` green on the ladder and
moves a scoreboard cell: linear columns (V1), contractions (V2), products and virtual
lookups (V3, V4), segments (V5), then the stacked weight phase with a fused opening
(V6, one weight pass).

### 3.3 Protocol stages

1. Bind the public input and the model roots.
2. Per segment: commit its witness; draw; run its lookup checks and zerochecks;
   reduce its virtual columns in reverse definition order; carry boundary and weight
   claims forward.
3. Batch every claim on each committed source to one point.
4. Open: one recursion per proof covers every witness segment and the model sources.

Weight claims from all segments meet in one linear claim on the model commitment.
The development tier may read the weights twice (partial evaluation, then opening). `standard` targets
one read through the stacked phase.

### 3.4 Numerics (lane N)

CQIS stays the law for what is proved. The research question is which CQIS
configuration is cheapest to prove at G7 fidelity. The measure is a pair: fidelity
under the fixed `harness/eval` protocol, and **cells and lookups per token** from the
static accounting tool (E22-01). Candidates, each an experiment before an amendment:

- static power-of-two scales with channel equalisation, against grouped dynamic rows;
- 16-bit inputs to norms and softmax; int8 only where a matmul needs it;
- linear stages merged before one rounding (RoPE inside the Q/K projection, exact
  residual adds);
- a per-row reciprocal for normalisation in place of per-element division;
- indexed lookups that leave table outputs virtual (Q35), aimed at the `T²`
  attention term.

The 8B model needs the wide residual (RFC-0004 A14) and grouped rows (A15) in the
proving modules before any of this; that is on the first-light path.

### 3.5 Commitment scheme v3 (RFC-0029, Draft)

One scheme for weights and witness: rows encoded with the circle Reed–Solomon code
of `stele-code` in coefficient form, columns hashed with BLAKE3, and a recursive
opening. The
prover combines rows once, commits the combination as a smaller matrix, and proves
the column checks by sumcheck into the next level, until the vector is small enough
to send.

- Parameters are proven in the unique-decoding regime for linear codes. No
  list-decoding or capacity conjecture is used. A larger radius needs its own
  amendment and theorem.
- The row combination of the weight opening is the weight pass of the matmul
  sumcheck when the stacked phase is on (the fused opening, ST-2).
- Segments are separate commitments opened in one batch.
- The layout reserves randomiser coefficients and mask rows from the start, empty
  until zero knowledge is on.

The immediate step needs no new protocol: the relation engine moves its stacked and
model sources from the v2 expander to the circle source that `stele-pcs` already
implements (E19-02).

### 3.6 Security (RFC-0030, Draft; resolves Q12)

A proof has λ bits when every round's round-by-round error is at most 2^-λ; an
adversary with Q hash queries then wins with probability at most Q·2^-λ plus the hash
terms. The verifier derives every term from the plan and rejects a configuration
below the profile.

| Tier | λ | Bounds | Zero knowledge | Challenge field |
|---|---|---|---|---|
| development | none claimed | printed, labelled | no | QM31 |
| standard | at least 100, no grinding counted | proven only | optional until M5 | QM31, with lookup checks and PCS rows capped so each round clears 100 |
| treaty | at least 128 | proven only | mandatory | a wider field for every challenge (a QM31 sumcheck round is 2^-122); E12-03 decides which |

### 3.7 Zero knowledge (RFC-0013 A2, Draft)

Bounded-query randomised encoding for every committed source, a mask row for each row
combination, and small committed masks for sumcheck messages. The model commitment has
an opening budget; fresh linked copies extend it. A published leak list states what a
proof reveals. The simulator argument is written before `standard` admits it and
machine-checked before `treaty` does.

### 3.8 Engine and GPU (lane E)

CPU first, because the reference defines the bytes (INV-3):

- typed small-value columns (`i8`, `i16`, `i32`), never `i64` or a dense QM31 table
  before the first sumcheck fold; base-field first rounds;
- one thread pool; independent sumchecks and lookup checks in parallel;
- LogUp with base-field leaves, precomputed first-layer tables for small domains, and
  the instance split of RFC-0026 A7;
- stage timers and counters in every run.

Then CUDA kernels behind one backend trait, in profile order: lookup tree levels and
layer sumchecks, dense rounds and sumcheck folds, small-value partial evaluations
(bucketed for int4 and int8 weights), row encoding and Merkle hashing, and the CQIS
forward pass for the witness. Every kernel has a CPU reference with the same signature and a byte-parity
test.

### 3.9 Verifier and assurance (lane V)

- A real `stele-verifier` crate (`no_std`), free of prover dependencies, under the
  15,000-line budget.
- An independent Python verifier, differential on honest and mutated proofs.
- The control corpus at full coverage of implemented bindings, runnable against any
  prover that claims compatibility.
- Lean statements for the commit rule's composition, the module uniqueness lemmas and
  the top-level theorem (R-FORMAL). Existing public libraries for sumcheck and
  proximity proofs are the starting point.
- A passport that binds the commitment to the published checkpoint digest. A valid
  proof about unidentified weights proves little.

## 4. Scoreboard and ladder

One table, generated from ledgers (`bench/scoreboard.md`, E17-02). A change on a
build lane states which cell it moves or which risk it retires.

| Rung | Model | Window | Role |
|---|---|---|---|
| L0 | synthetic, 1 layer, d 64 | T 16 | required CI smoke |
| L1 | synthetic, 8 layers, d 64 | T 64 | regression and profiling |
| L2 | stories42M (d 512, 8 layers, V 32000) | a: T 64 · b: T 1,024 | first real checkpoint |
| L3 | Llama-3.1-8B, G7 configuration | a: T 64 · b: T 1,024 · c: 4,096 + 512 (W1) | first light, then the headline |
| L4 | Llama-3.1-70B | 4,096 + 512 (W3) | scale |
| L5 | 400B mixture-of-experts, Maverick shape | 1,024 × batch 24 | head-to-head |
| L6 | 405B dense, DeepSeek-V3 | W4, W5; 16,384 context (W6) | frontier |

Columns per rung: prove seconds and tokens per second; verify seconds; proof bytes;
peak RSS and VRAM; committed cells per token; lookup positions per token; weight
reads per proof; tier and λ; controls passed. Fidelity is a model-level table beside
it (`harness/eval/REPORT.md`).

## 5. Milestones

A milestone is a gate, met when its ledgers and controls exist. M3 and M4 run in
parallel after M2; M4 also needs the `standard` admission of E21-04. M5 needs
commitment scheme v3.

| Gate | Name | Exit criteria |
|---|---|---|
| M0 | Development end to end | Done: L2a proved and verified (E16-11). |
| M1 | **First light on 8B** | L3a: a real prompt and greedy reply through the CLI, development tier, one CPU host with at most 512 GB RAM. Statement tampers and NC-1300..1310 rejected on that proof. Ledger recorded; no time or size cap. |
| M2 | **Lean protocol** | L2a on the 24-thread reference class: prove at most 30 s, verify at most 2 s, proof at most 4 MB, RSS at most 4 GB. L3b on at most 64 cores: at most 900 s. Committed cells per token at most 1/10 and lookup positions at most 1/5 of the E22-01 baseline. Proof bytes identical across hosts. |
| M3 | **Admitted** | L2 and L3 proofs under `standard`: λ at least 100, proven terms only, ledger generated and checked by the verifier. Python verifier agrees on 10^3 proofs and rejects every mutation. `stele-verifier` is `no_std` within budget. Control coverage 100% of implemented bindings. Passport binds the checkpoint digest. |
| M4 | **GPU** | L3b on one H100 under `standard`: at least 230 tok/s at batch 24, single request at most 10 s, CPU and GPU proofs byte-identical. Cells at most 1/20 and lookups at most 1/8 of the baseline (needs the numerics of E22-05). W1 recorded. Constants fitted from ledgers. |
| M5 | **Zero knowledge** | Weight-hiding and activation-hiding proofs on L3b with a published leak list, written simulator argument, opening budget enforced. Prover overhead at most 15%. |
| M6 | **Frontier** | L5 on one H100: at least 111 tok/s at batch 24, proof at most 4 MB, verify at most 2 s, single request at most 30 s. W6 proved with every generated token checked. Committed-seed sampling. Eight-GPU efficiency at least 0.8 on W4. |
| M7 | **Treaty** | λ at least 128, proven only, zero knowledge covering batches. Machine-checked top-level soundness statement. External audit with no open critical finding. Two independent verifiers agree on 10^4 proofs. |

## 6. Lanes and the task graph

Seven lanes. A lane owns crates, has at most one open change at a time, and bases every
change on `main`. Lanes meet only at stable interfaces: the relation IR, the source
context of the commitment scheme, the backend trait, the ledger schema.

| Lane | Epic | Owns | First tasks |
|---|---|---|---|
| B: bench | E17 | `stele-bench`, `bench/`, CI | stage counters, scoreboard, real gates in place of scaffold fingerprints |
| P: protocol | E18 | `stele-ir`, relation engine, modules | RFC-0028, linear then contraction virtual columns, segments |
| C: commitment | E19 | `stele-code`, `stele-pcs` | circle sources in the engine, RFC-0029, recursive opening |
| E: engine | E20 | `stele-sumcheck`, `stele-lookup`, `stele-kernels`, `stele-gpu` | typed columns, thread pool, lookup fast path, backend trait, CUDA |
| V: verifier | E21 | `stele-verifier`, `stele-proof`, Python verifier, controls, `formal/` | RFC-0030, verifier crate, Python verifier, admission |
| N: numerics | E22 | `stele-cqis`, `harness/`, model modules | accounting tool, wide residual modules, first light, static-scale experiment |
| Z: zero knowledge | E23 | masks and encodings across P, C, E | RFC-0013 A2, then implementation on v3 |

Critical path to each gate:

- **M1:** E17-01 → E22-03 (wide residual) and E18-06 (segments) → E22-04.
  Accelerators that are not required: E19-02, E18-02, E20-02.
- **M2:** E18-01..05, E19-02..04, E20-01..02, E22-01.
- **M3:** E21-01..05 on top of E19-02 and E20-02; E21-06 for the formal statements.
- **M4:** E20-03..08, E18-07, E22-02 and E22-05.
- **M5:** E23-01..03 on top of E19-05 and E19-06.

Legacy epics E6 to E15 stay in the graph as the treaty backlog. RFC-0027 §6 lists
which tasks are superseded, which are parked and which resume at which gate.

### First ten moves

1. Stage timers and cell, lookup and byte counters in the prover and the ledger (E17-01).
2. Circle sources for the stacked and model commitments (E19-02). Projection from the
   RFC-0010 A9 wire shape, to be measured by the task: on L1 the stacked certificate
   and the source openings fall from 35.3 MB to about 3.4 MB.
3. One thread pool; parallel lookup checks and matmul sumchecks (E20-02).
4. Typed columns; no `i64` or dense QM31 before the first sumcheck fold (E20-01).
5. The static accounting tool for cells and lookups per token (E22-01).
6. Linear virtual columns (E18-02).
7. Contraction virtual columns; drop every committed accumulator (E18-03).
8. Wide-residual and grouped-row modules for the 8B configuration (E22-03).
9. Segments with residual boundaries (E18-06).
10. Llama-3.1-8B first light (E22-04).

Five lanes can start at once: B on move 1, C on move 2, N on moves 5 and 8, P on
RFC-0028 (E18-01) and V on RFC-0030 and the verifier crate (E21-01, E21-02). Lane E
starts when the stage counters of move 1 exist.

## 7. Operating model

1. **End to end stays green.** `main` always proves and verifies L0 in required CI. A
   change that breaks it is reverted.
2. **Vertical slices.** A task ends with the ladder still passing and a scoreboard cell
   moved or a named risk retired. No task ends with "no credit".
3. **Three tiers.** Development: tests, plain-checker agreement, determinism, controls
   for new bindings, a ledger for any number. Standard: adds the soundness-auditor
   review, generated accounting from proven bounds, Python parity and full control
   coverage. Treaty: adds 128 bits, zero knowledge, formal statements and an external
   audit.
4. **Short specifications for the development tier.** A development-tier protocol
   change is an amendment of at most a page, accepted by one reviewer from another
   lane. Promotion to `standard` takes the full review of Workflow 02.
5. **Measure first.** No optimisation without a profile that names the stage, and no
   performance statement without a ledger on a named rung.
6. **Interfaces before parallel work.** A change to a lane interface is its own small
   change, merged before the work that needs it.
7. **Research has kill criteria.** A spike states what result ends it before it starts.

## 8. Research agenda

Mirrored as numbered questions in RFC-0019, where each track states its kill criterion.

**Cryptography**

- Q34: composition theorem for the commit rule (soundness of reductions over a graph
  of virtual columns), stated for Lean.
- Q35: indexed lookups that commit a table-sized vector per claim and no outputs.
  Does it remove the committed `T²` attention probabilities at acceptable cost?
- Q37: range checks by random projection in a 31-bit field. Where is there slack?
- Q39: the best proven radius for interleaved circle codes under tensor-structured
  combination, and the query counts that follow.
- Q40: zero-knowledge budget, linked copies and batch coverage for a reused model
  commitment.
- Q43: an attained-maximum argument with no committed selection.
- Q44, Q45: column height against segment count; a linear-time first layer as a
  fallback.
- Q46, Q47: knowledge soundness for consumers that need an extractor; the
  post-quantum claim.
- Q48: the identity of the coefficient-form circle code.
- Q12, restated by RFC-0030: the theorem and constants for the Fiat–Shamir step.

**Machine learning**

- Q36: static scales with equalisation against grouped dynamic rows, on Llama-3.1-8B.
- Q38: which activations need 16 bits, measured by task benchmarks, not perplexity alone.
- Q41: what to prove when the served reply came from a floating-point engine. Integer
  serving (E20-07, R-SERVE) or a gap policy with a stated meaning.
- Q42: long-context attention. Lookups per score, block accumulation, and a provable
  cutoff for probabilities that round to zero.
- E5-05h: the residual G7 gap in exact numerics.

## 9. Risks

| Risk | Signal | Response |
|---|---|---|
| Virtual columns hide a soundness gap | a near-miss control passes | the plain checker and controls land before each conversion; Q34 statement before `standard` |
| Parameter choices drift from proven theorems | a ledger line without a theorem id | RFC-0030 table; the verifier rejects unknown evidence ids |
| GPU work starts before the protocol settles | kernels rewritten twice | kernels are primitives behind a trait; the protocol composes them |
| Fidelity regresses while chasing proof cost | G7 delta grows | every numerics amendment carries a paired run on the fixed protocol |
| Lanes collide | repeated rebases on the relation IR | interface changes merge first; fallback in bet B5 |
| No GPU in CI | parity untested | rented H100 runs through one scripted harness (E17-04); parity is a release gate |
| The frontier moves again | a new public system | the ladder includes the competitor's own workload; re-baseline in an amendment |

## 10. Decisions this plan takes, for the owner to confirm or overturn

1. The small-model gate is stories42M (L2). GPT-2-small (W8) moves to architecture
   coverage and stops gating the first full proofs.
2. INV-6 and INV-7 apply as written to `standard` and `treaty` plans; the commit rule
   of RFC-0028 replaces INV-6's wording when that RFC is Accepted.
3. Security is stated per round with hash queries multiplying the largest round error
   (RFC-0030, Draft). `standard` becomes proven-only.
4. Work runs in lanes with one open change each, replacing one global queue.
5. New work stops on the v2 expander path, per-operation advice cuts, double-challenge
   LogUp, dual-prime accumulation and epoch beacons.

## 11. Inputs the program needs

1. **Hosts.** A CPU host class with at least 64 cores and 512 GB RAM for rungs L2 and
   L3 (gates M1 and M2), and H100 hours from task E20-04 on. Hosted CI has no GPU, so
   parity and every GPU ledger run on rented hosts through the harness of task E17-04.
2. **The Llama-3.1-8B Artifact.** The prepared CQIS Artifact used for the fidelity
   report (`harness/eval/REPORT.md`) must be reachable by that harness; first light
   proves that exact Artifact.
3. **Reviewers.** Promotion to `standard` needs the soundness-auditor skill run by an
   agent that did not write the change, and `treaty` needs an external review.
4. **A decision on section 10.**

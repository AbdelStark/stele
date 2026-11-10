# RFC-0018 — Benchmarks, targets, cost-model protocol

Status: Accepted · Version: 0.1.0

## 1. Rules
1. A number exists only if `bench/ledger/<run>.json` exists with: commit, toolchain, device, driver, model config,
   `plan.json` digest, profile, every binding enabled (`bindings_all_on: true`), wall time per stage, kernel counters, proof
   size, verifier time (Rust and Python), controls summary.
2. Reported rates are **positions per second over the full request** (prompt + generated); witness recompute included
   and shown separately; batch size stated.
3. Comparisons to other systems cite their reported numbers with their statement and arithmetic (SOTA table in
   `docs/research/sota-analysis.md`); never compare across statements without saying so.
4. Each optimisation PR names the cost-model term it moves and shows the before/after constant.

## 2. Standard workloads
`W1` Llama‑3.1‑8B, 4096+512, batch 1 · `W2` same, batch 8 · `W3` Llama‑3.1‑70B 4096+512 · `W4` Llama‑3.1‑405B 4096+512
(8 GPUs) · `W5` DeepSeek‑V3 4096+512 · `W6` 8B 16384+512 · `W7` Gemma‑class 31B with softcap/window · `W8` GPT‑2‑small
(CI smoke, CPU).

## 3. Targets (acceptance gates in the task graph)
| Milestone | Workload | Target |
|---|---|---|
| E8 (CPU e2e) | W8 | proves and verifies; all controls rejected; soundness ledger ≤ profile |
| E9 (CPU 8B) | W1 on 64 cores | ≤ 2 h (parity reference for GPU) |
| E10 (GPU) | W1 | ≤ 10 s prover, ≤ 10 s native verify; constants fitted |
| E11 (scale) | W4 | ≤ 3 min on 8×H100; ≥ 0.85 scaling efficiency |
| E11 | W5 | ≤ 2 min on 8×H100 |
| E12 (treaty) | W1 treaty profile | ≤ 1.5× standard-profile time; ledger ≤ 2⁻¹²⁸ |
| E14 (wrapper) | W1 | certificate ≤ 500 KB, ≤ 200 ms |

## 4. Fitting the model
`stele-bench fit` reads ledgers and produces `c_w, c_a, c_x, c_c, R` with confidence intervals; `docs/cost-model.md`
is regenerated from the fit (never hand-edited numbers).

## 5. Amendment log

- **A1 — Development-profile records (task E16-11).** Accepted with ADR-089.
  - **Motivation.** RFC-0026 §7 asks E16-11 to record development-profile prove/verify
    time and proof size in `bench/ledger/`. Rule 1 names a profile and a Python verifier
    time, but the development profile is not an RFC-0002 §8 profile, and RFC-0026 has no
    Python verifier. Without this amendment those numbers have no admissible record.
  - **Added text, §1 rule 5.** "5. A record of an RFC-0026 development-profile proof
    sets `profile: "development"` and `kind: "inference"`. Its workload is
    `dev/<name>`, with the model, `T`, tokens and checked range in `model_config`. It
    states a Rust verifier time and a Python verifier time of 0, because RFC-0026 has no
    Python verifier. Proof bytes and controls are required, as for any inference
    record; the controls are tampers run through the verifier against the recorded
    proof. A development record admits no profile and claims no security level. It is
    not comparable with a W1–W8 record and is never an input to the §4 fit."
  - **Soundness ledger.** No change. **Cost model.** No term moves (RFC-0026 §7).
  - **Affected tasks.** E16-11 (validator, records).

- **A2 — Ladder rungs and the scoreboard (RFC-0027 §3).** Accepted with ADR-091
  (owner-directed).
  - **Motivation.** §2 names W1 to W8 only. The build program measures progress on a
    ladder that starts below W8 and ends above W1, and reads it from one generated
    table.
  - **Added text, §2.** "The ladder rungs of RFC-0027 §3 are workloads: `L0`, `L1`,
    `L2a`, `L2b`, `L3a`, `L3b`, `L3c` (identical to W1), `L4` (W3), `L5`, `L6`. A
    development record keeps the `dev/<name>` form of A1 and names its rung in
    `model_config.rung`; records made before this amendment are mapped to their rung
    by the generator. A `standard` or `treaty` record uses the rung id as its
    workload where no W id exists."
  - **Added text, §1 rule 6.** "6. `bench/scoreboard.md` is generated from
    `bench/ledger/` by `stele-bench scoreboard` (until task E17-02 lands, by
    `bench/scoreboard.py`). It lists, per rung and profile, its records: prove and verify time, proof bytes, peak memory, committed cells and
    lookup positions per token, weight reads, λ, controls. A number in any other
    document that the scoreboard also carries cites the scoreboard row."
  - **Added text, §1 rule 7.** "7. From task E17-01 on, a record states `stage_times_ns` for at least:
    witness, commitment, lookups, zerochecks, reductions, openings; and
    `kernel_counters` for committed cells, lookup positions and proof section bytes."
  - **Changed gate.** The E8 row of §3 is read with L2 in place of W8 for the build
    program (RFC-0027 §3). W8 remains defined.
  - **Soundness ledger.** No change. **Cost model.** No term moves.
  - **Affected tasks.** E17-01 (counters), E17-02 (validator and generator).

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

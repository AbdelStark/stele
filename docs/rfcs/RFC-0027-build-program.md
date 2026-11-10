# RFC-0027 — Build program: tiers, ladder, lanes and milestones

Status: Accepted (owner-directed; ADR-095) · Version: 0.1.0 · Depends: RFC-0000, RFC-0002, RFC-0018, RFC-0020, RFC-0026

This RFC governs how Stele is built from the state recorded in
[`docs/assessment.md`](../assessment.md) to a prover that leads on the axes of
[`docs/plan.md`](../plan.md) §1. It changes no protocol behaviour. Every protocol
change it schedules is its own RFC or amendment (RFC-0028, RFC-0029, RFC-0030,
RFC-0013 A3) and stays Draft until reviewed.

## 1. Principles

1. **Work, then fast, then right.** First the target model through the engine that
   runs. Then cost, in the order protocol, commitment scheme, CPU engine, GPU. Rigour
   rises with maturity through the tiers of §2.
2. **End to end is the unit of progress.** A task is a vertical slice: it ends with
   `prove → verify` passing on the ladder (§3) and a scoreboard cell moved or a named
   risk retired. A task that ends with "no credit" is malformed.
3. **Measure first.** No optimisation without a profile that names the stage. No
   performance or capability statement without a ledger on a named rung.
4. **Soundness habits never relax.** In every tier: challenges only from the
   transcript; a negative control with every new binding; no flag, feature or
   environment variable that disables a check; the plain checker agrees with the
   proof engine; deterministic proof bytes.

## 2. Tiers

A tier is the rigour a capability has passed. It is bound to the profile a proof may
claim.

| Tier | Profile | A capability enters when | A proof may claim |
|---|---|---|---|
| T0 | `development` (RFC-0026) | tests, plain-checker agreement, near-miss tests, determinism across two runs, a control for each new binding, a ledger for each number | nothing; the verifier prints "no security level" |
| T1 | `standard` | T0, plus: its RFC text Accepted through Workflow 02 with the soundness-auditor sign-off; its soundness argument written in `formal/`; every round's error generated and checked by the verifier (RFC-0030); the independent Python verifier agrees; control coverage complete for its bindings; fuzzing of its parser | λ of at least 100 bits from proven bounds |
| T2 | `treaty` | T1, plus: zero knowledge with a written simulator argument; proven-only bounds at 128 bits; a machine-checked (Lean) statement for each reduction and for the composition; external review | λ of at least 128 bits, zero knowledge |

Rules:

- A capability lands at T0 and is promoted by Workflow 10. Promotion never happens
  inside the change that introduces the capability.
- A T0 protocol change is specified by a short amendment (motivation, exact change,
  soundness note, effect on cells, lookups and bytes) accepted by one reviewer from
  another lane. This is the only shortening of RFC-0000 §2; it applies to no text a
  `standard` or `treaty` proof depends on.
- A proof's tier is the lowest tier of any capability it uses. The verifier reads the
  profile from the public input and refuses a profile above that (INV-13).
- T1 and T2 state their λ under RFC-0030. Until RFC-0030 is Accepted, RFC-0002 §8 and
  RFC-0012 §4 stand and no proof is admitted to either tier (§7).

## 3. Ladder and scoreboard

| Rung | Model | Window | Role |
|---|---|---|---|
| L0 | synthetic one-layer fixture | T 16 | required CI smoke |
| L1 | synthetic eight-layer fixture | T 64 | regression and profiling |
| L2a, L2b | stories42M | T 64; T 1,024 | first real checkpoint |
| L3a, L3b, L3c | Llama-3.1-8B, G7 configuration | T 64; T 1,024; W1 | first light, headline |
| L4 | Llama-3.1-70B | W3 | scale |
| L5 | 400B mixture-of-experts, Maverick shape | 1,024 × batch 24 | head-to-head |
| L6 | 405B dense, DeepSeek-V3, 16k context | W4, W5, W6 | frontier |

- A ladder record is an RFC-0018 ledger. Development records keep the `dev/<name>`
  workload of RFC-0018 A1 and name their rung in `model_config.rung` (RFC-0018 A2);
  `standard` and `treaty` records on L3c, L4 and L6 use W1, W3 to W6.
- `bench/scoreboard.md` is generated from the ledgers (`bench/scoreboard.py`; task
  E17-02 moves the generator into `stele-bench`) and is never edited by hand. Its columns: prove seconds and tokens per second, verify seconds,
  proof bytes, peak RSS and VRAM, committed cells per token, lookup positions per
  token, weight reads per proof, tier and λ, controls passed.
- The small-model gate of the program is L2. GPT-2-small (W8) is architecture
  coverage and gates nothing in epics E17 to E23.

## 4. Milestones

Gates, not dates (INV-9). Exit criteria are in [`docs/plan.md`](../plan.md) §5 and in
the milestone tasks of `agents/tasks/graph.yaml`.

| Gate | Name | Task | Needs |
|---|---|---|---|
| M0 | Development end to end | E16-11 (done) | — |
| M1 | First light on 8B | E22-04 | — |
| M2 | Lean protocol | E18-09 | M1 |
| M3 | Admitted (`standard`) | E21-07 | M2, E21-09 |
| M4 | GPU | E20-08 | M2, E21-09, E18-08, E22-05 |
| M5 | Zero knowledge | E23-04 | M2, RFC-0029 Accepted |
| M6 | Frontier | E22-09 | M4, M5, E11-03, E11-05 |
| M7 | Treaty | E21-08 | M3, M5, M6 |

## 5. Lanes

A lane owns crates and directories. It has at most one open change. Every change is
based on `main`; stacked changes are not allowed. A change that touches another
lane's interface is made first, alone, and reviewed by that lane.

A task may edit code another lane owns when its acceptance requires it. The change
is then reviewed by the owning lane, counts as the editing lane's one open change,
and waits if the owning lane has an open change on the same files.

| Lane | Epic | Owns |
|---|---|---|
| B (bench) | E17 | `crates/stele-bench`, `bench/`, `.github/`, `scripts/` |
| P (protocol) | E18 | `crates/stele-ir`, the relation engine (`crates/stele-reductions/src/relation*.rs`), `crates/stele-prover` |
| C (commitment) | E19 | `crates/stele-code`, `crates/stele-pcs`, `crates/stele-hash` |
| E (engine) | E20 | `crates/stele-sumcheck`, `crates/stele-lookup`, `crates/stele-gkr`, `crates/stele-poly`, `crates/stele-field`, `crates/stele-simd`, `crates/stele-kernels`, `crates/stele-gpu`, `crates/stele-dist` |
| V (verifier) | E21 | `crates/stele-verifier`, `crates/stele-proof`, `crates/stele-cli`, `crates/stele-passport`, `crates/stele-wrapper`, `crates/stele-py`, the Python verifier, `tests/negative-controls`, `formal/`, `docs/security/` |
| N (numerics) | E22 | `crates/stele-cqis`, the proving modules (`crates/stele-reductions/src/development/` and the module files beside it), `harness/`, `research/cqis-*` |
| Z (zero knowledge) | E23 | the masking and encoding changes inside P, C and E, by agreement with each lane |

Interfaces between lanes: `stele_ir::relation` (P ↔ N, V); the source context and
opening API of `stele-pcs` (C ↔ P, V); the backend trait of `stele-kernels` (E ↔ P,
C); the ledger schema (B ↔ all); the proof container (V ↔ P).

## 6. Legacy task triage

Epics E3 to E15 hold tasks written for the first design. They stay in the graph as
the treaty backlog, with their acceptance text intact. None is picked unless this
table or `program.legacy_active` in `graph.yaml` says so.

| Legacy task | Disposition |
|---|---|
| E5-05h | active (lane N) |
| E6-00, E6-01 | superseded by `stele_prover::development::plan` (E16-10) and E18-01 |
| E6-02 | superseded by `Relation::validate` (E16-01) |
| E6-03 | capture superseded by E16-03; recompute by E18-06 |
| E7-01, E7-03..E7-10 | superseded by the E16-04..09 modules and E18-05 |
| E7-02 | superseded by E18-07 |
| E8-01 | superseded by E16-10 and E22-04 |
| E8-02, E8-03, E8-04 | superseded by E21-02, E21-03, E21-04 |
| E8-05, E8-05a | superseded by E21-01 and E21-04 |
| E8-06 | superseded by E17-03 |
| E9-01, E9-02, E9-03 | superseded by E22-04, E18-08, E20-08 |
| E10-01..E10-07 | superseded by E20-03..E20-08 |
| E5-06 | superseded by E20-07 |
| E4-05, E12-01, E12-01a | superseded by E23-02 |
| E4-06, E15-03 | superseded by E19-01 and E19-03 |
| E12-04 | `standard` part superseded by E21-04; `treaty` part resumes at M7 |
| E12-03, E12-07, E12-08, E12-09 | resume at M3 |
| E13-02, E13-04 | superseded by E22-07, E22-08 |
| E15-05 | superseded by E21-06 |
| E4-07, E11-01..E11-05, E13-01, E13-03, E13-05, E13-06, E15-02, E15-08 | parked until M4 is met; resume for M6 |
| E3-08, E5-03, E12-05, E12-05a, E12-06, E14-01..E14-03, E15-06, E15-07 | parked until M3 is met; resume for M7 |
| E15-01 | stopped (dual-prime accumulation; see §7) |

A superseded task is closed when its successor is done and every acceptance line that
still applies is covered by the successor or moved to a named task.

## 7. Scope of earlier decisions

- **INV-6 and INV-7.** They apply as written to `standard` and `treaty` plans. The
  development tier commits the columns RFC-0026 names and may read the weights twice.
  When RFC-0028 is Accepted, its commit rule replaces INV-6's wording through an
  amendment to `agents/context/invariants.md` recorded in an ADR.
- **Security targets.** RFC-0002 §8 and RFC-0012 §4 stand until RFC-0030 is
  Accepted. No task of E17 to E23 claims a `standard` or `treaty` level before then.
- **Stopped lines of work.** New work on the v2 expander source; per-operation advice
  cuts for new operations (the RFC-0023/0024 pattern); double-challenge LogUp as the
  route to 100 bits; dual-prime accumulation; epoch beacons before M6. The
  delivered code stays, tested, until a successor replaces it.
- **Scaffold fingerprints.** The exact-surface guards in `scripts/gates/check.py` for
  crates on a build lane are replaced by real gates in task E17-03. Until then a
  change that adds a file to such a crate updates the guard in the same change.

## 8. Negative controls

None added. NC-1300..1310 remain the development-tier controls. Each E18, E19, E21
and E23 task that adds a binding reserves its control id in its RFC or amendment.

## 9. Open questions

Q34 to Q51, mirrored in RFC-0019.

## 10. Amendment log

None.

# AGENTS.md — operating manual for every agent working in this repository

You are building **Stele**, a treaty‑grade zero‑knowledge proof system for neural‑network inference.
This file is the root of your context. Read it fully before touching anything. It is short on purpose;
everything it points to is authoritative.

## 0. The one‑paragraph mission

Produce proofs that a committed model, under the canonical quantised semantics (CQIS, RFC‑0004), mapped a
committed input to a committed output — at a cost linear in the bytes the inference touched, on the GPUs that
served it, with soundness a hostile auditor can verify from the spec alone. Performance, soundness and
legibility are co‑equal. A fast prover that admits one false statement is worth less than nothing.

The **build program** (RFC‑0027, `docs/plan.md`) sets the order: make it work, make it fast, make it right.
A working end‑to‑end proof exists (RFC‑0026). Every task now keeps it working while moving a number on the
scoreboard or retiring a named risk.

## 1. Where things are

| Need | Go to |
|---|---|
| The plan, bets, milestones M0–M7 | `docs/plan.md` (governed by RFC‑0027) |
| Where the project stands, with evidence | `docs/assessment.md` |
| What to build next | `agents/tasks/graph.yaml`: epics in `program.active_epics`; pick the lowest‑id `ready` task **in your lane** whose `depends` are all `done` |
| Progress, per workload rung | `bench/scoreboard.md` (generated from `bench/ledger/`; RFC‑0018 A2) |
| How a thing must behave | `docs/rfcs/RFC-xxxx-*.md` (RFC‑0000 is the index; status `Accepted` = law; `Draft` = direction, not law) |
| Why a decision was made | `agents/context/decision-log.md` (ADRs, append‑only) |
| Vocabulary | `agents/context/glossary.md` (use these words, no synonyms) |
| Architecture in one page | `agents/context/architecture.md` |
| Rules that never bend | `agents/context/invariants.md` and `agents/guardrails/*.md` |
| How to do a kind of work | `agents/workflows/*.md` |
| Specialised know‑how | `agents/skills/<skill>/SKILL.md` |
| Papers and what to extract | `agents/context/reading-list.md` |
| Cost model | `docs/cost-model.md` (every optimisation must move a term in it) |

## 2. Invariants (summary — full text in `agents/context/invariants.md`)

- **INV‑1 Spec first.** No protocol behaviour exists outside an `Accepted` RFC or amendment. Code that disagrees with the RFC is a bug in the code *or* a missing amendment — never silently “fix” the spec in code.
- **INV‑2 Soundness is accounted.** Every random challenge, every Schwartz–Zippel loss, every query is a ledger line the verifier derives. A change that adds a challenge without an accounting line is rejected.
- **INV‑3 Reference parity.** The CPU prover is the reference. SIMD and CUDA produce **byte‑identical** proofs. No GPU change merges without the parity gate.
- **INV‑4 Negative controls.** Every binding has at least one control that tampers with exactly one value and is rejected *for the reason the control states*. New binding ⇒ new control in the same change.
- **INV‑5 Field faithfulness is static.** Every integer identity proven in F_p carries a static bound checked by the verifier (`Relation::validate` for the relation engine). No dynamic “it fit in practice”.
- **INV‑6 Commit only what an RFC names.** Adding a committed tensor is an RFC‑level decision. `standard` and `treaty` plans commit only named cuts. The development tier commits the columns RFC‑0026 names; RFC‑0028 (Draft) narrows that to advice.
- **INV‑7 One pass over the weights per proof** in `standard` and `treaty` plans. The development tier may read them twice; the count is reported.
- **INV‑8 Determinism.** Same (spec version, model, input, seed) ⇒ same witness, same proof bytes, on every backend and thread count.
- **INV‑9 No human timelines.** Plans are DAGs with acceptance criteria. Never write “week”, “sprint”, “Q3”, “soon”.
- **INV‑10 Legibility.** Code is written to be audited by a hostile expert: small modules, named invariants, no cleverness without a comment that names the RFC section.
- **INV‑11 Verifier independence.** The verifier never depends on the prover. The Python verifier is kept in lockstep.
- **INV‑12 No floats** in prover or verifier crates.
- **INV‑13 Profiles are explicit.** The verifier reads the profile from the public input and refuses downgrades below the passport's minimum. A proof's tier is the lowest tier of any capability it uses (RFC‑0027 §2); no proof claims a profile above it.
- **INV‑14 Ladder evidence.** A performance or capability statement cites a ledger on a named rung (RFC‑0027 §3).
- **INV‑15 End to end stays green.** `main` always proves and verifies rung L0. A change that breaks it is reverted, not patched forward.

## 3. How to work (short form of `agents/workflows/01-implement-task.md`)

1. **Lane.** Work in one lane (RFC‑0027 §5). A lane has at most one open change, always based on `main`.
   No stacked changes. A change to another lane's interface goes first, alone (Workflow 12).
2. **Claim** a task: `status: in_progress` in `graph.yaml` with your agent id and a branch `task/<id>-<slug>`.
3. **Read** the task's `rfc` sections and `skill`. Read the acceptance criteria *before* writing code.
4. **Know the tier** (RFC‑0027 §2). New capability lands in the development tier. Promotion to `standard` or
   `treaty` is a separate task (Workflow 10).
5. **Tests first** when the task touches a binding, a reduction or a module: the plain checker's honest and
   near‑miss cases, then the negative controls.
6. **Slice.** End with `prove → verify` passing on the ladder and a scoreboard cell moved or a risk retired.
   Keep changes under ~800 lines where practical; split sequentially.
7. **Gates.** Always: `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test --workspace`,
   `scripts/gates/native.sh` (digest, controls, accounting union), and a ledger for every number you state.
   If GPU code changed: `scripts/gates/parity.sh`. For `standard` and `treaty` work add the Workflow 10 list.
8. **PR** with `agents/templates/pr.md`: tier, lane, scoreboard cell moved, cost‑model terms, controls.
   Send changes to `main` through the validated PR; never push them directly. Before merging, verify the
   passing run covers the current `main` base and the intended merge tree.
9. **Review.** Changes under `crates/stele-{sumcheck,gkr,lookup,pcs,hash,verifier}` always need the
   `soundness-auditor` skill. Development‑tier changes elsewhere need one reviewer from another lane; the
   auditor reviews them at promotion (Workflow 10).
10. **On merge:** set `status: done`, append an ADR if a decision was made, regenerate the scoreboard if a
    ledger changed.

## 4. Forbidden (full list in `agents/guardrails/forbidden.md`)

- Introducing an `--unsound-*` flag, a test‑only verifier bypass, or “skip check in release” — ever. Controls are separate binaries that *expect* rejection.
- Claiming a security level for a development‑tier proof, or a conjectural bound in `standard` or `treaty`.
- Deriving Fiat–Shamir challenges from anything other than the transcript object (`crates/stele-hash::Transcript`).
- Floating‑point arithmetic anywhere in the prover or verifier (the harness may use floats to *evaluate accuracy* only).
- Vendoring or forking another proof system’s prover into the core. Reference implementations may live under `vendor-ref/` for differential testing only.
- Editing an `Accepted` RFC without an amendment entry; deleting any ADR; rewriting history on `main`.
- Writing a benchmark number into a doc without a `bench/ledger/*.json` entry that produced it.
- Claiming a performance result measured with any binding disabled.
- Marking a column virtual that is advice (RFC‑0028 §1.2), or merging a change that leaves rung L0 failing.

## 5. Escalation

If a task cannot be completed as specified: do **not** improvise a protocol change. Open an amendment
(`agents/workflows/02-rfc-change.md`), mark the task `blocked` with the amendment id, and move to the next
task in your lane. Research questions go to `docs/rfcs/RFC-0019-research-agenda.md` as a numbered question
with a kill criterion. If a bet of `docs/plan.md` §2 meets its kill criterion, say so in an ADR and take the
stated fallback.

## 6. Style

Rust 2021 edition, `#![forbid(unsafe_code)]` except in `stele-gpu` and `stele-simd` (each `unsafe` block carries a
`// SAFETY:` comment naming the invariant). Module‑level doc comment names the governing RFC section.
Names in `agents/context/glossary.md` only. Tests are named `rejects_<what>` / `accepts_<what>` / `matches_reference_<what>`.
Commit messages: `<crate>: <imperative summary> (RFC-xxxx §y, task <id>)`.

CLAUDE.md, `.codex/`, `.cursor/` all point here. There is one source of truth.

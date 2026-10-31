# AGENTS.md — operating manual for every agent working in this repository

You are building **Stele**, a treaty‑grade zero‑knowledge proof system for neural‑network inference.
This file is the root of your context. Read it fully before touching anything. It is short on purpose;
everything it points to is authoritative.

## 0. The one‑paragraph mission

Produce proofs that a committed model, under the canonical quantised semantics (CQIS, RFC‑0004), mapped a
committed input to a committed output — at a cost linear in the bytes the inference touched, on the GPUs that
served it, with soundness a hostile auditor can verify from the spec alone. Performance, soundness and
legibility are co‑equal. A fast prover that admits one false statement is worth less than nothing.

## 1. Where things are

| Need | Go to |
|---|---|
| What to build next | `agents/tasks/graph.yaml` (task DAG; pick the lowest‑id task whose `depends` are all `done`) |
| How a thing must behave | `docs/rfcs/RFC-xxxx-*.md` (RFC‑0000 is the index; status `Accepted` = law) |
| Why a decision was made | `agents/context/decision-log.md` (ADRs, append‑only) |
| Vocabulary | `agents/context/glossary.md` (use these words, no synonyms) |
| Architecture in one page | `agents/context/architecture.md` |
| Rules that never bend | `agents/context/invariants.md` and `agents/guardrails/*.md` |
| How to do a kind of work | `agents/workflows/*.md` (implement, RFC change, review, benchmark, security review, research spike) |
| Specialised know‑how | `agents/skills/<skill>/SKILL.md` |
| Papers and what to extract | `agents/context/reading-list.md` |
| Cost model | `docs/cost-model.md` (every optimisation must move a term in it) |

## 2. Invariants (summary — full text in `agents/context/invariants.md`)

- **INV‑1 Spec first.** No protocol behaviour exists outside an `Accepted` RFC. Code that disagrees with the RFC is a bug in the code *or* a missing RFC amendment — never silently “fix” the spec in code.
- **INV‑2 Soundness is accounted.** Every random challenge, every Schwartz–Zippel loss, every query appears in `docs/security/soundness-accounting.md`. A change that adds a challenge without an accounting line is rejected.
- **INV‑3 Reference parity.** The SIMD/CPU prover is the reference. The CUDA prover must produce **byte‑identical** proofs on randomised inputs (`agents/guardrails/gpu-parity.md`). No GPU change merges without the parity gate.
- **INV‑4 Negative controls.** Every binding (every edge in the claim graph) has at least one negative control in `tests/negative-controls/` that tampers with exactly one value and must be rejected *for the reason the control states*. New binding ⇒ new control in the same PR.
- **INV‑5 Field faithfulness is static.** Every integer identity proven in F_p carries a bound certificate (RFC‑0004 §6) computed from shapes and CQIS parameters, checked by the verifier. No dynamic “it fit in practice”.
- **INV‑6 Nothing intermediate is committed** unless an RFC names the tensor as a *cut*. Adding a committed tensor is an RFC‑level decision.
- **INV‑7 One pass over the weights per proof.** Any change to the matmul phases must preserve the pass count in `docs/cost-model.md` or amend RFC‑0007.
- **INV‑8 Determinism.** Same (spec version, model, input, seed) ⇒ same witness, same proof bytes, on every backend.
- **INV‑9 No human timelines.** Plans are DAGs with acceptance criteria. Never write “week”, “sprint”, “Q3”, “soon”.
- **INV‑10 Legibility.** Code is written to be audited by a hostile expert: small modules, named invariants, no cleverness without a comment that names the RFC section.

## 3. How to work (short form of `agents/workflows/01-implement-task.md`)

1. Claim a task: set `status: in_progress` in `graph.yaml` with your agent id and a branch name `task/<id>-<slug>`.
2. Read the task’s `rfc` sections and `skill`. Read the acceptance criteria *before* writing code.
3. Write the negative controls and tests first when the task touches a binding or a reduction.
4. Implement one task at a time. Validate and merge its PR before starting the next task.
   Keep new changes under ~800 lines where practical; split sequentially, never into parallel PR stacks.
   The owner-directed E0-06 consolidation is the one-time exception for existing pending work.
5. Run the gates: `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test --workspace`,
   `scripts/gates/digest.sh` (reference digests), `scripts/gates/negative-controls.sh`, `scripts/gates/parity.sh` (if GPU touched),
   `scripts/gates/soundness-accounting.sh` (if any challenge/transcript change).
   CI may use `scripts/gates/native.sh` to run the digest/control/accounting union once.
   Exhaustive research and copied-source mutation campaigns follow `agents/context/research-ci.md`.
6. Fill the PR template (`agents/templates/pr.md`). State which cost‑model terms moved and by how much, with a bench link.
7. Request review by the `soundness-auditor` skill for anything under `crates/stele-{sumcheck,gkr,lookup,pcs,hash,verifier}`.
8. On merge: set `status: done`, append an ADR if a decision was made, update `docs/cost-model.md` if a constant moved.

## 4. Forbidden (full list in `agents/guardrails/forbidden.md`)

- Introducing an `--unsound-*` flag, a test‑only verifier bypass, or “skip check in release” — ever. Controls are separate binaries that *expect* rejection.
- Using a conjectural soundness bound in the `treaty` profile.
- Deriving Fiat–Shamir challenges from anything other than the transcript object (`crates/stele-hash::Transcript`).
- Floating‑point arithmetic anywhere in the prover or verifier (the harness may use floats to *evaluate accuracy* only).
- Vendoring or forking another proof system’s prover into the core. Reference implementations may live under `vendor-ref/` for differential testing only.
- Editing an `Accepted` RFC without an amendment entry; deleting any ADR; rewriting history on `main`.
- Writing a benchmark number into a doc without a `bench/ledger/*.json` entry that produced it.
- Claiming a performance result measured with any binding disabled.

## 5. Escalation

If a task cannot be completed as specified: do **not** improvise a protocol change. Open an RFC amendment
(`agents/workflows/02-rfc-change.md`), mark the task `blocked` with the amendment id, and move to the next
unblocked task. Research questions go to `docs/rfcs/RFC-0019-research-agenda.md` as a numbered question.

## 6. Style

Rust 2021 edition, `#![forbid(unsafe_code)]` except in `stele-gpu` and `stele-simd` (each `unsafe` block carries a
`// SAFETY:` comment naming the invariant). Module‑level doc comment names the governing RFC section.
Names in `agents/context/glossary.md` only. Tests are named `rejects_<what>` / `accepts_<what>` / `matches_reference_<what>`.
Commit messages: `<crate>: <imperative summary> (RFC-xxxx §y, task <id>)`.

CLAUDE.md, `.codex/`, `.cursor/` all point here. There is one source of truth.

# Invariants (binding; summarised in AGENTS.md §2)

INV-1 Spec first — behaviour exists only in Accepted RFCs; disagreement ⇒ fix code or file an amendment, never both silently.
INV-2 Soundness is accounted — every challenge/loss/query is a ledger line; `scripts/gates/soundness-accounting.sh` diffs the ledger generator against the transcript code.
INV-3 Reference parity — CPU/SIMD is the reference; CUDA byte-identical on randomised inputs; no tolerance.
INV-4 Negative controls — each binding (claim-graph edge, PCS check, ledger line) has ≥1 control; new binding ⇒ new control in the same PR; controls are separate test binaries that *expect* rejection and name the RFC section.
INV-5 Static field faithfulness — bound certificates per reduction instance, recomputed by the verifier; no dynamic fits.
INV-6 Nothing intermediate is committed — adding a committed tensor requires an RFC amendment naming it a cut.
INV-7 One weight pass per proof — any matmul-phase change must keep `T_weights` at one pass or amend RFC-0007.
INV-8 Determinism — same inputs ⇒ same proof bytes on all backends; padding canonical; reductions in fixed order.
INV-9 No human timelines — DAGs and acceptance criteria only.
INV-10 Legibility — small modules, named invariants, RFC citations in code, `no_std` verifier under 15k LoC.
INV-11 Verifier independence — `stele-prover` never depends on `stele-verifier`; the Python verifier is kept in lockstep.
INV-12 No floats — in prover/verifier crates `f32/f64` are denied by clippy config; the harness uses floats only to evaluate accuracy.
INV-13 Profiles are explicit — the verifier reads the profile from the public input and refuses downgrades below the passport's minimum profile.

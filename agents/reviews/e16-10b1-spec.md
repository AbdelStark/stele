# E16-10b1 — independent Spec/soundness and lane E ownership review

Reviewer: `adversarial_finals_engine_review`, applying the repository `soundness-auditor` skill.
Fixed base: `18ae0f0d7b86d48a724b48467237fa0079a422db`.
Inspected implementation head: `d5b3c9d81ce783812c939f840a21c1647d0568d0`.
Scope: the complete six-file diff, commits `68ca129d` and `d5b3c9d8`; the controls-only producer interface, before dependent E16-10b work.

## Findings

**Approved for specification/soundness and explicitly approved by owning lane E. No blocking or nonblocking finding.** This approves the interface at the inspected head; it does not certify the integrator's final cumulative merge-tree gates.

RFC-0006 A3 requires: “Require C(w)=running (FinalEvaluationMismatch otherwise).” Its final payload is “input-major then ascending b.” The primitive computes every emitted final from the actual table's original Boolean-prefix slice at the retained tail point. The controls producer absorbs those exact finals under the unchanged ZeroFinal framing before any continuation. Independently replaying the emitted descriptor, weights, skip, rounds and final frame produces the same next challenge.

`Zerocheck::finish`, both verifier implementations and ordinary producer checks are unchanged. The only public route to the alternative final-table branch is `#[cfg(feature = "controls")]`; ordinary `prove`/`prove_with_point` always supply `None`. Default-feature tests still reject a false scalar identity with `FinalEvaluationMismatch` and false non-scalar input with the existing producer rejection.

RFC-0026 §9 specifies “+1 on one witness value of a group, recommitted honestly.” `Forge.witness` checks the witness kind, identity participation, entry existence, checked increment and declared width before transcript work. The changed values drive the commitment, multiplicities, genuine finals and every subsequent consumer. Reference values feed only zerocheck round tables. The engine test confirms the integer checker rejects the single-entry near miss, the commitment changes, and the real verifier reports exactly `Sumcheck(FinalEvaluationMismatch)` for all three tested source sets.

RFC-0026 §9 also requires: “Each must run through the actual E16-10 verifier.” These primitive/engine checks grant no composed NC-1302 credit. The catalog is untouched; task E16-10b retains that obligation. Both existing `Forge` callers are updated, and no unrelated protocol or interface change is included.

## Workflow 03 checklist

- Public items: `Zerocheck::prove_forged_finals` implements a producer adversary for RFC-0006 A3/RFC-0026 §9 NC-1302; `Forge.witness` wires it to §3.2 and §4 step 4. Both are controls-only.
- Challenges: no new challenge. The relation statement/model roots, group root and multiplicity roots precede identity coefficients; Zero precedes ZeroWeight; optional ZeroSkip precedes its Sumcheck challenge; each Round precedes its tail challenge. Exact emitted ZeroFinal bytes precede continuation. No transcript state import or alternate randomness.
- Claims: genuine finals at the retained point route through the existing `Ref` restriction, public evaluation or source claim batch and PCS opening. Reference tables never supply an emitted final claim. The unchanged verifier creates its own points and checks the final equation first.
- Bindings: no new binding. The targeted tests `rejects_forged_finals_from_one_changed_table_entry` and `rejects_forged_identity_finals_after_honest_recommitment` exercise the existing final-evaluation binding. NC-1302 remains reserved for E16-10b's composed execution.
- Ledger: no RLC, SC, lookup, PCS or transcript accounting line changes. Independent reference-vector tests checked existing A3 accounting; `soundness-accounting.sh` was not rerun by this reviewer.
- Bound certificate: no new instance or bound rule; `plan` still validates the relation before the forgery. The increment must remain inside the verifier-declared width.
- Padding/masks: unchanged relation-derived tables, maps and masking. Neither adversary supplies new padding or selectors.
- Determinism: existing ordered loops and fixed folds retained; no hash-map iteration or timing-dependent reduction introduced.
- Parity: honest/restored primitive proofs, points and continuation match; engine proofs match for an empty `Forge` in Expander, CircleAll and CircleAllGrind. CPU/SIMD/CUDA hardware parity was not rerun; no GPU source changed.
- Cost model: no optimization, fitted constant or performance claim; no benchmark ledger added.
- Verifier: source unchanged; existing no_std and plan-derived lengths preserved. Both table sets are shape-checked before primitive transcript work; no verifier panic or bypass added. Author's no-std clippy log was inspected separately from reviewer-run checks.
- Glossary: no forbidden synonym introduced.
- Tier: development-control support only; no security-level, zero-knowledge or promotion claim.
- Commit rule: no column or commitment schema added; the selected existing witness is honestly recommitted, with no new virtual column.
- Plain checker: independently ran the engine test's honest case and the exact one-entry `Violation::Compose { relation: "v", index: 0 }` near miss.
- Segments: no segment, carry or relation dependency change.
- Proof bytes: honest/restored equality and all 130 existing zerocheck reference vectors passed independently, with and without controls. No proof pin changed; full ladder proof pins were not rerun here.
- Ladder: no L0/L1 run or performance comparison claimed by this reviewer. Cumulative workspace/native/ladder qualification remains with the integrator before merge.

## Checks performed

All reviewer Cargo commands used `CARGO_INCREMENTAL=0` and a separate `CARGO_TARGET_DIR=/tmp/stele-e16-10b1-spec-target` at the exact implementation head above:

```text
cargo test -p stele-sumcheck --features controls --test zerocheck
cargo test -p stele-reductions --features controls relation::tests
cargo test -p stele-sumcheck --no-default-features --test zerocheck
git diff --check 18ae0f0d7b86d48a724b48467237fa0079a422db...HEAD
```

Passed: 4 controls-enabled primitive tests, 25 engine unit tests, 3 default primitive tests, and diff hygiene. The engine command also visited integration targets with zero matching tests; those are not counted as additional coverage. Added-line forbidden-pattern inspection found only the intended ZeroFinal absorb and test transcript replay, with no verifier bypass, secret-state import, floats or unsafe code. Reviewed all in-repository callers and feature forwarding.

Logs: `/Users/abdel/dev/stele-validation/e16-10b1-spec-{zerocheck,relation,zerocheck-default}.log`. Author logs for default engine tests (23 passed), all-feature clippy and no-std clippy were inspected as corroboration, not reviewer-run checks.

I tried to break it by incrementing one in-range witness entry while retaining honest zerocheck rounds, and the control `rejects_forged_identity_finals_after_honest_recommitment` rejected it with exactly `Sumcheck(FinalEvaluationMismatch)` in all three source sets.

Skipped duplicate cumulative workspace/native/accounting/ladder and GPU gates. Remaining obligation: E16-10b must establish genuine composed NC-1302 execution; this review grants no such credit.

# E16-10b specification and soundness review

Reviewer: `codex-root/composed_bindings_spec_review`, independent lane P reviewer
using `soundness-auditor`. PR397; 2026-11-17.

Fixed base: `afb147a374fd44d7fdca2cad28689f8dbc5b1110`.
Implementation reviewed/tested: `40b9cb97e08007b6614f9035ec3420673bcb66e6`.
Final reviewed head: `e819ebf286191f5e304723010f1e817a2219c700`; its only additional
change is the two-line public runner documentation, inspected separately.

## Findings summary

**Approve the specification and implementation; no findings.** Read AGENTS.md,
task E16-10b and its prerequisites, the soundness-auditor skill, soundness and
forbidden guardrails, review checklist, Workflows 03/10, RFC-0030 (Draft), and
Accepted RFC-0026 §§2.3/4/9/A4/A17/A18.

Section 9 requires controls to run through the “actual E16-10 verifier”. All
three call unchanged `development::verify` and compare complete typed errors;
producer failures cannot earn coverage. NC-1302 changes exactly one in-range
entry, honestly recommits it, and evaluates that witness at challenges generated
while proving reference zerocheck rounds. It does not replay stale rounds from
the original transcript. NC-1306 satisfies A17's “replace only its stacked root”
and full restoration rule, separately covering Policy 1 and profiles 3/5.
NC-1308 satisfies A18's “change only its Boolean column-index prefix” and
“Generate genuine dependent claim batches and source openings”; equal adjacent
columns permit genuine production, and every pre-opening section stays equal.
Both producer-based controls assert honest byte identity with the ordinary
window prover. E16-02's historical execution claim is corrected; NC-1310's
Accepted exception remains explicit. No protocol change, additional profile
credit, performance claim or security-level claim is introduced.

I tried to break it by incrementing entry 0 of `L0/norm1/S_0` within its declared
width, honestly recommitting and regenerating the dependent proof, and the
control NC-1302 rejected it with exactly
`Engine(Sumcheck(FinalEvaluationMismatch))` on both rungs and both profiles.

## Workflow 03 checklist

- [x] **Public items / RFC:** the controls-only runner implements RFC-0026
  §9/A17/A18; shared fixture visibility remains crate-local. Manifest targets,
  registrations, inventory allowlist, catalog and inventory tests are updated.
- [x] **Challenges / absorbs:** no added challenge or changed order. Main
  transcript: public inputs including model roots/profile, relation digest,
  model/stacked/multiplicity roots, identity coefficients, Zero/ZeroWeight,
  Round/Sumcheck, ZeroFinal; existing lookup descriptors, multiplicities and
  profile-5 nonce precede beta/alpha, with their rounds/finals before matmul
  points. Step 7 absorbs the complete point/value Batch descriptor before gamma,
  each Round before its challenge, then BatchFinal before the PCS opening.
  Certificate transcripts bind the source/root; tensor nonce precedes weights,
  row precedes column nonce and queries, and nonce checks precede Merkle paths.
- [x] **Claims / consumers:** identity finals become Ref-restricted column
  claims; lookup tuple and matmul out/lhs/rhs claims retain their derived points.
  Public claims are evaluated directly; witness claims acquire the A4 Boolean
  prefix, weight claims name model sources, and multiplicities open in step 5.
  `Opening::verify` passes the batch reduction's actual point/value directly to
  `verify_point` with the earlier certificate. No prover-value-only discharge.
- [x] **Bindings / controls:** existing identity, stacked-root and descriptor
  bindings gain composed NC-1302/1306/1308 execution. Mutation/restoration checks
  and typed-error harness failure paths were inspected, including current Forge
  validation and genuine producer calls.
- [x] **Ledger:** no SC/RLC/LU/PCS line, source parameter, degree, query count or
  theorem changes. Full accounting-gate status is recorded below; no new ledger
  or numerical security bound is claimed.
- [x] **Bound certificate:** no new instance; unchanged plan validation supplies
  static bounds. NC-1302 asserts unsigned width 8 and 0→1 remains in range.
- [x] **Padding/masks:** unchanged layout, selectors and zerocheck masks. The
  routed neighbour is a real column in the same group, never padding.
- [x] **Determinism:** fixed fixture names, tokens, source profiles and selectors;
  OnceLock shares immutable fixture results. No unordered or timing-based work.
- [x] **Parity:** production/backend code and pins unchanged. GPU parity was
  not rerun; this is CPU control coverage, not new SIMD/CUDA evidence.
- [x] **Cost model:** no production term moves and no performance number is
  claimed; the retired risk is missing composed execution for three bindings.
- [x] **Verifier:** unchanged source/dependencies, plan-derived section lengths
  and no_std boundary; all new assertions are in the separate control harness.
- [x] **Glossary:** no forbidden terminology introduced.
- [x] **Tier:** development only; no standard/treaty promotion or security claim.
- [x] **Commit rule:** no new committed or virtual column. The witness attack
  changes one already named advice entry; routing preserves all sources.
- [x] **Plain checker:** independently reran NC-1302: honest captures pass;
  the exact near miss returns Identity `L0/norm1/S/0`, point 0, on L0/L1 and 3/5.
- [x] **Segments:** no new segment, carry, or earlier-segment read.
- [x] **Proof bytes:** unchanged honest producer; NC-1302/1308 compare complete
  regenerated containers with ordinary window proofs. A18's adversarial proof
  changes only dependent opening sections. No pins were edited.
- [x] **Ladder:** actual one-layer L0/T=16 and eight-layer L1/T=64, profiles 3/5;
  NC-1306 also runs Expander Policy 1 on each rung. No before/after benchmark
  pair or other-profile execution credit is asserted.

## Evidence and protected-check sensitivity

Independent original-verifier run:
`target/release/deps/nc_1302-09668dfea419f75c --nocapture`, all four cases passed;
log `/tmp/e16-10b-spec-original-1302.log`. Inspected author evidence
`/tmp/e16-10b-green.log`: NC-1302 and NC-1308 each pass all four rung/profile
cases; NC-1306 passes all six Policy-1/profile-3/profile-5 rung cases with the
exact nested errors. NC-1308 returns `Engine(Sumcheck(RoundSumMismatch))`;
NC-1306 returns `Engine(Pcs(Merkle(RootMismatch)))` under Policy 1 and
`Engine(Pcs(Transcript(GrindMismatch)))` under profiles 3/5.
Also inspected red, inventory and both Clippy logs.
`git diff --check` passed through the final reviewed head.

Fault injection used an external `git archive` of the implementation head at
`/tmp/e16-10b-spec-sensitivity`, with its own target directory. The unchanged
registered test was run with `cargo test --release -p stele-negative-controls
--features controls --test nc-<id> --locked --offline -- --nocapture` for each
single-check deletion. Each previous mutation was restored before the next.
No live-tree producer or verifier was altered. Each experiment reaches the
first L0/profile-3 case after honest acceptance, then the strict harness fails:

| Control | Isolated removed predicate | Observed mutant result |
|---|---|---|
| NC-1302 | `Zerocheck::finish` final identity equation | **Accepted tamper**, harness `TamperAccepted` |
| NC-1306 | `Transcript::verify_grind` nonce predicate, retaining PoW work and nonce absorb | Still rejected: `Engine(Pcs(Merkle(RootMismatch)))`; harness `WrongRejection` |
| NC-1308 | `round_payload` round-sum equation, retaining round absorb/challenge | Still rejected: `Engine(Sumcheck(FinalEvaluationMismatch))`; harness `WrongRejection` |

Only NC-1302 demonstrates acceptance after check removal. The other experiments
demonstrate exact-check sensitivity and downstream rejection, not acceptance.
They make no claim about other fixtures or exhaustive authentication coverage.
All external source mutations were restored after the experiments. Patches and
logs are `/tmp/e16-10b-spec-sensitivity-{1302,1306,1308}.{patch,log}`; their
SHA-256 manifest, also covering the original-verifier log, is
`/tmp/e16-10b-spec-sensitivity.sha256`.

Accounting-gate attempt: system Python 3.9 first failed on `tomllib`, then a
Python-3.12 top-level retry found a nested Python-3.9 `zip(strict=True)` failure.
The corrected run with Python 3.12 on PATH is still executing the existing
`stele-reductions --lib` validation; session 95850, log
`/tmp/e16-10b-spec-accounting.log`. No successful full-gate result is claimed here.

Full workspace/native, digest/ladder CI, Python-verifier parity and GPU parity
were not duplicated by this reviewer. Integration must still verify required
gates on the current main base and intended merge tree; this review is not a
merge-gate attestation.

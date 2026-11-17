# E16-40g owning lane P / soundness review

Reviewer: `gkr_reference_spec_review`, independent of implementation. Date: 2026-11-17.

**Final code/spec verdict: PASS, with no remaining blocking finding, at `178139d119bc5d5859ab0688ab5b79df680d6cc6`.** This is an interface review, not task completion, a merge decision, or GPU qualification. Mandatory current-base/current-merge-tree L0/L1 and repository gates remain the integrator's responsibility.

## Scope and pinned revisions

- Worktree: `/tmp/stele-codex-e16-40g`.
- Fixed review base: `67d7f8459761a0c15a1c16b1e2765ef36ef66595`.
- Initially reviewed implementation: `a661cae2e53ad99a0397f8b0d84a935ca25baf9a`.
- Required runtime fix and compact consumer clarification: `89096668fef1e46314a5c71b34a52ff5bd9b75d3`.
- Final reviewed head: `178139d119bc5d5859ab0688ab5b79df680d6cc6`; the final commit only corrects the vanishing-coordinate API comment. No behavior differs from the tested runtime fix.
- Read all root AGENTS.md, soundness-auditor skill, soundness/review/forbidden guardrails, invariants, Workflows 03/10/12, RFC-0030 (Draft), task E16-40g acceptance, RFC-0008 A7 with implementation notes, RFC-0013 A5/A6/A8, RFC-0014 sections 1/5/6.
- Reviewed the complete fixed-base diff plus production factor construction, compact expansion, masked rounds, routing/advance, source batches/openings, seed consumption, and corresponding verifier paths. No repository changes, merge, or GPU job were made by this reviewer. Standalone probes and this report are outside the worktree.

## Findings and disposition

**F1 — lifetime disclosure semantic mismatch, fixed.** The standards reviewer supplied the counterexample: a valid lookup on source 0 plus an unused source-1 column, with lifetime source 1 and `blocks=[0]`. Original `observe_gkr` returned the internal `Ok((proof, None))`; ordinary `prove_lifetime` instead required the disclosure and returned `Error::Statement` (`zk_claims.rs:3456`). I independently confirmed this mismatch in the original adapter. RFC-0013 A6 item 3 requires each proof's opening, and items 4–5 retain its row vector with the lifetime state (spec lines 672–691). The fixed adapter remembers whether lifetime was requested and rejects missing disclosure after the ordinary producer returns (`zk_gkr_bench.rs:94–109`). This exactly preserves ordinary postconditions without changing transcript work or source accounting. The new `rejects_lifetime_observation_without_disclosure` regression passed independently, including the requirement that genuine GKR callbacks occurred before the terminal refusal.

**F2 — expanded-final equality alone is insufficient compact parity evidence, clarified.** An independent probe on the heterogeneous compact case used seed `[57;32]`. At zero-based step 2 / lookup 0, the compact state has 10 factors; index 8 is the combined `X_0`. Adding one to that compact final changes the evaluation of the actual compact term list, yet `expand_at` yields identical expanded finals and `route` yields the identical receipt. The original CPU proof still verifies. This follows from the genuine producer: `Expanded::Claim` evaluates retained columns/mask blocks (`zk_lookup.rs:856–877`), while the combined factor is inserted separately (`zk_lookup.rs:1048–1056`). It is not a proof-authority defect: the adapter never consumes callback values. It is a material consumer qualification trap under RFC-0014 section 5 (lines 42–44). The final API comment and `GKR-REFERENCE.md:20–25` now explicitly require comparison of every round polynomial and folded factor, including every compact final, before expansion. Closed as an explicit consumer-contract limit; no production expansion change was appropriate.

**F3 — vanishing-coordinate wording, fixed.** `Factor.v` remains the original absolute coordinate after folding; only the mask table is cleared when bound (`zk_claims.rs:2170–2174`). The final getter comment at line 4059 now accurately says original coordinate, rather than remaining coordinate.

## Challenges, authority, and claim consumers

The observer introduces no transcript label, absorb, challenge, degree, claim, or loss. `observe_gkr` hard-codes claim masks on and forgery off; its callback returns only `Result<(), Error>`, receives immutable references, and receives no transcript or mutable production state. The rebuilt `Masked` owns its factors/expansion state. Changing that owned value or a cloned routing receipt cannot change the proof. Callback error propagates immediately. The original move-only `Seed` is consumed; reconstruction uses existing messages and blocks, not a new seed stream. Lifetime roots and row-disclosure semantics now match the ordinary entry point.

The inherited challenge schedule remains:

1. Existing caller statement framing remains its responsibility, unchanged by this low-level research API. The production relation wrapper absorbs `RelationStatement` before entering claims (`zk_relation.rs:420–424,459–463`). Early sources, including multiplicities, precede lookup statement/unit messages and `LookupBeta`, then `LookupAlpha` (`zk_claims.rs:3071–3080`; RFC-0013 A5 order at spec lines 407–415).
2. Top and shared-mask roots are absorbed before relation/GKR rounds (`zk_claims.rs:3125`). The first step draws `ZeroWeight`; each step draws `FractionGamma` through `lookup::start` (`zk_lookup.rs:769–787`). Source inputs remain fixed before their points.
3. Masked sumcheck absorbs encoded instance, binding, and mask sum before `ZkMaskWeight`; each round payload precedes its challenge; checked expanded finals plus mask final are absorbed before return (`stele-sumcheck/src/masked.rs:225–263,330–403`). Declared degree comes unchanged from the plan, including compact versus expanded maximum, per RFC-0008 A7 implementation notes (spec lines 513–526,579–586).
4. Only then do existing public aborts and public-final checks execute, followed by observation (`zk_claims.rs:3339–3357`). Actual source claims enter unchanged batches, layer-block/mask claims enter the shared batch, and actual children feed unchanged `FractionFold`/next-step state (`zk_claims.rs:3359–3365`; `zk_lookup.rs:1317–1349`). There is no callback-controlled claim consumer.
5. Existing `BatchCoefficient` draws, masked source batches, shared batch, and PCS openings remain unchanged. The verifier repeats public-final routing at the same reduction point and consumes all claims through existing source/shared openings (`zk_claims.rs:3623–3675`). Successful `route` alone never authenticates arbitrary non-public values.

## Checklist (Workflow 03)

1. **New public items / RFC:** `observe_gkr`, `GkrCase`, `GkrClaims`, and read-only `Masked` accessors expose existing RFC-0008 A7 / RFC-0013 A5/A6/A8 producer behavior for RFC-0014 section 6 instrumentation. No new protocol behavior or commitment was added.
2. **Challenge/absorb order:** traced above; unchanged, callback inserted after final absorption. No challenge is derived outside `Transcript`.
3. **Claims/consumers:** source finals -> existing source batch/opening; block and mask finals -> shared batch/opening; child values -> existing line fold and next step. Public head/selector/padding/member/table finals are recomputed. Point identity is preserved through borrowed references.
4. **Bindings/controls:** no new binding. Existing NC-0913/0914/0917/0918/0919 were independently executed. New tests exercise a one-value public final, wrong final length, false multiplicity, malformed columns, wrong root, callback failure, and missing lifetime disclosure.
5. **Ledger:** no changed ledger generator/verifier lines or formula/degree inputs. The observer adds none. Accounting union gate was not rerun by this reviewer; no claim of a passing mandatory gate is made here.
6. **Bounds:** no new bound certificate or instance family. Existing plan validation and static degrees remain authoritative.
7. **Padding/masks:** actual production helper retains selectors, shifts, heterogeneous alignment and padded multiplicities, per RFC-0008 A7 notes lines 571–594. Compact test and independent one-step padded probe passed.
8. **Determinism:** no hash-map iteration or timing-based value path added. Rebuild uses the identical captured run, plan, layers, columns, source messages and mask blocks before advance. Successful observed proofs, transcript continuation and lifetime disclosure matched ordinary outputs.
9. **CPU/SIMD/CUDA parity:** this proves CPU-observed versus ordinary CPU identity only. No CUDA/SIMD comparison or integrated device proof was run or claimed. RFC-0014 section 5 still applies to any device consumer.
10. **Cost:** no performance or moved score cell claimed. Reference rebuilding, copying/retention, expansion, route recomputation and receipt cloning are explicitly host overhead (`GKR-REFERENCE.md:33–39`). No whole-stage credit from rounds alone.
11. **Verifier/no_std:** verifier/parser behavior untouched; public helper lengths/full-fold state are guarded. Bench no-default-features compilation passed at the initial implementation and again at final `178139d1`. No new verifier panic path found.
12. **Glossary/forbidden:** no new forbidden synonym, unsafe block, float, bypass flag, logging, dependency, or challenge path found in the diff. The vanishing-coordinate wording is corrected.
13. **Tier:** development/research interface only; docs explicitly disclaim integrated GPU proof, complete device budget, speedup and ADR-127 GO evidence. No promotion or claimed security level.
14. **Commit rule:** no committed/virtual tensor changes; only production inputs and claims are observed.
15. **Plain checker:** 27 `stele-ir` relation tests passed, including honest cases of every relation kind, lookup/range/matmul near misses and selector/padding behavior. Checker implementation unchanged.
16. **Segments:** no source-plan or earlier-segment read changed.
17. **Proof bytes:** ordinary versus observed encoded bytes, proof objects, transcript continuation and lifetime disclosures agree in the new tests; independent one-step/two-lookup probe also agrees. No amendment or digest rerecording needed for this interface behavior.
18. **Ladder:** no named L0/L1 rung or performance ledger run by this reviewer. Mandatory final-tree ladder/native/workspace gates remain outstanding from this review's perspective. A consumer must wait for actual interface merge (Workflow 12).

## Independent execution evidence

All commands used Rust `+1.90.0`, `CARGO_INCREMENTAL=0`, and `CARGO_TARGET_DIR=/tmp/stele-e16-40g-spec-target`.

- At initial `a661cae2`: `cargo test -p stele-reductions --features bench --test gkr_bench -- --nocapture`: 2 passed.
- At runtime-fix `89096668`: same command: 3 passed, including missing-disclosure regression. Final `178139d1` changes only a comment; full delta reviewed.
- At `a661cae2`: `cargo test -p stele-negative-controls --features controls --test nc-0913 --test nc-0914 --test nc-0917 --test nc-0918 --test nc-0919`: each passed through the real composed verifier.
- At `a661cae2`: `cargo test -p stele-ir --lib relation::tests:: -- --nocapture`: 27 passed.
- At `a661cae2` and final `178139d1`: `cargo check -p stele-reductions --no-default-features --features bench`: passed.
- External probes, initial and fixed runtime: `cargo test --offline --manifest-path /tmp/stele-e16-40g-spec-probes/Cargo.toml reviewer_ -- --nocapture`: 2 passed. The standalone lock was seeded from the repository Cargo.lock before recorded runs. Probe source is `/tmp/stele-e16-40g-spec-probes/tests/probes.rs`; it retains the initial test fixture plus `reviewer_compact_expansion_does_not_authenticate_combined_factor` and `reviewer_one_step_compact_and_multiple_lookups`.
- A persistent copy of the probe source, manifest and lock is retained in `/Users/abdel/dev/stele-validation/e16-40g-spec-probes/`.
- Exact probe diagnostic: `step=2 lookup=0 compact_factors=10 ignored_combined_index=8`.

**I tried to break it by changing one masked layer value and the control NC-0913 rejected it with RoundSumMismatch.** NC-0914 rejected the changed layer mask-block opening with RootMismatch; NC-0917/0918 rejected altered public head/selector finals with ClaimMismatch. The callback-failure and malformed/false input regressions also rejected as specified.

Skipped: full workspace, native/accounting union, digest, L0/L1, GPU parity, fuzzing and performance measurements; these were not assigned to this independent review. Risk: observed inputs are private, compact expansion is not authentication, and device consumers still need complete per-round/per-factor comparisons and the required integration gates after actual interface merge.

Coordinator ancestry note: this interface was moved ahead of the hardware-dependent changes, from base PR401 to PR398 (`631f2336`). The original review head `178139d1` maps to rebased `108f34de`; the disclosure fix maps to `8c455ade`. An exact git diff of all reductions source/tests and GKR-REFERENCE.md against `task/E16-40g-before-reorder` is empty. The reviewed runtime is unchanged; this note does not replace the later current-main/intended-tree gates. Original commits remain in the local backup branch for audit.

# E16-10b2 — independent Spec and soundness review

Reviewer: `codex-column-route-spec-review`, lane C; independent of the lane V
author. Skills: `soundness-auditor`, `rfc-author`; Workflows 02, 03, 08 and 12.
Fixed comparison:
`git diff e78345d33d7c14fabdb7848537e7004872b6cc94...548ae5494977a7c2478afeff913dfa52df0e0254`.
Inspected commits: `4cf6bd84` (claim), `548ae549` (draft and qualification).

## Spec findings and decision

**Approve RFC-0026 A18's exact development-tier amendment under Workflow 02
item 4.** No missing, incorrectly implemented or out-of-scope requirement was
found in this specification-only diff. Acceptance bookkeeping and required
current-main merge-tree gates remain the integrator's work; this is not merge
certification.

The task requires “one column claim routed to its distinct adjacent real column”
and “the same witness, roots, claim value and tail.” The isolated patch selects
the first claim of ColumnId(147), verifies its neighbour is ColumnId(148) in the
same real group, and changes only the leading Boolean index from `index` to
`index + 1`. Full-vector equality makes the rerouted scalar claim true. The
single changed claim, unchanged tail/value and complete restoration assertions
exclude an opening-scalar substitute or padding-column route.

RFC-0006 A2 requires absorption of the “complete descriptor” before
`BatchCoefficient`. The verifier independently derives the original claim list;
the producer's different descriptor changes its transcript before the source
opening. Genuine producer success and exact round-sum rejection therefore
justify the replacement contract without removing a check. A18 correctly limits
this result to the declared L0/L1 fixtures under profiles 3/5, retains the older
contract for other profiles, and disclaims universal rejection precedence and
PCS value-authentication coverage. NC-1308 remains `todo`; neither this review
nor the experiment earns catalog execution, promotion or performance credit.

## Evidence checked independently

- Read the complete four-file diff, task acceptance, RFC-0026 §2.3, §4 step 7,
  §9, A4 and proposed A18, RFC-0006 A2/A8, ADR-136, and the qualification record.
- Confirmed both external checkouts are at
  `6f7182b9110de8dd7b0c250dd10ab48e2d851cc1`; the reference is clean and the
  producer copy changes only `crates/stele-reductions/src/relation.rs`. Its full
  diff equals the recorded patch, SHA-256
  `dd21c346044da9b0c87e191c7b11cb9fb327e57e499edddd2e13f5e044dec7d6`.
  Both external harness sources match `main.rs`, SHA-256
  `52ede4bf4ed77378c0e0e6fb75754a9877eca1a7d52856f7ac4a6a79b719181b`.
- Inspected `group_claims`, producer and verifier step 7, `Opening::prove/verify`,
  and `claim_batch::{encode,start,prove_with_point,verify,finish}`. The patch is
  confined to the producer call; no verifier mapping or check changes. The
  reference-to-CLI-source comparison, ending at
  `9e215b19ffe3e87300144d47fe2a579f8e759969`, has no `crates/` delta.
- Re-ran `/tmp/stele-codex-e8-02f3c/target/release/stele verify-dev --public
  <case>/public.bin --proof <case>/proof.bin` for all eight stored artifacts.
  The CLI SHA-256 is
  `8ed9682782c314d60d7aa8fb6a7b066ca62bb3787ffb8d5909b03a59785c85d7`.
  Each honest case exited 0 with `YES`; each routed case exited 1 with exactly
  `NO: Engine(Sumcheck(RoundSumMismatch))`.
- Independently decoded the containers according to
  `stele-proof/src/development.rs`, checked all recorded artifact SHA-256s and
  identical public bytes, headers, groups, multiplicities, identities, lookups
  and matmuls. Opening counts match and only dependent opening bytes differ.
  Both profile-5 honest proofs also equal the existing
  `/tmp/stele-a16-windows/{one-layer,eight-layer}/proof.bin` pins.
- `git diff --check` passed for the fixed comparison. Reviewed both successful
  producer logs and their before/after plain-checker assertions; the disclosed
  initial compile failure is not counted as rejection evidence.

Artifacts and qualification source:
`/Users/abdel/dev/stele-validation/column-route-qualification/`.

I tried to break it by submitting the four genuine neighbour-routing artifacts
with their unchanged public statements, and the control qualification replay
through the unchanged production verifier rejected it with exactly
`Engine(Sumcheck(RoundSumMismatch))` in every declared case.

## Soundness checklist

- [x] Public items: no API added. A18 replaces only the current-profile NC-1308
  expectation in RFC-0026 §9; §2.3/A4 and §4 step 7 govern the routing.
- [x] Challenges: none added or reordered. Statement/model roots and stacked
  roots precede claims; complete A2 point/value descriptor precedes gamma,
  each round precedes its sumcheck challenge, and BatchFinal precedes the PCS
  opening. The mutation changes descriptor content, not this schedule.
- [x] Claims: no new obligation. The genuine A2 batch emits its exact source
  point/value to the ordinary point opening of the already committed source.
  The verifier derives its own complete input claim list.
- [x] Bindings/controls: no new binding. NC-1308's one prefix change is explicit;
  exact real-verifier rejection is qualified, while mandatory execution remains
  E16-10b. No producer failure or arbitrary error counts.
- [x] Ledger: no line changes. Existing A2 RLC `t/|K|` and SC `2S/|K|` records
  remain; their algebraic argument is conditional on uniform challenges. No
  new theorem or security claim; existing development PCS/FS qualifications
  remain. The cumulative accounting gate was not rerun by this reviewer.
- [x] Bounds: no new instance, bound certificate or runtime-derived parameter.
- [x] Padding/masks: unchanged; the selected neighbour is a real group member,
  not a padded source column. No lookup or zerocheck selector changes.
- [x] Determinism: fixed fixtures and canonical group/column iteration; no new
  hash-map iteration, random source or timing-dependent reduction.
- [x] Parity: no production or GPU changes in this diff; no fresh SIMD/CUDA
  parity result claimed or run.
- [x] Cost model: no term moved and no benchmark claimed. The retired risk is
  the mismatch between NC-1308's old error and the observed batch precedence.
- [x] Verifier: unchanged, including its `no_std`, validation and plan-derived
  lengths; the qualification adds assertions only in an isolated producer copy.
- [x] Glossary: no new forbidden synonym or alternate protocol vocabulary.
- [x] Tier: development only, source profiles 3/5; no security level, zero
  knowledge, `standard` or `treaty` admission.
- [x] Commit rule: sources, committed columns and virtual columns are unchanged.
- [x] Plain checker: no semantic change. Reviewed successful before/after
  `check` calls in the qualification; did not independently regenerate the
  witness or rerun near-miss tests. Honest full verification was rerun above.
- [x] Segments: no new segment or read from an earlier non-carried column.
- [x] Proof bytes: no honest format/algorithm change. Both profile-5 pinned
  honest artifacts match; altered bytes are confined to dependent adversarial
  openings. No proof-pin rewrite is requested.
- [x] Ladder: independently verified L0/T=16 and L1/T=64, each under profiles
  3/5, for honest and routed proofs. These are rejection qualifications, not
  before/after performance ledgers or full required-gate runs.

Skipped: producer rebuild/re-execution, near-miss suites, cumulative gates and
GPU parity. Required merge gates remain outstanding in integration; this review
does not establish PCS value-authentication coverage or another profile's error.

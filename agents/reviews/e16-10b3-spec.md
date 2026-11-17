# E16-10b3 specification/soundness and owning lane P review

Reviewer: `codex-root/route_producer_spec_review` (independent owning lane P review).
Base: `685258d2d7820aba20b790eebfa478bee538783f`.
Reviewed head: `7a95d79e74ca3ba995f8fa103873a2d930421df8` (PR394).
Scope: `4604549a` task claim and `7a95d79e` controls-only producer interface.

**Approve this interface and implementation at the reviewed head; no findings.**
Read AGENTS.md, task acceptance, soundness-auditor skill, soundness/forbidden
guardrails, full review checklist, Workflows 03/10/12, RFC-0030 (Draft), and the
governing Accepted RFC-0026 §§2.3/4 step 7/A4/A18, RFC-0006 A2 and RFC-0027 §5.

A18 requires “change only its Boolean column-index prefix” and “Generate genuine
dependent claim batches and source openings”. Selection validates real witness
membership, a next real column in that group, and identical assigned vectors;
other mutation selectors are rejected. The helper traverses the same ordered
group/column/claim list as `group_claims`, changes its first selected claim, checks
unchanged value/tail/other claims and exact restoration, then calls the existing
batch and PCS producer. Every pre-opening section remains unchanged. The verifier
never consults the selector, including with `controls` enabled.

RFC-0027 §5 permits editing another lane's code when “reviewed by the owning lane”.
Owning lane P approves this small producer interface; the existing explicit Forge
callers are adapted and default Forge preserves ordinary proof bytes. PR393's A18
is independently Accepted; merge this lane-V stack bottom-up before E16-10b.

I tried to break it by routing the first claim to an equal-valued adjacent real
column under profiles 3 and 5, including interleaved ColumnIds, a padded group and
a later group offset, and the control `rejects_forged_column_claim_with_unchanged_sources`
and independent interleaved-group probe rejected it with exactly
`Sumcheck(RoundSumMismatch)` in the unchanged engine verifier.

This approval supplies no composed NC-1308 catalog credit: A18 says it “remains
reserved and `todo` until E16-10b”. Fresh PR394 workspace/native/accounting/digest/
ladder CI on the merged PR393 base and intended merge tree remains required.

## Required checklist evidence

- [x] **Public items / RFC.** `Forge::column_claim` is feature-gated to controls;
  RFC-0026 A18, §2.3/A4, §4 step 7 specify its sole mutation. `route_column_claim`
  and `Plan::column_claim` are private. All Forge literals were searched; two
  existing complete literals now explicitly use None. No config/export change.
- [x] **Challenges / absorbs.** No new challenge, label or absorb. The unchanged
  prefix starts with `Transcript::new(public)`, relation digest and model roots,
  then stacked/multiplicity roots. RelationIdentity follows these roots;
  ZeroWeight follows Zero, sumcheck challenges follow their rounds, and ZeroFinal
  binds finals. LookupStatement/Units/Multiplicities/Repetition precede beta/alpha
  (profile 5's existing grind precedes those draws); unchanged fraction rounds
  and finals follow. RelationPoint follows prior subprotocol finals, and the
  matmul instance binds its output before sumcheck. The changed path is exactly
  `group_claims -> route_column_claim -> Opening::prove -> Batch::start`: the
  entire ordered point/value descriptor is absorbed as Batch before
  BatchCoefficient; Round precedes each Sumcheck; the final equation is checked
  and BatchFinal absorbed before PCS. Opening binds the same emitted point/value
  and certificate, OpeningRow precedes nonce/query draws, and OpeningColumns
  binds responses. Hence changing the descriptor changes gamma and dependent
  rounds, without changing the honest verifier transcript or order.
- [x] **Claims / consumers.** Identity finals are restricted to each Ref's point;
  lookup finals become tuple-column claims (multiplicity openings stay in step 5);
  matmul emits out/lhs/rhs claims at its derived points. Public claims retain the
  verifier's direct MLE check. Witness claims become Boolean-prefix stacked
  claims; only one prefix changes for this control. Weight claims retain their
  model source. `Opening::verify` passes the batch's sole emitted `claim.point`
  and `claim.value` directly to `verify_point` with the earlier certificate.
  Equal assigned vectors make the rerouted scalar true, allowing genuine proof
  generation. No prover-value-only discharge is introduced.
- [x] **Bindings / controls.** No new accepted binding. Existing A2 descriptor
  binding is exercised by the new exact-error engine test under CircleAll/3 and
  CircleAllGrind/5. Invalid, unequal-neighbour, last-column, public, weight,
  combined and unused selectors reject; the helper asserts exact restoration.
  NC-1308 remains todo, with full composed-window control left to E16-10b.
- [x] **Ledger.** No line changes: geometry, counts, degree-2 batch SC, RLC, PCS
  queries and lookup grind are unchanged. No new theorem or security assertion.
  Full `soundness-accounting.sh`/native union was not independently duplicated;
  fresh PR394 CI remains pending after PR393. No ledger regeneration is claimed.
- [x] **Bound certificate.** No new instance or integer identity. Existing
  `Relation::validate` and plan geometry stay static and verifier-derived.
  Equality of supplied vectors only qualifies this controls producer fixture;
  it does not replace a verifier bound or check.
- [x] **Padding / masks.** No change to lookup selectors or zerocheck masks.
  `group.columns.get(j+1)` forbids routing into group padding or another group.
  Independent probe exercised `[0,2,4]` (padded to four columns) and `[1,3]` at a
  nonzero block offset; last real columns reject.
- [x] **Determinism.** Only ordered Vec traversals and first-claim selection;
  no unordered map, clock, randomness or alternate reduction order. Default Forge
  equals ordinary Proof byte vectors in both profiles.
- [x] **Parity.** No GPU/SIMD code changes or parity claim. Fresh digest/ladder CI
  remains required; GPU parity was not run for this producer-only seam.
- [x] **Cost model.** No production term moves and no benchmark claim. Extra
  copying/assertions occur only when this controls selector is used.
- [x] **Verifier.** Source and predicates unchanged; Plan defaults the selector to
  None and verifier never reads it. New assertions are confined to the private
  controls producer helper whose group, claim and batch shapes come from the same
  validated plan. Independent `cargo check -p stele-reductions --no-default-features`
  passed; `#![no_std]` remains. No production parser or length source changes.
- [x] **Glossary / forbidden patterns.** No new forbidden synonyms, unsafe, floats,
  alternate challenges, bypasses, untracked performance numbers or promotion
  claims in the diff. `git diff --check` passed.
- [x] **Tier.** Development-only adversarial producer, with no security-level,
  zero-knowledge, standard/treaty or other-source-profile credit. RFC-0030 remains
  Draft and is not used to override Accepted text.
- [x] **Commit rule.** No new commitment or virtual column. The same witness and
  multiplicity values produce byte-identical certificates; all existing
  development cuts remain exactly those governed by RFC-0026.
- [x] **Plain checker.** Independently ran all 27 `stele-ir --lib relation::tests::`
  cases: honest, identity/lookup/matmul/range near-misses, wrapping identities,
  malformed refs, padding-related selectors and composition cases passed.
- [x] **Segments.** No segment or carried-column interface changes; routing is
  explicitly within one current witness commitment group.
- [x] **Proof bytes.** Honest production bytes unchanged; independent default Forge
  comparison and new unit test assert equality under both profiles. Routed proof
  changes only dependent opening sections, as A18 authorizes. No pin rewrite is
  warranted; full pinned-digest gate awaits CI.
- [x] **Ladder.** This review independently ran engine fixtures, not a ladder rung.
  No rung/performance claim or before/after ledger comparison is made. L0/L1
  composed NC-1308 execution belongs to E16-10b, and fresh ordinary ladder/native
  CI must cover PR394's final main base before merging.

## Reproducible independent evidence

All commands used `/tmp/stele-e16-10b3-spec-target`, with the reviewed head unchanged.

- `cargo test -p stele-reductions --features controls forged_column_claim -- --nocapture`:
  3 passed (routed, invalid, unused); honest engine acceptance and exact routed
  error exercised separately for profiles 3/5.
- `cargo test -p stele-ir --lib relation::tests:: -- --nocapture`: 27 passed.
- `cargo check -p stele-reductions --no-default-features`: passed.
- Independent public-API probe: six genuine routed proofs, six invalid-selector
  attempts, honest acceptance, default proof equality and unchanged pre-opening
  sections; all passed. Exact source, Cargo lockfile, commands and stdout are
  preserved outside the repository in
  `/Users/abdel/dev/stele-validation/e16-10b3-spec-probe/`.
- Implementer's source/default/no_std/controls and all-targets/all-features Clippy
  logs are `/Users/abdel/dev/stele-validation/e16-10b3-{relation-controls,relation-default,no-std,clippy}.log`;
  these are supporting evidence, not substitutes for the independent tests above.

Skipped duplicate workspace/native/accounting/digest/ladder and GPU suites. Risk:
merge remains gated on fresh passing CI after the base lands; composed NC-1308
coverage is intentionally ungranted.

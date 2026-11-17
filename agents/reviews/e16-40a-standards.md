# E16-40a standards and lane B review

Reviewer: Codex, independent lane B review of lane V work.
Fixed base: `07a7710044b8dc7b2f39433694cad7dba58ba062`.
Reviewed head: `3a1e077e0d6c35a18c9332fab326483c31baa066`.
Diff: `git diff 07a7710044b8dc7b2f39433694cad7dba58ba062...3a1e077e0d6c35a18c9332fab326483c31baa066`.
Commits: `2ec1bbe0`, `3a1e077e`. No implementation changes made by this reviewer.

## Disposition and findings

**Lane B: hold benchmark qualification; standards axis has no hard coding-standard
violation or discretionary smell finding.** This is a pinned-head review, not merge
approval. The H100 CPU ledger, owning lane P review, and current-main L0/L1 and
mandatory gates remain outstanding. RFC-0018 A1/A2 and Workflows 04/12 require that
evidence; the zero-time fixture grants none.

One benchmark-integrity concern needs resolution before relying on the parser:
`research/gpu-gating/stage_inventory.py:24–37` accepts `degree=0` on the fixture's
first nonconstant masked relation. Index checks do not establish a valid degree
bound, although `STAGE-INVENTORY.md:78–80` promises shape-bound validation. At
minimum reject degrees below a topology-derived lower bound and test the case,
or precisely narrow the advertised validation. This is a correctness concern,
not a Fowler smell or a claim that verifier soundness changed.

Independent probes also accepted swapped source-child order and removal of a whole
batch group. The first agrees with the separate spec review. The latter exposes a
limit: equal child counts alone cannot establish complete coverage without an
expected group count. Document that limit rather than crediting parser success as
full inventory evidence.

Read AGENTS, task acceptance, invariants/glossary, all six guardrails, Workflows
03/04/09/12, benchmark-runner, RFC-0014 including §6/A1, RFC-0018 including A1/A2,
RFC-0026 §7, RFC-0027 §5, and the two-axis code-review skill. No CONTRIBUTING or
CODING_STANDARDS file exists. Repository rules override smell heuristics; tooling
findings are omitted.

The scope is small and complete across producer, caller, fixture, parser, tests and
documentation. Existing `Laps` and dependencies are reused; no exports, backend,
ledger schema or proof interface changes. Parent/child costs, setup/reporting
overhead, source rebuilds, complete certification/opening work and CPU remainder
are described honestly. No fitted constant, speedup, device-memory or GPU GO credit
is claimed.

I tried to break it by removing a batch opening, adding overlapping child time and
an extra shape field, and the parser controls rejected it. The actual prover's
`rejects_wrong_multiplicity` control also rejected its tamper. The degree and order
probes above were not rejected.

## Repository checklist

- [x] Public items: no new public API; private topology observer implements RFC-0014 §6; `is_first` documents RFC-0008 A7 item 4.
- [x] Challenges: no draws or absorbs added/moved; source roots still precede lookup challenges and existing round messages precede round challenges.
- [x] Claims: no changed claims or consumers; occurrence/GKR finals still feed source batches, authenticated openings and the shared mask batch at the original points.
- [x] Bindings: no new binding; existing wrong-multiplicity control passed independently.
- [x] Accounting: no soundness-ledger lines change; accounting-union gate not independently rerun.
- [x] Bound certificates: no new instances; static validation remains unchanged. Parser geometry validation concern is above.
- [x] Padding/masks: unchanged selectors and masking; observer records coordinates/topology only, never factor values, coefficients, seeds or challenges.
- [x] Determinism: ordered producer vectors; timers cannot affect reduction order or transcript. Off/on subprocess proof-field digests match.
- [x] Parity: CPU instrumentation parity passed; no SIMD/CUDA change. GPU parity not rerun or credited.
- [x] Cost model: instrumentation only; no term or measured constant moves, and no benchmark claim follows from the fixture.
- [x] Verifier: unchanged code/dependencies; observer is `std`-gated and timers already become no-ops without `std`. Build gates remain integration evidence.
- [x] Glossary: no forbidden synonyms introduced.
- [x] Tier: development only; no security-level, unconditional ZK or promotion claim.
- [x] Commit rule: no committed/virtual column changes.
- [x] Plain checker: independently ran 27 relation tests, including honest and identity/lookup/matmul near misses; all passed.
- [x] Segments: no relation reads or source lifetimes changed.
- [x] Proof bytes: actual prove/verify subprocesses have equal digests of all derived-Debug proof fields; production serializer/digest gates remain required, not independently credited here.
- [ ] Ladder: H100 validated ledger with actual verified hashes and host/thread/affinity/toolchain/run metadata is pending; no new independent L0/L1 evidence.

## Checks run

- `python3 -m unittest scripts.tests.test_stage_inventory`: four passed.
- `cargo test -p stele-reductions --features std --test zk_lookup matches_reference_stage_instrumentation`: passed.
- `cargo test -p stele-ir relation::tests`: 27 passed.
- `cargo test -p stele-reductions --features std --test zk_lookup rejects_wrong_multiplicity`: passed.
- Pinned diff whitespace check: passed. Three additional malformed-log probes are recorded above.

Skipped full workspace/native, no_std, ladder and GPU reruns in this focused review.
Risk: parser validation gaps and missing H100/current-main evidence prevent benchmark qualification or merge approval.

## Correction review at a9fd51f8

Reviewed head: `a9fd51f891ade65c5d95fa8ee6dd03b1da1eb130`.
Correction diff: `git diff 3a1e077e0d6c35a18c9332fab326483c31baa066..a9fd51f891ade65c5d95fa8ee6dd03b1da1eb130`.

**Standards and lane B instrumentation interface approved at this head.** Prior
parser findings are resolved: public plan counts detect omitted whole batches;
child/shape order is enforced; zero degree is rejected. Documentation now precisely
limits geometry validation. No new coding-standard or smell finding. Benchmark
qualification still requires H100/current-main evidence.

I tried to break it with the original malformed logs and five additional mutations,
and all eight probes rejected.

Correction evidence and checklist updates:

- [x] Seven parser tests and expanded real off/on prove/verify subprocess test passed independently.
- [x] Fresh real subprocess logs for both leaf-only and first/interior/leaf trees parsed successfully; declared counts and complete public shape inventories matched their sanitized fixtures.
- [x] Independent probes rejected zero degree, zero dimension, reordered children, an omitted whole batch, duplicate/missing declarations, misplaced shape, and mixed field degree.
- [x] Public observer: new plan counts are public geometry only. No challenge, claim, binding, protocol degree, committed column, source lifetime or verifier behavior changes; the remaining repository checklist carries forward.
- [x] Correction diff whitespace check passed. Author-reported no_std and Clippy passes were not independently repeated.
- [ ] H100 validated ledger, owning lane P approval and current-main mandatory/L0/L1 evidence remain merge requirements; neither fixture is benchmark evidence.

Skipped full gates, ladder, GPU, and duplicate no_std/Clippy runs for this correction.
Remaining risk: H100 measurement and current-main validation are pending; this approval grants no GPU GO, speedup, or fitted-cost credit.

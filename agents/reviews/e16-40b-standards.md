# E16-40b standards review — PR #396

Independent lane B review of `59f9a18ba0db3dd096912bbe4fa130f25fddad16` against
`b8e89a376b5e10dbefa3848636f0ea9ff853102c`, using the three-dot diff. Commits:
`526b3910` (claim), `95ac6e4b` (parent merge), `59f9a18b` (implementation).
Also inspected documentation-only follow-up `54ad0883289c9dabff7e814fe8e0a665ea08483f`;
its two header replacements leave runtime code unchanged.

## Findings

**Outstanding documented-standard violations:** none found.

**Resolved P3:** the module headers in
`research/gpu-gating/masked/examples/source_material.rs:1` and
`src/gpu_source.rs:1` omitted their governing RFC. `54ad0883` adds RFC-0014 §4/A1
to both, satisfying `AGENTS.md` §6 and `agents/guardrails/code.md`.

**Baseline smells (judgment):** none warrant a change. The common `run` retains
one device algorithm, the existing root-only entry point stays distinct, and
`Material` owns response slicing and path construction. No speculative interface,
dependency, telemetry, challenge, verifier authority or production backend was
added. The research allowance is documented by ADR-127; this review grants no
backend-trait or full-proof parity credit.

The transfer/retention counters explicitly exclude driver/runtime resources.
The report makes no speedup, device-budget, security-level or GO claim. Its
hardware evidence is still pending rather than represented as a measured result.

Verdict: standards approved at `54ad0883`; no remaining findings. This is not
merge approval.

## Independent evidence

I tried to break it by changing one payload byte, truncating encoded material or
Merkle nodes, inserting the noncanonical M31 value `p`, and supplying an empty
message; the control `matches_reference_complete_source_material` rejected the
payload tamper with ordinary `merkle::Error::RootMismatch`, and
`rejects_incomplete_or_noncanonical_material` rejected the malformed material.
Both targeted tests passed at the reviewed head. The first also compares every
salted payload/path against production `PreparedSource` for the three CPU cases.

Read: `AGENTS.md`, E16-40b acceptance, invariants, glossary, code/security/forbidden/
GPU-parity/review-checklist guardrails, Workflows 03/09/12, `cuda-kernel-author`,
RFC-0014 §§1/4/5/A1, RFC-0010 A9, RFC-0012 A3, RFC-0013 A8, RFC-0003 §1 and
`docs/plan.md` §3.8. No CONTRIBUTING or CODING_STANDARDS file was found.

## Required review checklist

1. Public items: `Material`, `material`, response/root/storage accessors and
   `prepare_material` implement RFC-0010 A9/RFC-0012 A3 source bytes; timing and
   storage fields address RFC-0014 §4/A1. Header citations corrected.
2. Challenges/absorb order: no added challenge or transcript operation.
3. Emitted claims/consumers: no new algebraic claim or verified handle.
4. Binding controls: no new binding; existing Merkle binding exercised by the
   one-value `RootMismatch` control above. No catalog-control credit claimed.
5. Soundness ledger: unchanged; accounting-union gate not independently run.
6. Bound certificates: no new relation or bound instance.
7. Padding/masks: source geometry and salts remain production-defined; complete
   real leaves compared. No lookup/zerocheck padding change.
8. Determinism: ordered vectors and existing kernels; no hash-map iteration,
   new atomic reduction or timing-dependent result.
9. Parity: CPU complete-material comparison passed. H100 1,000-seed operation
   parity remains pending; neither this test nor that run is full-proof parity.
10. Cost model: source preparation `c_c`/`T_misc`, storage and transfers are being
    measured; no moved value or benchmark ledger claimed by this head.
11. Verifier: untouched; no new dependency, parser, panic or plan-derived length.
12. Glossary: no forbidden synonym introduced.
13. Tier: research supporting development; no promotion or security claim.
14. Commit rule: existing hiding source only; no new committed/virtual column.
15. Plain checker: relation checker untouched and not rerun here; honest source
    parity and malformed-material near-misses passed independently.
16. Segments: no relation/segment access changed.
17. Proof bytes: no production producer/verifier change; mandatory digest gate
    remains the integrator's evidence obligation.
18. Ladder: no rung or before/after measurement run by this reviewer. Paired H100
    measurements and validated ledgers remain pending.

**Outstanding hardware evidence:** the parent owns H100 operation parity and
paired CPU/GPU measurements, all samples, host/device overlap and validated ledgers.
The parent reports its job submission was rejected before allocation; no actual
hardware pass has been claimed.

**Outstanding merge evidence:** mandatory gates must cover current `main` and the
intended merge tree; this fixed-head review and the reported local checks do not
establish that coverage. Owning lane E review is separate from this lane B review.

Skipped full workspace/native suites, hardware runs and tooling-enforced style
checks. No integrated GPU backend, certificate or full-proof parity was validated.

## Hardware-evidence addendum — cf9d3956

Fresh lane B standards review of
`9a6e7028fae59e52f50a037a9c37894cf3445b8f...cf9d3956c1eaa1c935e67d86b950662e681f0c38`.
Scope: three generated microledgers and `SOURCE-MATERIAL.md`; runtime code is
unchanged. This supersedes the earlier hardware-pending statements only.

**Documented-standard breaches:** none found. RFC-0018 §1 requires “never compare
across statements without saying so”; the CPU certificate/verification work
absent from the GPU command is explicit. RFC-0014 A1 requires “actual device
allocation and transfer lifetimes, including host/device overlap”; the report
correctly disclaims complete device-peak and 40% evidence.

**Baseline heuristics:** no actionable smell. The changed hunk says “Ranges below
span all three repetitions”; repeated generated records preserve evidence and
do not warrant extracting a new abstraction.

Independently reconciled all 21 commands, 85 measurement hashes, seven parity
hashes, the archive and its payloads, exact packaged-ledger bytes, decimal load
strings, timestamps, phase sums, storage formulas, nine paired roots and every
reported range. Cold GPU process time is greater in every pair. I tried to break
it by changing one in-memory payload byte, and the control comparing its SHA-256
with the recorded manifest rejected it.

Required checklist:

1. Public items: unchanged.
2. Challenges/absorb order: unchanged.
3. Claims/consumers: unchanged.
4. Bindings: unchanged; recorded device test checks `RootMismatch`.
5. Soundness accounting: unchanged.
6. Static bounds: unchanged.
7. Padding/masks: unchanged; canonical-field cases recorded.
8. Determinism: nine matching CPU/GPU roots; no proof claim.
9. Parity: 1,000 complete operations, not per-kernel/full-proof certification.
10. Cost: source preparation/transfer/assembly observations; no fitted constant.
11. Verifier: unchanged.
12. Glossary: no violation.
13. Tier: research only; schema tag grants no admission.
14. Commit rule: unchanged.
15. Plain checker: unchanged; not rerun.
16. Segments: unchanged.
17. Proof bytes: unchanged production code; merge gates remain pending.
18. Ladder: explicitly micro-only; inference scoreboard exclusion is appropriate.

Read AGENTS, invariants/glossary, all guardrails, Workflows 03/04/09/12,
benchmark-runner, cuda-kernel-author, RFC-0018 A1/A2 and RFC-0014 A1.
No CONTRIBUTING/CODING_STANDARDS file found. E17-01 remains ready; its future
counter requirement is not an outstanding breach here.

Standards approved for this evidence diff. ADR-127 remains NO-GO. Current-main
and intended-merge-tree gates remain required in stack order.

Skipped full suites, hardware reruns and tooling-enforced checks. Hash consistency
does not independently authenticate the remote execution; no integration approval.

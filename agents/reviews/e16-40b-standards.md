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

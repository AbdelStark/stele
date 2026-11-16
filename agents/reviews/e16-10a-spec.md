# E16-10a — independent lane-C spec/soundness review

Reviewed implementation: `f31aaeee7c8c07cf247e897d840e1d08eafdb527`.
Fixed base: `65f35281b7771c26b2a3209092345df7f45d1c04`.
Diff: `git diff 65f35281...f31aaeee` (commits `59100e66`, `2a32a72a`, `f31aaeee`).
Reviewer: `composed_messages_spec_review`, using `soundness-auditor` and the Spec axis of `code-review`.

## Spec finding summary

**Approved; no missing/partial requirement, incorrect implementation, or scope-creep finding.**

RFC-0026 §9 requires: “Each must run through the actual E16-10 verifier.” Both controls construct production proofs, accept them through `development::verify`, then use that same verifier for rejection. The four fixtures cover L0/T=16 and L1/T=64 under source bytes 3/5.

NC-1303 changes one canonical certificate-row limb to `p`; its offset includes the plan-derived tensor nonce and is checked against `Source::parse`. NC-1307 increments the first limb of the first QM31 matmul output claim modulo `p`, exactly field addition by one. The unchanged first sumcheck message consequently fails its round-sum equation. Restoring the limb restores the entire container; canonical encoding preserves every remaining proof byte. Public inputs remain immutable borrows outside the mutation hook. Full nested error equality excludes wrong rejection and producer failure.

Both registrations are mandatory proof controls. Native runs direct tests, catalog tests and executed coverage. The shared width binding is counted once; NC-1302/1306/1308 remain unregistered `todo` entries, with follow-up E16-10b recorded. No production code or Accepted RFC changes.

## Workflow 03 checklist

- Public items: hidden control runner, RFC-0026 §4 steps 2/6 and §9; wire RFC-0010 A9/A14.
- Challenges: none added; certificate canonical parsing precedes challenge replay; matmul point follows the unchanged statement/root/identity/lookup prefix.
- Claims: none added; matmul output supplies `claimed_sum`; existing routing uses the same `rho` and sumcheck point.
- Bindings: existing bindings covered by NC-1303 and NC-1307; no new binding.
- Ledger: no accounting lines change; accounting gate not rerun by this reviewer.
- Bound certificates: no new instances or runtime bounds; existing `Relation::validate` runs.
- Padding/masks: unchanged; no new lookup or zerocheck.
- Determinism: fixed fixture/profile order; immutable fixture cache; no timing or hash-map iteration.
- Parity: no CPU/SIMD/CUDA implementation change; GPU parity not rerun.
- Cost model: no optimization or performance claim; no benchmark ledger needed.
- Verifier: unchanged, including no_std boundary and plan-derived lengths; no production panic added.
- Glossary: no forbidden synonym introduced.
- Tier: development only; no security level, ZK or promotion claim.
- Commit rule: no committed or virtual column change.
- Plain checker: ran all 27 relation tests; honest and near-miss cases passed.
- Segments: no relation or carried-column change.
- Proof bytes: producer/codec unchanged; only deliberate control mutations; pins not independently rerun.
- Ladder: fresh L0 and L1 proofs verified in both source sets; no performance comparison or before/after ledger claimed.

## Checks performed

All cargo checks used `CARGO_TARGET_DIR=/tmp/stele-e16-10a-spec-target`, independently of the author's target:

```text
cargo test -p stele-negative-controls --all-features --locked --offline --lib nc_130 -- --nocapture
cargo test -p stele-ir --locked --offline --lib relation::tests:: -- --nocapture
cargo test -p stele-negative-controls --all-features --locked --offline --test proof-control -- --nocapture
cargo test -p stele-negative-controls --all-features --locked --offline --test catalog rejects_composed_message_tampers -- --exact --nocapture
git diff --check 65f35281...f31aaeee
```

Passed: 2 direct controls, 27 plain-checker tests, 3 harness failure-path tests, and the registered-control test. Diff check passed. Added-line forbidden-pattern search found no match. Read the author's tests-first red and targeted green logs; those are corroboration, not reviewer-run checks.

I tried to break it by replacing one certificate-row limb with `p` and incrementing one matmul output claim by one, and the control NC-1303/NC-1307 rejected it with `Engine(Pcs(NoncanonicalField))`/`Engine(Sumcheck(RoundSumMismatch))` respectively on all four fixtures.

Skipped duplicate workspace/native/accounting/parity gates; the parent reviewer owns final gate and merge-tree verification. Remaining risk: NC-1302/1306/1308 stay open and receive no execution credit here.

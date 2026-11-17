# E16-10b0 standards review

Reviewer: Codex, independent lane B reviewer of lane V work.
Inspected head: `5c8694f6b23e27f63a369dd2817962098243c660`.
Fixed base and verified merge base: `aa42a55fcccb681c3e5f41c69345a1e628ec05e6`.
Diff: `git diff aa42a55fcccb681c3e5f41c69345a1e628ec05e6...HEAD`;
commits `85fb3eee`, `6f71c82b` and `5c8694f6`.

## Decision

Standards approval of the draft amendment. No documented-standard violations;
no discretionary Fowler smell findings. Required integration gates remain the
integrator's responsibility on the intended merge tree.

I tried to break it by changing identity, lookup and matmul values, and the
control tests `rejects_identity_tamper`, `rejects_lookup_tamper` and
`rejects_matmul_tamper` rejected it with their exact expected violations.

Read `AGENTS.md`, context invariants/glossary, all guardrails, workflows 02/03/12,
the short amendment template, RFC-0027 §2, RFC-0026 A4/A11/A17, RFC-0010 A14,
and `formal/native-field-pcs.md` §3. No `CONTRIBUTING` or `CODING_STANDARDS` file
was found. Applied the code-review skill's smell baseline as judgement calls
subordinate to repository rules.

The RFC and ADR changes are append-only (Workflow 02.1; forbidden rule 6).
The short amendment contains the required motivation, exact replacement,
soundness, cost/encoding effects and control obligations (Workflow 02.4).
It neither changes production behavior nor grants a security claim or promotion
(INV-1/13; RFC-0027 §2). Index/catalog acceptance updates are explicitly pending,
and dependent implementation remains blocked; that is consistent with Workflow
02.5–6 while A17 is Draft.

The replacement requires distinct roots, unchanged remaining bytes, restoration
of the entire proof, and precise policy-specific errors. It forbids arbitrary
rejections and interchangeable errors. Existing certificate code checks both
nonce predicates before Merkle authentication, matching RFC-0010 A14. The
qualification expressly covers only profile 5; Policy 1 and profile 3 remain
separate obligations. NC-1306 stays `todo`; NC-0808's narrower evidence is not
credited to it (INV-4). No verifier predicate, binding or ledger line changes.

## Repository checklist

- [x] Public items: no new API; control contract is RFC-0026 A17 replacing A4's §9 entry.
- [x] Challenges/absorbs: none changed; existing root-bound certificate ordering inspected.
- [x] Claims/consumers: none added or moved.
- [x] Bindings/controls: no new binding; NC-1306 remains reserved pending E16-10b execution.
- [x] Ledger: no changed lines; accounting gate remains integration's check.
- [x] Bound certificates: no new instances or changed static bounds.
- [x] Padding/masks: unchanged.
- [x] Determinism: no production change; declared deterministic fixtures are required.
- [x] Parity: no CPU/SIMD/CUDA changes; GPU parity not rerun.
- [x] Cost model: no term moves or performance claims; no benchmark comparison.
- [x] Verifier: unchanged code, dependencies, `no_std`, length checks and error behavior.
- [x] Glossary: no forbidden synonyms introduced.
- [x] Tier: development only; no security level, zero-knowledge or promotion claim.
- [x] Commit rule: no committed or virtual column change.
- [x] Plain checker: independently compiled and ran all 27 `stele-ir` relation tests; passed.
- [x] Segments: unchanged.
- [x] Proof bytes: production encoding and pins unchanged; adversarial root mutation only.
- [x] Ladder: qualification declares L0/L1 profile 5 only; no independent root replay here.

Check command: `CARGO_TARGET_DIR=/tmp/stele-e16-10b0-standards-target cargo test -p stele-ir relation::tests --locked --offline`.

## Follow-up approval

Inspected `5c8694f6`'s prose-only correction; standards approval stands. It names
RFC-0010 A14 explicitly and confines nonce-before-Merkle ordering to the
substituted stacked-source certificate. This matches `stele-verifier`'s model
certificate checks preceding the stacked certificate and `stele-pcs`'s ordering
within that certificate. No predicate or execution credit changes. The initial
27-test result remains applicable; no tests were rerun for this wording change.

Skipped duplicate full gates and root-proof reproduction. Remaining risk: acceptance
updates and final merge-tree gates must complete; this review grants no NC-1306 execution credit.

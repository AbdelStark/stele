# E3-04 seeded reference review

Reviewer: codex-root, also the author. Same-author soundness-auditor and
sumcheck-prover-engineer passes; not independent audit. Production code unchanged.

I tried to break it by truncating one unused original value, and the control
NC-0204 rejected it with ClaimMismatch. The new test-only reference recomputes
original MLEs at every full prefix/node/Boolean suffix and sums monomials directly;
it has no prefix grid or materialized/folded tail. Sharing the A1 engine, field,
eq and transcript primitives means this is not a fully independent implementation.
The pending Python/Rust decisions remain complementary mandatory evidence.

Workflow 03 checklist:
- Public items: no API change; test-only Summand implements RFC-0006 A5's A1 relation.
- Challenges: unchanged Instance, Round before Sumcheck, then every Final.
- Claims/consumers: actual verify_public consumes all original inputs, including
  unused ones; checks compare all proof fields, ordered final claims, SC descriptor
  and numerator, derived-point length and all four transcript continuations.
- Bindings/controls: existing NC-0204 retained; no new coverage credit.
- Ledger: same SC m*delta/p^d; both named field tests required by both gates.
- Certificates: typed values only; no integer bound or private range proof added.
- Padding/masks: unchanged, no selector or privacy claim introduced.
- Determinism: fixed LCG seeds and ordered loops, 1,000 cases per degree/field,
  every supported (m,k) through m=4 and maximum k with tail at m=5. Includes mixed
  types, extrema, extension coefficients, repeated/mixed factors, constants,
  empty/unused inputs and zero coefficients without degree reduction.
- Parity: Small, Dense and direct reference in both fields; GPU unchanged.
- Cost: no performance claim; exhaustive reference is not a tuned baseline.
- Verifier: unchanged no_std consumer; reference allocations/assertions are test-only.
- Glossary: no changed claim or optimization eligibility meaning.

Sign-off: approve seeded coverage conditional on required gates. E3-04 remains
in progress until independent decisions and complete measured costs/memory pass.
Finite tests do not prove soundness or resolve Q12.

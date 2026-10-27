# RFC-0006 A1 / RFC-0020 A1 skill reviews

Reviewer: codex-root, also the author. These are same-author skill passes, not an
independent audit. Scope: the contract, reference evidence and control workflow;
production sumcheck, real corpus, accounting producer and benchmarks remain pending.

Soundness-auditor: approve the conditional interactive reduction statement.
The polynomial description bounds each variable's degree statically, including
repeated factors, zero coefficients and empty polynomials. Exactly δ+1 evaluations
fix a degree-bounded interpolant. Degree zero doubles its sole value in the sum
check. A false initial sum either triggers a consistency failure, remains false
at the final composition check, or hits a nonzero degree-at-most-δ difference
polynomial's root in some round. The sum of these losses is m*δ/p^d under the
interactive uniform-challenge premise. This does not instantiate Fiat–Shamir.
The m=0 direct check, exact SC numerator and remaining claim obligations are explicit.

I tried to break it by substituting one final value derived after an omitted
prior Final absorb, and the research control rejected it with
`FinalEvaluationMismatch`. The constant-P test also exposes a false unresolved
claim that the separate public verifier rejects with `ClaimMismatch`. Neither
research result earns a protocol NC status or certifies a profile.

RFC-author: approve append-only amendments. Ordered descriptors and typed widths
fully determine messages, with explicit field degree and format version. The
inference-proof container and canonical plan derivation remain with their owning
RFCs. No original task criterion, dependency, PCS/ZK obligation or Q12 gate is removed.

Sumcheck-prover-engineer: approve arbitrary sum-of-products P of degree <=4, the
leading-coordinate dense reference, and a prover-only Summand interface. The
verifier's P/degree/shape are independent of that strategy. All final obligations
use its own derived point. The real Rust/Python corpus and naive c_sc/memory ledger
remain implementation requirements, not properties supplied by this prototype.

PCS-engineer (hash/evaluation consumer): approve reuse of A1's existing labels
and return of explicit tensor/point/value obligations. No intermediate commitment,
new challenge or implicit PCS opening is introduced. The public adapter closes
public tables only; private inputs still require real reductions/openings.

Negative-control-author: approve a real-prover honest baseline followed by one
proof-value mutation and the same real verifier. This complements witness-first
controls, keeps every failure fail-closed and adds no configuration exception.
NC-0205 is planned; all NC-02xx/0800/0802 statuses remain incomplete.

Workflow 03 checklist:
- Public items: no core API yet; all proposed behavior is RFC-0006 A1.
- Challenges: descriptor first, each round message before its challenge, final
  values before continuation. The reference two-instance case tests that dependency.
- Claims: ordered tensor ids and final values at the computed point; every one
  must reach a public evaluation or real reduction/PCS consumer.
- Bindings: NC-0200/0201/0205/0800/0802 specified with exact errors; no catalog credit.
- Ledger: existing SC formula; symbolic p^d and exact m*δ record; generator pending.
- Certificates: field-only identities, no new integer-lift certificate.
- Padding/masks: none implicit; future strategies retain canonical plan padding.
- Determinism: ordered terms/ids, checked widths and exact field serialization.
- Parity: independent Python candidate bytes only; Rust/GPU parity not claimed.
- Cost: symbolic dense/verification costs; no measured constant or benchmark claim.
- Verifier: implementation must remain no_std+alloc, with typed errors and checked
  lengths from the verifier's instance; any transcript-advancing error aborts.
- Glossary: final claims are obligations, not complete-statement acceptance.

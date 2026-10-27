# Claim batching review (RFC-0006 A2)

Reviewer: codex-root, also the author; soundness-auditor and sumcheck-prover-engineer
passes, not independent audit. Approve mode 1; full E3-02 corpus/benchmarks remain open.

I tried to break it by changing one unclaimed tensor entry while keeping the initial
claims fixed, and the control NC-0205 rejected it with ClaimMismatch. NC-0202/0206
and NC-0802 also reject in both modes/fields through the real implementations.

Workflow 03 checklist:
- Public items: claim_batch::Batch and pure coefficient operations implement A2 mode 1.
- Challenges: complete descriptor before gamma; each Round before SC; BatchFinal before continuation.
- Claims: only y(r), unconditionally emitted; A(r) is computed directly by the verifier.
- Bindings: registered two-mode 0202/0206 and extended 0205/0802; no verifier bypass API.
- Ledger: one t/p^d RLC and one 2m/p^d SC; all fields checked against six independent byte cases.
- Certificates: field identities only; inherited interactive bound, Q12 and full profiles unresolved.
- Padding/masks: maximal Boolean-prefix blocks accumulate overlaps; no new commitment or ZK claim.
- Determinism: ordered powers and blocks, checked capacities, no external challenge injection.
- Parity: 10^4 coefficient points per field, duplicate/cancelling claims, both-field chained bytes.
- Costs: eq-table construction and Dense product folding; no measured constant or weight-pass change.
- Verifier: no_std; shape checks; direct coefficient evaluation; public adapter closes the sole claim.
- Glossary: existing terms; virtual role is caller-verified, never a proof flag.
Gate mutants overwrite overlapping blocks or bypass the public consumer; both must fail.

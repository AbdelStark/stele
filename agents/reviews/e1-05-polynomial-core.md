# E1-05 polynomial core review

Same-author sumcheck-prover-engineer and soundness-auditor skill pass; not an independent audit.
Scope: arithmetic primitives in stele-poly; benchmark acceptance remains in progress.

- Public items: Mle, SmallMle, Strategy and eq_table implement RFC-0006 §5; trailing-coordinate evaluation implements RFC-0007 §§1,5; eq_evaluate implements RFC-0006 §§5,6. Errors enforce shape/range/allocation boundaries. Payload bytes expose storage for the pending benchmark.
- Challenges: none generated; points are caller-supplied. No transcript order exists in this crate.
- Claims/consumers: no protocol claims emitted. Returned tables are arithmetic results, not verified claims.
- Bindings/controls: no claim-graph edge added. Single int4 values changed to -9 or 8 (and native endpoints) at each lane reject with Int4Range. Malformed shapes and excess coordinates reject explicitly. No NC catalog coverage claimed.
- Ledger: no new randomness or loss. Accounting gate confirms the existing E2-01/E8-05 scaffold; it is not a soundness proof.
- Certificates: none. Signed embeddings and bucket aggregation are field identities, not integer-overflow assertions. Input ranges are checked at construction or enforced by the integer type.
- Padding/masks: no implicit padding, lookup or zerocheck. Non-power-of-two shapes reject. The unused high nibble of a scalar int4 is zero.
- Determinism: indexed vectors and fixed reduction order only; no hash map, parallel accumulation or timing-dependent branch.
- Parity: naive/bucketed/dense match an independent explicit multilinear sum on seeded QM31/OM31 cases, every signed int16 value, Boolean corners and suffix composition. eq_evaluate matches table evaluation at 10,000 OM31 point pairs. No CUDA change or proof digest claim.
- Cost: intended term c_w; timing and bytes/element ledger pending in E1-05 part 2. Exact operation instrumentation establishes N-1 multiplies and N-1 subtractions for eq_table; this does not fit a hardware constant.
- Verifier: existing verifier untouched. eq_evaluate is allocation-free and stele-poly is no_std with alloc. Table sizes use checked shifts and fallible allocation; coordinate counts are checked before row indexing.
- Glossary/forbidden patterns: applicable gates pass; no bypass, floats, new dependency or intermediate commitment.

I tried to break it by replacing one valid int4 value with 8, and the control rejects_invalid_shapes_ranges_and_dimensions rejected it with Int4Range.

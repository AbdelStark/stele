# Native Requant static schema review

E7-01d1 implements RFC-0023 §2.1 metadata only. Parent E7-01d retains
all proof consumers, controls, complete parity and resource-ledger criteria.

Root executed eight local checks on implementation commit
`c3e84a4f06163124ac2a099d38c071f146a35bb1`, with changed-source hashes checked
before and after. Receipt SHA256:
`051511e47904738c4e3d228249ee2fbd69c3da2db10521a477611abaabde7c32`.
All three native tests and eight Python tests passed, as did fmt, strict
targeted Clippy, Rust policy, RFC status, documentation links and glossary checks.
The exact PR head must also pass the full hosted workspace/native gates.

1. Public items: `requant::{Error,Block,Role,Schema}` implement RFC-0023 §2.1
   and expose immutable observations of the actual RFC-0022 schema-1 record.
   The only constructor checks separate scalar parameters before derivation.
2. Challenges: none added or sampled; no absorb order or registry change.
3. Claims: none emitted. Static metadata grants no source or proof authority.
4. Bindings: none added. NC-0308..0314 remain TODO. The
   [native tests](../../crates/stele-reductions/src/requant_tests.rs) reject
   invalid parameters, inexact narrowing, malformed private-reader structure,
   truncation, trailing bytes and checked capacity failures.
5. Soundness ledger: unchanged. RFC-0012 A13 still requires all four RLC terms
   and actual A3/A1/A5/A9 consumers; the native union gate checks accounting.
6. Bounds: `Record::requant` generates the actual static record. Its complete
   bytes are retained; column formulas are not duplicated. The private reader
   consumes only that generated record, never an attacker-supplied authority.
7. Padding: L/R metadata and reserved rows are checked. All nine values precede
   their caps; tighter caps share the full original value width. Zero caps
   retain one byte and high role columns. Future consumers must enforce actual
   input/advice padding and reserved zeros; no such proof credit is claimed.
8. Determinism: fixed role/value order and integer arithmetic determine every
   range; no hash-map iteration or witness-dependent allocation.
9. Parity: 18 complete layouts compare canonical bound bytes and every block,
   cap, role and carry against the independent
   [Python reference](../../tests/negative-controls/requant_schema.py).
   Fixture regeneration checks reference source fingerprints. No GPU code or
   field proof is introduced; complete QM31/OM31 parity remains parent work.
10. Cost: bounded static metadata in T_misc; no measured constant or weight pass
    changes. Fallible reservations cover fixed role counts and K<=20. This is
    not the complete producer/verifier peak-memory ledger.
11. Verifier: no accepting verifier is added. The crate remains no_std;
    generated dimensions are bounded and row arithmetic/reservations checked.
    No supplied-record constructor, mutable view or generic callback is exposed.
12. Vocabulary: schema, plane, role, cap and carry follow the Accepted contract.
    The architecture inventory adds only its explicitly named advice cut.

Root validation statement: I tried to break it by supplying invalid scalar
parameters, malformed private-reader fields and impossible allocation sizes,
and the control `rejects_parameters_reader_and_capacity` rejected it.
This is executed static-schema evidence, not a native proof-control result.

Soundness/PCS-owner and GKR/RFC-owner reviewers independently checked all
frozen source and log hashes and approved this scope, subject to final hosted
validation. Their full twelve-item review SHA256 values are respectively
`5f8a05908e05589dc7c3c6eb5c79ed4b998267c8c225590dab537b06c9364c9c`
and `5af69ba21499cfe3ba258309a2008bbf9cf4182db17e394e7c3c119416206dfb`.

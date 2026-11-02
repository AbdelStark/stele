# Native Requant ordered constraint review

E7-01d2 implements the static arithmetic compiler in RFC-0023 §§2.1-2.2.
Parent E7-01d retains descriptor, proof consumer, native control, complete
parity and resource-ledger requirements.

Root executed eight local checks on implementation commit
`092bf4ea294c568f077d92019e268d2fdbacb559`, checking source hashes before
and after. Receipt SHA256:
`ba7e0d63ec4e93348b98c7e842623643cb7e96010a2934c701ad627e6bafad02`.
Six native tests and ten Python tests passed, along with formatting, strict
targeted Clippy, Rust policy, RFC status, documentation links and glossary.
The exact PR head must also pass the full hosted workspace/native gates.

1. Public items: `Schema::constraints` and immutable `Constraints` implement
   RFC-0023 §2.2 using actual sumcheck `Term<K>` values. Only the sealed
   `ChallengeField` types are admitted; no supplied polynomial constructor exists.
2. Challenges: none added. This compiler has no transcript or sampled weights.
3. Claims: none emitted. Its common sigma/U/advice ordinals describe equations;
   they do not grant source fixation, consumer or accepting-record authority.
4. Bindings: no new proof binding. Direct equation tests cover one-value input,
   sign, shared-result, carry, Boolean, target, padding and reserved-row changes.
   The third t byte leaves low division columns zero while the complete tighter
   cap detects it. NC-0308..0314 remain unimplemented native proof controls.
5. Soundness: no loss or ledger line changes. RFC-0012 A13 still requires all
   four RLC terms and actual A3/A1/A5/A9 consumers. The native union gate checks
   the existing accounting without assigning this compiler proof credit.
6. Bounds: the immutable generated schema supplies every column width and cap.
   Actual operands are checked against both recorded role bounds before term
   allocation; pair counts are checked too. No witness determines a bound.
7. Padding: all semantic terms retain sigma, including literal zeros and
   repeated factors. Input and allocated advice padding use x-sigma*x;
   reserved advice uses unmasked x. Full shared widths and zero-cap bytes remain.
8. Determinism: fixed role, pair, byte and term order; no term simplification,
   hash-map iteration, sampled coefficients or witness-dependent compilation.
9. Parity: all 18 complete independent fixtures compare every equation boundary,
   degree, coefficient byte and ordered factor in QM31 and OM31. Both fields
   evaluate 58 honest rows plus zero padding and 22 mutation observations:
   20 nonzero equations and the two intended low-column misses. The independent
   [reference](../../tests/negative-controls/requant_schema.py) is regenerated
   with source fingerprints. No GPU or full proof parity claim is made.
10. Cost: O(J+E) static metadata in T_misc, with one common ordinal count.
    Checked counts and fallible reservations bound allocation; factor buffers
    reserve three slots before product/sigma insertion. No weight pass or
    measured constant changes. Actual capacities and complete peak-memory
    accounting remain part of the parent delivery.
11. Verifier: no accepting verifier is added. The crate remains no_std with
    checked geometry and typed allocation errors. Immutable getters expose
    no mutable authority, generic callback or supplied-record conversion.
12. Vocabulary: existing schema, cap, role, plane, carry and constraint names
    follow the Accepted RFC. Parent acceptance criteria are unchanged.

Root validation statement: I tried to break it by lowering either operand
bound, changing the role count and requesting impossible allocation sizes,
and the control `rejects_constraint_caps_and_resources` rejected it.
These are executed compiler checks, not native proof-control results.

Soundness/PCS-owner and GKR/RFC-owner reviewers verified the frozen source
and execution logs and approved this scope, subject to final hosted validation.
Their full twelve-item review SHA256 values are respectively
`3fd9e895e4039091f08be9bc3113d672190cc4601293dd4cd21afce6fefa7517`
and `0e2e782b8adb9474465bc7fa04f51c58437cade5b7351d71a7ba78c914280c32`.

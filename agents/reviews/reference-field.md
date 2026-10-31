# Reference field arithmetic review

Same-author soundness-auditor pass, not independent audit. All required local
repository gates passed; this record does not approve full inference.

1. Public contract: RFC-0003 §2/A1 fixes i²=-1, u²=2+i, v²=u and the basis.
   The research multiplier uses the same fixed maps and Karatsuba identity
   as native `stele-field`. No new public protocol item is introduced.
2. Challenges: none added or removed. A1/A3 byte vectors, complete wide-range
   states and continuation challenges match their pre-change fixtures.
3. Claims: all existing public consumers remain in place. Complete range
   proofs consume their actual source bytes, lookup children and A3 finals.
4. Bindings: none added. Wrong source roots and noncanonical final fields
   reject in every complete artifact case. Existing A1/A3 and wide-range
   controls passed; no supplied receipt or disabled check is used.
5. Accounting: no labels, draws, degrees or losses change. Complete receipt
   artifacts and explicit range/lookup account formulas match. The full
   accounting gate passed on the original measured branch.
6. Bounds: the canonical base modulus and tower basis are unchanged.
   Fixed maps and scalar products reduce every coefficient modulo p.
   No runtime magnitude tightens an integer-faithfulness certificate.
7. Padding/masks: all callers and domains are unchanged. The complete
   artifact includes zero, padded and multi-byte source values.
8. Determinism: ordered tuple operations and integer arithmetic only.
   The original recursive oracle independently checks 40409 products;
   it calls neither the candidate nor its fixed maps.
9. Parity: native/SIMD/GPU code is unchanged. Frozen A1/A3 artifacts and
   complete research proofs match; the native digest gate passed.
10. Cost: the [report](../../research/sumcheck/REFERENCE-FIELD.md) links
    both-field before/after complete-operation ledgers. Only Python
    reference c_sc/T_misc work is measured. No fitted native constant,
    constant-time claim or weight pass changes.
11. Verifier: public validation and consumer code are unchanged. Malformed
    fields reject at existing boundaries; the multiplier is an internal
    arithmetic primitive with canonical, same-degree operands.
12. Vocabulary/history: Accepted RFCs, accounting and original task criteria
    are unchanged. Scope and tests preceded implementation. Existing live
    proof processes and logs were preserved.

I tried to break it by changing the expected source root and replacing a
final coefficient with p, and the control for each rejected it at
CommitmentMismatch or SourceCopy:NoncanonicalField. A3's shared corpus
also retained all 174 exact rejection decisions.

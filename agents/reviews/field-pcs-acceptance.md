# Conditional field PCS acceptance review

Decision: accept the corrected conditional specification after the recorded
Review, with its index, ADR, task, glossary and control reservations.
This is coordinated internal agent review, not an independent cryptographic
audit. Native implementation and its delivery gates remain unfinished.

The soundness-auditor reviewed cd53b947 and the corrected wire oracle at
010b0dec. The rfc-author approved the scoped route with the reference corrections
recorded here: RFC-0006 A1 qualification, direct formal-section links, and adoption
of the individual adaptive-reuse paragraph without its batching protocols.

The pcs-engineer approves RFC-0010 A8/A9 as stele-pcs owner. Applying
sumcheck-prover-engineer supplies the second implementing-skill review and
approves shared A1 preflight without algebraic changes. The owner pass explicitly
approves stele-hash's A10 usage/sampling contract and stele-reductions' A5
dependency and complete source-consumption contract. Both owner and soundness
passes approve immutable conditional records, externally owned lifetime caps
and observable non-authorizing failed-attempt usage.

| Security statement | Authority and limit |
|---|---|
| Certificate tensor and query losses | Conditional interactive bound; Circle distance and fixed canonical oracle required |
| Individual functional opening | Conditional near-message bound with fresh uniform queries after the complete row |
| Merkle authentication lift | Classical ideal-hash model with deterministic lifetime caps and separate collision/late-preimage events |
| Concrete FS/QROM composition | Unresolved Q12; local usage does not establish adversarial caps |
| Inference, privacy and profiles | Unadmitted; original task criteria remain |

The review checklist is answered as follows.

- The specification authorizes RFC-0010 A9, RFC-0012 A10 and RFC-0020 A5's
  conditional implementation. A8 supplies
  only the bounded authentication lemma. Broader A3 protocols stay Draft.
- Source context precedes CertificateWeight; complete rows precede column
  challenges; full response blocks precede continuation. Typed labels are exact.
- The adapter uses every actual RFC-0006 A1 returned point/value, including
  unused inputs. Its verifier has no original-table or authentication callback.
- NC-0606..0609 are reserved as todo. Native NC-0600/0601 and NC-0803 also remain
  required; NC-0602 keeps only its existing Merkle authentication credit.
- Ledger obligations retain certificate tensor/miss, each opening miss, A8
  lifetime events and the actual SC record. No native accounting producer exists.
- Parameters are static and checked across all 59 Circle identities. There is
  no new integer inference identity or runtime-derived bound certificate.
- Logical and padded field dimensions coincide; packed/CQIS padding and privacy
  remain separate. No new committed intermediate or cut is authorized.
- MSB order, fixed source/proof bytes and repeated-query response order determine
  the computation. The oracle checks both challenge fields.
- Native/Python and CPU/SIMD/GPU proof parity are not claimed. GPU code is unchanged.
- Costs include source rows, full encoding scratch, authentication, certificate
  storage and proof buffers. No measured constant or weight-pass improvement.
- Native no_std, fallible allocation and malformed-proof testing remain delivery
  gates. Complete structural preflight precedes any adapter absorption.
- Glossary additions define source context and certificate terms; all Accepted
  antecedents remain unchanged and the original PCS criteria stay intact.

Focused checks passed: 59 exact query pairs, 12 toy index distributions and
30 M31 thresholds; 15 Merkle trees/57 paths; 298 proximity toy matrices;
5265 near matrices and 379080 wrong-row checks; six complete wire cases in both
fields. The full native accounting/gate suite was not rerun for these reviews.

I tried to break it by changing an unused A1 final, and the control
rejects_unused_original rejected it. After rebuilding the preceding used-source
opening, the reference terminal consumer rejected ValueMismatch. This evidence
supplies no production control coverage or native opaque-handle guarantee.

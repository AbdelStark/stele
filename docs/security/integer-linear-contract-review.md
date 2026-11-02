# Centered integer linear contract acceptance review

Accept RFC-0024 and RFC-0005 A3, RFC-0007 A4, RFC-0012 A14, RFC-0020 A9 and
RFC-0023 A1 for the conditional signed-int8 matmul/Requant operation. Native
delivery remains E7-01f. This is an internal coordinated agent review, not an
external cryptographic audit or inference/profile certification.

The three substantive reviews cover commit
`21b791cc68fbe0a64bf421de7b023d3563e3ba4b`, tree
`3f18e52b95af8654a56288e7d15f5258366d4e16`, RFC-0024 SHA256
`bd77d7a883cfa15e704ce43476f72828b5053f7efca2f9351596d70dfb954935`.
The adoption revision spells out allocated rows 0..L_old+10 inclusive and
reserved rows L_old+11..R-1, as required by the reviewed J formula. It also
updates lifecycle/index/ADR/task/glossary/accounting and control-authoring
metadata. It changes no research/native engine or proof bytes.

| Reviewer role | Full report SHA256 |
|---|---|
| Soundness/transcript owner, ci_queue_audit | `e61d7c688f13e6c160210820b31216cbf4d1981b461656232b8997ef0b39cef1` |
| RFC/GKR-reductions owner, e2e_gap_audit | `2b622c058d0c056700645dea59fe8c4bd414c6e73bf4ff8a97a192d1d881ce3f` |
| Soundness/PCS owner, worktree_hygiene_audit | `437b67c7852c310328cb60b5b959f2c731817964895f0af775a21583e9d6c713` |

Root's saved reference receipt SHA256 is
`710bb8e2be573e275c4d982be7fe6ee2199491f9e8da766ce9d00a760b12715e`.
The command requests Python3.12 and the locked checker. Its launch HEAD is the
earlier graph claim; all six actual checker/lock/reference source hashes match
the reviewed commit. Root and the reviewers checked those bytes and both logs.
Stdout SHA256 is `794e7a3e73aeb9cc026608faed14bebb40881cde0b82eb413ba0c927f3c901da`;
stderr is empty and the command exited zero. Root's final review-pin qualification
SHA256 is `81114957deb062d498a71e3941715f01a3292695021ba1818b218637a40cee75`.

The [bounded checker](../../research/integer-linear/REPORT.md) supplies 36 affine
cases in QM31/OM31 and four scalar A3/A1 reference rejections after accepted
baselines. It demonstrates the residue, truncated-cap, wrong-point and
product-of-MLE counterexamples. These are not composed A5/A9 proofs, native
catalogue executions, full-wire parity or resource measurements.

## Workflow 03 checklist

| Item | Review |
|---|---|
| 1. RFC/public items | RFC-0024 §§1-6 and the five companions define the scoped operation. No native API, registry or dependency changes. |
| 2. Challenges | Fixed independent range initializer, complete A5 schedules, fixed constraints before weights, full claim groups before independent weights, then actual signed matmul/A9. SZ reuses A3's actual tail. |
| 3. Consumers | A7 consumes sigma/eq/layer coefficients; three A9 groups consume every advice final. The linear U claim at exact q enters signed matmul; affine-restored A9 closes both originals, including zero factors. |
| 4. Controls | NC-0315..0318 remain todo. Their exact range/cap/product/affine causes and the narrowly fixed false-source procedure are in §6. API/static tests earn no proof-control count. |
| 5. Ledger | Direct SC+RLC+SZ is (8m+3(h+b)+4)/\|K\|, retaining all child records. Add full advice/original-range A5, all A9, certificate/lifetime and hash obligations. No profile total is claimed. |
| 6. Static bounds | Whole-source bytes imply signed operands; B=d*128² and 2B<p are verifier-derived. Both accumulator bounds and the complete four-byte cap exclude residue aliases. Existing Requant records are rederived. |
| 7. Padding | Full power-of-two positions; sigma is consumed. Semantic rows keep their canonical padding equations, reserved rows equal zero, and all physical message cells enter the byte lookup. |
| 8. Determinism | Fixed IDs, axes, terms, groups, byte encodings and actual returned points. No retry, rollback, supplied q or receipt authority. |
| 9. Parity | No backend changed. Reference algebra evidence is bounded; complete native/Python wire/record/Usage/continuation parity remains E7-01f. |
| 10. Cost | Charge the expanded cut, ranges, arithmetic and all consumers. Separate registration/capture from the online weight visit. Exact admission scopes include signed copies and retained q; measured capacities/RSS remain due. |
| 11. Verifier | Expected geometry owns all limits and complete early suffix preflight. Private records borrow genuine owners; authenticate columns before decoding; typed failures retain real consumed-prefix Usage. Native no_std implementation remains due. |
| 12. Scope | All parent, configured-plan, scale, wider/packed, private/virtual, Q12/Q29 and W8 criteria remain. All 176 inherited research commands stay in order; one bounded checker is added. |

I tried to break it by changing one high-cap slack final and one signed-product
final, and the control `rejects_changed_cap_and_join_finals` rejected it with
FinalEvaluationMismatch through the existing reference A3/A1 verifiers in both
fields. Root executed that saved run; reviewers inspected its source and evidence.
The four new native reservations remain unexecuted. Final repository/hosted gates,
adoption-diff qualification and exact-base merge evidence belong to the PR delivery.

# Integer Requant contract acceptance review

RFC-0023 fixes a full int32 Requant relation through explicit input bytes and
one named advice cut. This review supports the specification; E7-01d retains
native implementation and complete resource evidence.

The root agent executed the reference at commit
`88e114cbbb9e973c74997119445c6a4da0bc8efc`, tree
`52a7a28fafc521c74af48e3497a99e63d87aaa06`. Draft RFC SHA256:
`e9809ba5b641a0805dcae1f1653c9386c8d8f25e3aa8da71d0ca7b07628d9fb8`.
Frozen helper preparation manifest SHA256:
`facfb96397704e3d585cd05349de43cd0c151ffcfe3e33455a0f5f3941742d03`.
The helper imports the unchanged A5/A3/A1/A9 engines; its actual verifier
receives genuine certificate handles, never plaintext witness authority.

| Root execution receipt | SHA256 |
|---|---|
| QM31 scalar pilot | `2968ae4ed8d5022c8d051569f08303a1bd9a40d618bcf96a5187e31dc4d453e0` |
| QM31 remaining cases | `cf7a87a357ea3d4bc8ad9b658e390c63937f4115f97db37e1a82eeddb84f52ec` |
| OM31 complete selection | `87a8fd7c86434580e4b4528cc477c8dd3b6d1628dcdec037b20e5939e311f18f` |
| Root artifact audit | `5e093f616d73f5ac1d228794b6867749349b9cbe291f16168f524023ca0e7dda` |

All three executions exited zero on the frozen tree. Ten honest cases cover
scalar, wide mantissa, shift 62, rounding ties and n=3/N=4 in each field.
Twenty-six actual rejections cover high result bytes, carry, padding/reserved
bytes, three source functionals, a different genuine advice handle, canonical
wire/shape checks and exactly one changed following-A1 final. Both range
consumers accept before each false arithmetic candidate reaches A3. The
acc=65537, q=1 attack reaches FinalEvaluationMismatch through the tighter
full-width division result cap. Source-functional attacks reach ValueMismatch.
The audit verifies every saved binary and all 21 imported reference sources.
These bounded cases do not enumerate the parameter domain. The input 0/p
authority attack and independent per-frame omission variants remain native
obligations; producer overflow checks receive no verifier-control credit.

The substantive soundness/PCS review has SHA256
`ed1581598613b27b882548d2734f532411b0990fba6324424d7ff17cd5fbf524`;
the RFC/GKR owner sign-off has SHA256
`23ff6eb37c96950fc653b64f4f014a042ac018f9bc56dd0a0c19e46fb0818f2a`.

## Workflow 03 checklist

| Item | Review |
|---|---|
| 1. RFC/public items | RFC-0023 sections 1 through 6 and RFC-0005 A2/0007 A3/0012 A13/0020 A8 specify the operation. No native public item is added. |
| 2. Challenge order | Fix statement/advice, both complete A5 schedules and all constraints before their weights; fix each actual final roster before its independent group weights and A9 row/columns. |
| 3. Claim consumers | A7 consumes sigma/eq; actual A9 consumes every A3 input/advice and output s/q final at the returned point. Retain input/advice and all 2r mu handles. |
| 4. Controls | NC-0308..0314 reserve every new binding. Actual reference rejections above support design review; every new native row remains todo. RFC-0023 §6 retains 0100/0101/0109/0606/0610/0802 variants. |
| 5. Ledger | Four independent-vector terms contribute 4/\|K\|; A3 adds 4m/\|K\| and output A1 3m/\|K\|, plus both complete A5 inventories and all certificate/opening/hash losses. Use an unconditional union. Executable accounting stays unchanged until implementation. |
| 6. Static bounds | Recompute RFC-0022 schema 1 from expected parameters. Whole-value and tighter shared-result caps cover their full allocated widths; cap/Boolean/carry/target relations establish integer faithfulness. |
| 7. Padding | Sigma masks semantic equations; input/allocated advice padding is constrained zero; reserved planes are globally zero. Whole-source byte lookups intentionally include those zeros. |
| 8. Determinism | Fixed schemas, retained zero terms, canonical bytes, ordered IDs and actual transcript sampling. No retries or transcript-state replacement. |
| 9. Parity | Reference proof/consumer agreement in both fields supports this contract only. Native full bytes/claims/records/Usage/continuation parity remains E7-01d; CUDA is untouched. |
| 10. Cost | Charge the new cut, 4N+R_q*N range cells, complete arithmetic/functionals and coefficient/buffer work. No measured constant or performance claim; complete native ledger remains due. |
| 11. Verifier | Contract requires no_std+alloc, checked shape/resource limits, fallible allocation and retained failure work. No native verifier is delivered or excused from these requirements. |
| 12. Glossary/scope | Explicit advice cut replaces residual-only glossary wording. Configured plan/source, matmul integer join, privacy, profiles and W8 keep all original criteria. |

The root agent's adversarial execution statement: I tried to break it by placing
65537 in the shared division result while retaining valid low columns, and the
control using the actual aggregate A3 rejected it with FinalEvaluationMismatch.
Independent soundness and RFC/GKR owner reviews qualify the frozen source,
root-executed evidence and separate acceptance metadata; reviewers did not rerun
the proofs. Native catalogs and full inference remain incomplete.

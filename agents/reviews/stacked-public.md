# Public stacked runtime review

This delivery implements the public-source part of Accepted RFC-0006 A4 and
RFC-0012 A6. E3-06 stays `in_progress`: the certified adapter, certified NC-0211,
NC-0213 and complete resource ledgers remain required.

Separate GKR, soundness-auditor and CI agent passes reviewed the implementation.
This is coordinated internal review, not an independent cryptographic audit.
The author owns all tracked changes. The reviewers found no remaining structural
blocker for this public slice; merge still requires final native and hosted gates.
The PR records their completed results and the tested revision.

The reviewed production SHA256 fingerprints are:

- `stacked/mod.rs`: `f002a26503d23e3ade88f92e5e860626e9e3695bf008f37cdb198c6c10d42754`
- `stacked/statement.rs`: `f2b3e925983835700212b6c9ba53ddb8444c8a36c549b71bad6cade1f7a41d9d`
- `stacked/strategy.rs`: `704e18499ee2305572d2d3cf36490e965e23ecc7b7912abf5afb178636e950ba`

| Workflow 03 item | Finding |
|---|---|
| RFC coverage | A4 owns the expected statement, canonical frames, dense strategy and closed public consumer. A7 remains the independent coefficient evaluator. No Accepted RFC is edited. |
| Challenges | Complete expected StackSources then Stack precede actual A1. A1 owns every Round/Sumcheck/Final step. The two new labels absorb only; there is no new draw. |
| Claims | Restore the actual point to original coordinates. Independently consume A, then every original including unused inputs. Only the private Record constructor exports the closed result. |
| Controls | NC-0203 and both NC-0212 variants reach CoefficientMismatch after raw A1 succeeds. Public NC-0211 reaches ClaimMismatch. Each NC-0802 frame omission reaches the real successor's FinalEvaluationMismatch. |
| Accounting | Retain actual `m*delta/|K|`, including empty-P and zero-round records. Delta includes zero-coefficient terms. Every failure exposes actual cumulative transcript usage and no closed record. |
| Static bounds | No integer identity is asserted. Expected dimensions and conservative degree are static. CQIS provenance and profile composition remain outside this conditional field interface. |
| Padding and masks | Public originals reject nonzero padding before replay. Validity and selectors multiply the Boolean coefficient before extension. Fixed block partials retain every padded slot. |
| Determinism | Canonical ordered bytes, actual transcript challenges, fixed term/block order and explicit inverse permutations. No callback supplies a claimed authentication or replacement point. |
| Parity | Both-field original-table round oracles cover active cubic P, both orders and all six kinds. The independent wire corpus compares 116 decisions and complete frames, native-produced proofs, restored claims, SC and continuation. A7 retains 10,000 points per kind/field. No GPU change. |
| Cost | Charge dense preparation, partials, folds and every consumer to c_sc/T_misc. Dense retained capacity is a partial observation; complete source/frame/consumer/RSS evidence remains due. No constant or weight-pass claim changes. |
| Verifier safety | Checked layout/identity/size/caller limits and actual A1 preflight precede absorbs. Addressability checks and fallible allocation reject. Later failures retain usage. GKR remains no_std and forbids unsafe code; Record construction has a compile-fail boundary. |
| Vocabulary | Uses the Accepted contract's coefficient, original, claim, partial and SC terms. No inference, privacy or certified-source authority is implied by this public result. |

Review corrected a stale control-suite gate inventory and added malformed inner
round widths with correct outer counts. The existing independent round oracle
now exercises the maximum allowed active cubic P. All changes are in the same
public delivery; the certified consumer is a separate sequential delivery.

The author executed the actual four standalone control tests in both fields;
the reviewers traced their production consumers without rerunning those tests.
I tried to break it by changing the coefficient's layer point, onehot index and
exact-table value, using a draw-order unused original final, and omitting each
new frame before a successor. The controls rejected these with
CoefficientMismatch, ClaimMismatch and FinalEvaluationMismatch as specified.
The mandatory native gate reruns these controls on the frozen delivery source.

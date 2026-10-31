# Conditional functional-opening review

Scope: E4-03a opening producer/verifier, RFC-0010 A9 §§4,8,9 and RFC-0012 A10.
The soundness-auditor pass found no remaining blocker in this scope after fixing
the control-helper gate inventory. It does not complete E4-03a.

| Workflow 03 check | Finding |
|---|---|
| Public API | Functional and producer/verifier follow §4; errors follow §8; the borrowed OpeningRecord follows §9. |
| Challenges | Full expected context, certificate ID and coefficients bind before the row; the row binds before column draws; all responses bind before continuation. |
| Claim consumers | Scalar and every sampled-column equation pass before returning a record. A1 original-source closure remains separate. |
| Controls | NC-0600/0601/0606/0607/0610 and NC-0802/0803 execute actual opening or following A1 consumers. |
| Accounting | Each opening retains its query term and original certificate reference. Cumulative transcript snapshots are distinct from local Merkle work. |
| Static bounds | Existing Circle dimensions and finite query policies remain authoritative; no witness-derived parameter is added. |
| Padding/masks | Exact power-of-two dimensions; zero coefficients skip no authentication, decoding or equation. |
| Determinism | Canonical byte/response order, fixed labels and transcript-derived queries; duplicates retained. |
| Parity | Six independent fixtures and continuation challenges pass in both fields. No GPU code changes or CUDA parity claim. |
| Cost model | Existing c_c/T_misc work; no measured constant or benchmark improvement. Resource ledgers remain required. |
| Verifier | no_std, unsafe forbidden, checked shapes and fallible allocation. Failures return usage without a record; record lifetime follows its certificate. |
| Glossary | No terminology conflict found. |

The reviewer ran seven focused NC binaries, both opening integration tests,
three hash PCS tests and five compile-fail doctests; all passed. The separate
full native suite and hosted merge-tree validation remain merge requirements.

I tried to break it by omitting OpeningColumns in an attack replay and replacing
one following A1 final, and the control NC-0802 rejected it with
FinalEvaluationMismatch in both fields.

The A1 adapter, NC-0609, combined SC obligations and complete resource ledgers
remain required before E4-03a completion.

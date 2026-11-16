# E8-02f3a: RFC-author and standards review

Reviewer: `registry_standards_review`; RFC-author, affected lanes B and P.
Base: `b5ab311f`; reviewed `ae956599` plus the test-name correction, locked vector
check, native-gate wiring, receipt regression and catalog prose correction.
Lane V approval and integration gates belong to the integration owner.

Verdict: approved for specification acceptance. No remaining hard violations or
baseline smell findings. The initial allocation-bound finding is resolved by the
trusted relation length checked before decoding. The new test now follows
AGENTS.md §6 naming. Accepted text remains intact; ADR-133 explains the refinement.

I reproduced `vectors.json` byte for byte and ran `vectors.py --check`. The focused
`test_rejects_missing_accounting_receipt_and_unadmitted_verifier_surface` passed
under Python 3.12, covering missing declaration/generator receipts and failure.

I tried to break it by retaining original mantissa widths during normalization,
and the control `research/plan-registry/vectors.py` template-equality assertion
rejected it. The mutant existed only in an external temporary copy. This is a
spec-vector experiment, not executed NC-1325..1334 coverage.

Workflow 03 checklist:

- Public items: no runtime API; A16 specifies the wrapper/publisher contract.
- Challenges: none added; A15 transcript order stays unchanged.
- Claims: original public evaluations and opening consumers remain unchanged.
- Bindings: NC-1325..1334 are exact reservations; composed controls remain required.
- Ledger: three digest invocations and compression work enter H; no algebraic loss changes.
- Bounds: trusted length bounds decoding; trusted T/V bound request computation.
- Padding/masks: padded vocabulary and unchecked argmax rows are zero.
- Determinism: canonical names, order, widths and normalization are explicit.
- Parity: no GPU changes; vector bytes reproduced against supplied production dumps.
- Cost: explicit formulas; no measured constant or performance claim.
- Verifier: no_std contract retained; checked counts, typed errors and fallible allocation specified.
- Glossary: terminology conforms; no forbidden synonym introduced.
- Tier: development only; registry trust and no security level are explicit.
- Commit rule: no columns or sources added.
- Plain checker: runtime unchanged; declaration exports require existing validation.
- Segments: no new reads or carried columns.
- Proof bytes: unchanged runtime; existing proof pins are retained.
- Ladder: L0/L1 fixture vectors checked; full ladder/native execution remains the owner's gate.

Full gates and fresh runtime controls were not rerun here. Correct registry
publication and distribution remain explicit trust premises.

# Sumcheck protocol contract (Q15)

Question: which instance encoding, polynomial description, final-claim boundary
and transcript schedule make RFC-0006 §§1–2 interoperable and testable?
Security property: an accepted reduction leaves exactly the ordered input
multilinear evaluations at its derived point, with SC loss m*degree/|K|.
Kill criterion: a false public sum accepted, an unresolved emitted claim called
verified, an unbound polynomial/instance, or an omitted final absorb undetected
by a real subsequent instance. No performance measurement is part of this study.

## Reproduce

```sh
uv run --locked --script research/sumcheck/check_sumcheck.py
```

The pinned script implements the canonical QM31/OM31 tower with integer recursive
multiplication. Proving uses repeated leading-coordinate folds; the public verifier
independently evaluates full multilinears using hypercube weights. Interpolation
uses exact Lagrange products, including degree zero and challenges at interpolation
nodes. The transcript uses the existing independent Python byte-framing oracle;
its official BLAKE3 backend is not an independent hash implementation. Research
imports no Stele protocol code and is not imported by core.

## Evidence

- 48 honest cases: both fields, degrees 0..4 and dimensions 0..3, plus empty-input
  zero/constant polynomials. Forty one-value changes to claimed sums reject.
- Wrong round evaluation, early challenge and cross-instance reused challenge
  reject at the stated round/final checks. In each challenge case the replacement
  changes only one final evaluation of a nonconstant one-round relation.
- A second production-shaped instance after a history omitting the first Final
  absorb rejects. Its round message stays identical; only its sole final value
  changes. A digest-sensitivity check alone would not establish this consequence.
- A constant-P case deliberately retains an unused input evaluation. Reduction
  verification returns the false value as an unresolved obligation; the public
  verifier rejects it with ClaimMismatch. This exhibits why the generic result
  must never be labelled complete statement acceptance.
- Invalid degree, repeated ids, out-of-range factor index, malformed proof shape
  and noncanonical field limbs reject. Exact SC records use m*degree and p^d.
- Committed two-instance vectors cover both fields, full extension-valued input
  data/coefficients, every message payload, final values, derived points and SC
  records. They are candidate bytes for Rust/Python parity, not inference proofs.

## Recommendation and limits

Accept RFC-0006 A1 and RFC-0020 A1 after skill review, then implement E3-01 with
real controls and accounting gates. The planned post-proof hook keeps an honest
production-prover/verifier baseline and changes one proof value; it adds no
configuration exception or verifier bypass. Catalog controls remain incomplete
until the real Rust/Python protocol corpus passes. No new commitment is introduced.

The [sumcheck theorem](https://people.cs.georgetown.edu/jthaler/ProofsArgsAndZK.pdf)
supports the conditional interactive reduction bound; `formal/sumcheck.md` states
that obligation explicitly. These finite checks do not prove Fiat–Shamir, privacy,
PCS composition or a profile budget. Q12 and the remaining MVP tasks stay open.

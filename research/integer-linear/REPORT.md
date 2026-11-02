# Centered integer linear join

Question Q26/Q28: can a fixed offset-int8 source pair join the actual matmul
consumer to Requant without another accumulator root or online weight visit?
Kill criteria: a residue alias survives both integer bounds, the advice can be
chosen after the joining point, the point is restored incorrectly, or the
affine opening requires a second original-message scan.

Run `uv run --python 3.12 --locked --script research/integer-linear/check_contract.py`.
The bounded checker reuses the existing reference field and A3/A1 engines.
It directly evaluates Boolean-basis polynomials independently
of folding, on 36 directed/seeded cases across QM31 and OM31. The shapes include
every zero/one-bit axis combination and two asymmetric stacked cases. It checks
the integer product's MLE, its four offset-byte MLEs, the signed partial-row
identity, and the restored raw functional at a non-Boolean physical point.

For all power-of-two inner exponents 0..15 the static bound B=2^b*128^2 has
2B<p. Exponent16 fails. Four byte-column cap equations accept 0,1,B-1,B and
reject B+1. Direct counterexamples show that 0 and p share a field residue,
that keeping only two cap columns accepts B+65536 when B=16384, and that
swapping two physical coordinates changes an evaluation. For signed values
[-1,2] at point2, the true MLE is5 while multiplying the separate sign and
magnitude MLEs gives9. These are algebra counterexamples, not native controls.

Four scalar reference rejections supplement those identities: in each field,
the existing A3 verifier rejects one changed new high-cap slack final and the
existing A1 verifier rejects one changed signed product final, each after an
accepted baseline, with FinalEvaluationMismatch. These small public-source
checks do not implement the composed A5/A9 protocol or certify its wire format.

Recommend RFC-0024 and its companion amendments. Byte-range registration must
run actual A5 with all-one selectors; an arbitrary lookup record does not prove
this predicate. Fix originals and the complete advice before A3, derive the
linear U claim at A3's actual tail, and retain a separate m/|K| equality loss.
The presampled-tail argument and unconditional failure union are in RFC-0024 §5;
finite checks do not establish a soundness theorem.

This study creates no composed proof, certificate, native control, benchmark or
profile admission. It does not test native orchestration, wire codec, failure Usage,
registration lifetimes or complete memory behavior. E7-01f must provide those
actual consumers and independent full-wire evidence. Full configured model,
private/virtual sources, wider dots, Q12/Q29 and W8 requirements remain.

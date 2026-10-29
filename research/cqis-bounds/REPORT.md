# Quantiser and bound-certificate contract

Q26 asks which canonical quantiser, certificate schema and integer obligations
complete E5-03. The security property is static integer faithfulness under M31,
with reproducible quantisation. Kill criterion: a stated allowed shape violates
the stated strict field bound, or a claimed scale passes the stated inequality
without satisfying the ceiling definition. Both occur in the accepted prose.

## Exact evidence

Run `python3 research/cqis-bounds/check_bounds.py` (standard library only).
For p=2^31-1, integer bound B satisfies B<p/2 iff 2B<p. The advertised
int8 product bound 2^14*d admits at most d=65535, not 65536. The analogous
full signed int4/int8 bound 2^10*d admits at most d=1048575, not 1048576.
At either advertised endpoint the bound is 2^30. That integer embeds and
recovers as -(2^30-1), a different integer with the same M31 residue.
The full native signed ranges permit this product sum using repeated negative
endpoints. If symmetric quantisation excludes those endpoints, the spec must
define and enforce the narrower ranges; it cannot silently change its bound.
This is not a bug in M31 recovery, which correctly returns the centered value.

RFC-0004 §5.5's upper-only condition `127*s-M<127` is not equivalent to
`s=ceil(M/127)`: M=128,s=1 passes, but the ceiling is 2. The exact relation is
`0<=127*s-M<127`. The script checks the equivalence for all M=0..32768 and
three neighboring scale candidates (98,307 decisions), plus 10,000 seeded
static-bound cases against exact rational comparison. These are independent
research checks, not NC-0102/0109 against a production verifier.

At M=0 the stated ceiling is zero. The conversion rule must define the all-zero
row without dividing by zero, or explicitly amend the scale definition. The
current spec does not select one. Scale alignment and static fallback also need
canonical policy; scalar Requant does not choose tensor scales.

## Missing contract and recommendation

RFC-0004 specifies scale formats, but not how source checkpoint values select
the shared exponent and channel mantissas, how int4 versus int8 is chosen, the
exact weight-rounding/conversion rule, or the static fallback/calibration policy.
RFC-0011 requires a reproducible `quantiser_id` and `cqis-weights-v1` bytes without
giving their encoding. These choices affect model outputs and cannot be inferred
from scalar round-half-away arithmetic alone. Exact checkpoint conversion also
needs supported source dtypes, nonfinite rejection and a bit-level rule; host
floating-point behavior must not become an implicit protocol definition.

RFC-0004 §6 supplies a certificate tuple sketch, not per-reduction schemas or
canonical bytes. A trusted static format/shape must determine every magnitude
and dimension. Checking only a prover-supplied product is insufficient; include
the claimed result's range, biased requant intermediates, signed sums and any
limb/chunk relations in the integer argument. Native int32 fit is not M31
faithfulness. A narrower bound measured on the actual input is not static proof.

Recommend RFC-0003 A2 and RFC-0004 A3. The strict arithmetic correction is exact,
but the complete quantiser/certificate contract remains Draft and E5-03 blocked.
Preserve certificate property tests and the actual NC-0109 requirement. No core
API, proof, challenge, benchmark, cost constant or production control changes.

The [Q26 limb study](LIMBS.md) extends this evidence with static per-column
carry and result-side bounds, whole-input range counterexamples and independent
exact/NumPy checks. Closed certificate schemas and actual consumers remain open.

The [closed scalar Requant study](REQUANT.md) derives six fixed column
certificates and the output sign relation for RFC-0004 A1, with native/exact/
NumPy decision parity. Full schema coverage and proof consumers remain open.

The [closed RMSNorm study](NORM.md) accounts for all wide arithmetic in
RFC-0021 §2.3 using bounds that cover every allowed exponent and output branch.
It retains source/range/table/branch bindings as actual consumer obligations.

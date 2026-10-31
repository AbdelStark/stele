# Doubled attention normalization denominator (Q26 / Q31)

Draft RFC-0004 A3/A6 and RFC-0009 A2 research. Before code: can the actual
sixteen-byte denominator D produce the full sixteen-byte 2D needed by signed
normalization's strict remainder relation? Costs are c_a/c_sc/c_lu/T_misc.
Kill the design if a false result, wrong factor, truncated high byte, source
substitute, modulus alias or omitted original consumer is accepted.

Use the full attention_normalization_bounds.Spec. The expected Dmax can be
2^64 and the doubled maximum 2^65; sixteen byte planes preserve both. Reuse
one complete radix-eight limb product with count 1, left_max=Dmax and
right_max=2. Every right byte must equal the expected coefficient two. Its
left bytes, zero-extended to sixteen, must join the actual external D root;
the complete output joins the sixteen-byte external doubled root. Retain
all input whole ranges, packing, output/carry ranges, both actual operand
claims and both public power claims. No whole-field D or 2D equality.

This arithmetic consumer allows D=0 as a standalone bounded source, including
its zero-hidden factor control. Admissible normalization must compose the
actual positive-denominator proof on the same source root. This consumer
cannot replace positivity, global attainment or source ownership. The
wrapper draws no challenge. Expected schema, roles, field/repetition bytes,
both external roots, both internal roots and the verified product state bind
the returned composition state. Equivalent arithmetic metadata can reuse a
valid product, but the returned state changes and must be bound by the caller.

Identity<2^44 reserves base=2^63+2^18*identity. The product uses identity
64*identity+1 and source/output roots base+1/base+2. External roles are
distinct and outside the whole reserved span. Verify that all inherited
namespaces remain disjoint and that input/output slots fit sixteen bytes.
Expected static limb certificates bound every column below p/2; no observed
input determines a bound or an admissible shape.

Let b be the product input-plane exponent, g its output-slot exponent and k
its result-column count. Three independent lookup dimensions are b+2,g+3,g+3.
Each identity remains ((2^m+255)/|K|)^repetitions with unsquared reduction
repetitions*(F(m)+F(8)+3m)/|K|, F(m)=3m(m-1)/2+2m. Range/A3 numerator is
9b+18g+31; product identity loss k-1 and A1 reduction 4b remain separate.
Nonlookup draws are 4b+8g+13 ZeroWeight and 6b+8g+14 Sumcheck. No wrapper
loss or label is added. Confirm every runtime receipt and original claim;
binding/FS/H and the complete positive source proof remain additional.

Tests first: 10000 independent NumPy integer doubles, sixteen-byte roots and
column convolutions over both modes, legal shifts, unit directions and compact
widths. Both fields/repetition counts include zero and maximum inputs. Attack
each root, the exact factor including hidden zero, actual operand originals,
public powers, malformed shapes, caps, carry endpoints and high external
planes. A genuine output-ranged 2D-p alias must fail the product relation.
Compose the complete positive denominator and reject separately valid changed
sources; a standalone zero product must not replace that source. Require full
metadata scalar proofs at exact 2D=2^65 and block 2D=2^49, and all repository
gates. These scalar proofs do not establish upstream channel/key ownership.

Continue Q26/Q31. Biased numerator, quotient product, strict remainder, signed
output and final conversion must compose on their actual roots. Native/private
inference, complete ownership, global attainment, fidelity, independent audit
and all original task criteria remain required. No benchmark, new cut or
additional weight pass is claimed; Draft amendments remain unaccepted.

Seed 2744 passed all 10000 independent cases and 28651 column cells,
including 3358 zero sources. Both modes, legal shifts, unit directions and
all compact-width families passed. Frozen corpus SHA-256:
`e07ddd1c2b56c031b3583849c0804d2114c6bbe7c9c7c4ef5f984f7429c87975`.
Primary controls passed, including both actual operand originals, both public
powers and the coefficient two hidden by zero. Boundary, composition, matrix
and full-metadata proofs remain under validation; repository gates are queued.

All boundary controls and actual positive-denominator composition passed.
The output-ranged 2D-p value rejected at the product equation. Valid changed
and standalone zero sources could not replace the pinned positive source.
All 16 matrix proofs passed across both fields/repetition counts with exact
receipts and all original consumers. Frozen SHA-256:
`4e1b11841e44afb486319288865815ad8ddf56359ed810ea4ec5e3bf15f4b0d5`.
Full-metadata boundaries and repository gates remain under validation.

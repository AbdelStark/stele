# Global attention offset base (Q26 / Q31)

Draft RFC-0004 A3/A6 and RFC-0009 A2 research. Before code: can the exact
normalization base H=S*Z consume the same eight-byte global Z root as the
positive denominator? The local base accepts four-byte sums only. Costs are
c_a/c_sc/c_lu/T_misc. Kill this design if a wrong factor, source substitution,
modulus alias, truncated high plane or omitted original consumer is accepted.

Use the full expected attention_normalization_bounds.Spec and require exact
accumulation. Block accumulation has no global offset base in normalization.
The static bounds are Zmax=L*2^E<=2^34 and Hmax=Zmax*S<2^50, with configured
restored value bound S<=65535. Both external roots have eight bytes. One
complete radix-eight limb product has count=1, left_max=Zmax and right_max=S.
Its whole input ranges already enforce both caps. Extract the actual paired
left bytes and zero-extend to eight; require every paired right byte to equal
the configured S byte, including all high zeros. Zero-extend the complete
product output to eight bytes. Retain whole ranges, packing, output/carry
ranges, both actual operand claims and both public power claims.

The wrapper draws no challenge and checks no whole-field Z or H equality.
The returned state binds the full expected schema, roles, field/repetition
bytes, both external/internal roots and the verified product state. Equivalent
arithmetic metadata may reuse a product but must produce a distinct context
state. Standalone Z=0 remains legal; normalization must compose the actual
positive denominator on the same root. Full upstream ownership is separate.

Identity<2^44 reserves base=2^63+2^18*identity. The product uses identity
64*identity+1 and roots base+1/base+2. External roles must be distinct and
outside the whole reserved span. Check every inherited namespace and eight-
byte capacity at the maximum identity. Static column certificates must remain
below p/2; observed source values never choose the bound or layout.

Let b be the product input-plane exponent, g its output-slot exponent and k
its result-column count. Independent lookup dimensions are b+2,g+3,g+3.
Each identity remains ((2^m+255)/|K|)^repetitions and each unsquared reduction
is repetitions*(F(m)+F(8)+3m)/|K|, F(m)=3m(m-1)/2+2m. Range/A3 numerator
is 9b+18g+31. Product identity loss k-1 and A1 reduction 4b remain separate.
Nonlookup draws are 4b+8g+13 ZeroWeight and 6b+8g+14 Sumcheck. No wrapper
loss or label is added. Binding/FS/H and upstream consumers remain additional.

Tests first: 10000 independent NumPy integer products, byte roots and column
convolutions across lengths through 1048576, all exponents, value policies,
scales and normalization unit directions. Both fields/repetitions include
zero and maximum inputs. Attack every external root, the exact factor when
Z=0, high factor bytes, whole Z overflow, both actual operands and public
powers, padding and carry endpoints. Genuine output-ranged H-p and H+p
must fail at the product relation. Reject block mode and malformed metadata.
Compose complete global probability aggregation, the positive denominator
and canonical raw sign through the same Z/H roots; separately valid changed
sources must reject. Require a full-metadata scalar proof at Z=2^34 and
H=65535*2^34. This is not evidence of full-row performance or ownership.

Continue Q26/Q31 with complete normalization composition after this relation
passes. Exact weighted offset aggregation, all key/block/model ownership,
configured output conversion, native/private PCS/ZK/FS, GPU parity, fidelity
and independent audit remain required. No benchmark, additional weight pass,
Accepted cut or production coverage is claimed. Original task criteria stay
blocked; Draft amendments remain unaccepted.

Seed 2749 passed all 10000 independent cases and 41070 column cells,
including 3360 zero sources. Both value policies, all probability exponents,
unit directions and compact-width families passed. Frozen corpus SHA-256:
`06aa9af52d3ca315e16b7c18e152073d8d5457eb87a6c217ff2932a55b604d4f`.
Primary and boundary controls passed. Both genuinely output-ranged H-p/H+p
values rejected at the product equation; exact zero-hidden factor checks,
both actual operand claims and both public powers retained their consumers.
Composition, matrix, full-metadata proofs and repository gates remain pending.

Complete global probability, positive denominator and canonical raw-sign
proofs composed on the same Z/H roots. Separately valid changed Z/H proofs
and a standalone zero product could not replace those sources. All 16 matrix
proofs passed with exact receipts, draws and actual/public claims. Their
frozen SHA-256 is
`5f413bbd5013ba70720c522af90f7e5201bfa268839af65a96ce577c48cb58bb`.

Both full-metadata scalar proofs passed at length 1048576 and width 16384,
with Z=2^34 and S=65535 or S=127*259. All eight external bytes and complete
consumers remained present. Their combined frozen SHA-256 is
`6367a962df4890477a8e18d1d71be8585ccc5a2ffe9ddf7f1ddd4fe0efe52437`.
The original proof runner completed successfully. Repository gates remain
queued; independent review and full upstream ownership are still required.

CI now requires the corpus, controls, boundaries, source composition and
sixteen-proof matrix, plus a separate maximum-parameter job for both scalar
cases. All eleven inventory/CLI/aggregate tests passed. Integration preserves
all inherited jobs and 33 native steps: 161 commands, 63 research groups,
57 full-capacity jobs and 127 hosted jobs. Hosted CI and the original local
gate process remain pending; the completed proof runs were not restarted.

# Consumed attention probability sum (Q26 / Q31)

Can an actual bounded and masked exponential byte source produce an exact
four-byte Z=sum(P_hat), with its emitted source claim fully consumed? This is
Draft RFC-0004 A3/A6 research for RFC-0009 §2 step3 and A1. Costs are
c_x/c_sc/c_lu/T_misc. Kill the design if a changed sum, field alias, source
permutation, masked/padded value or unconsumed final claim is accepted.

Expected metadata fixes the complete attention-maximum row description and
E in[0,14]. Both external source and output identities are independently fixed.
The source range caps allowed positions at Q=2^E and masked/padded positions
at zero. The scalar sum range caps Z at K*Q, where K is the expected number of
allowed keys. The full supported parent domain is16384 keys; absolute positions
retain the sequence span2^20. Whole-sequence key completeness, larger row
assembly and physical/model source ownership remain separate obligations.

Zero sums are valid for this standalone arithmetic operation, including empty
contributions from accumulation blocks. No per-block Z>=Q assertion is added.
In actual whole-row maximum/exp/sum composition, the verified attained key
has argument zero and P_hat=Q; nonnegative entries therefore give Z>=Q.
All three exponential representations must compose on their exact source root
and expected E/mask metadata. The sum itself does not depend on mode or split.

Two complete wide ranges verify before integer field views. With at most16384
entries and Q<=16384, both sides are at most2^28<p/2. One degree-one A1 at
dimension a proves the sum of the actual verified whole-byte view equals the
verified scalar Z. Its original claim is independently evaluated at the exact
receipt point. No supplied view, digest, child receipt or reduced prefix is
authority. The external output root always hashes four canonical byte leaves;
the compact ranged scalar is zero-extended before this exact source join.
High output bytes cannot be omitted even at Z=0. There is no new Accepted cut.

Namespace before code: identity<2^48, base=2^63+2^14*identity, disjoint from
the expected maximum namespace. Both external roles are distinct from each
other and all four maximum roles, outside both namespaces. Wide children
256*identity+1/+2 occupy offsets64..192. The compact output source uses
base+1, the A1 original view base+16 and A1 id1024*identity+128. No public
mask MLE is introduced: the expected mask remains in the complete range caps.

For N=2^a, source byte width2^bp and compact scalar width2^bz, the two lookup
units have dimensions a+bp+1 and bz+1. Each independently contributes
((2^m+255)/|K_field|)^rpt and unsquared
rpt*(F(m)+F(8)+3m)/|K_field|, F(m)=3m(m-1)/2+2m. Range/A3 numerator is
9a+7bp+7bz; the separate sum A1 numerator is a. Full nonlookup draw counts
are4a+3bp+3bz ZeroWeight and5a+3bp+3bz Sumcheck. Parent draws a Sumcheck
challenges, after expected row/E metadata, both external roots, the compact
output root and both verified child states. Original A1 Instance/Round/Final
messages remain. Actual maximum/exp composition retains every child's full
independent account without additional join challenges.

Tests first:10000 independent NumPy sums, explicit byte encoding and namespace
cases across E=0..14, mask/window/block/padding and all source/output widths.
Require actual proof matrices in both fields/repetition counts, all-zero and
inclusive maxima, one-value root/sum/source controls, coherent M31 aliases,
permuted equal-sum views and strict full output geometry. Compose actual
maximum and canonical exp proofs for all three representations, including a
valid different exponential source with the same Z. Require a complete16384-row
proof and every local gate before publication. Native/private inference,
restored value products, output normalization, full attention, fidelity and
original task/control criteria remain open. Continue Q26/Q31; no benchmark,
weight-pass change, production control or profile credit is claimed.
